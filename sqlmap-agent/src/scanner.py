"""
Main scanning orchestration logic
"""

import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlencode

from .config import setup_cli_parser
from .openapi import (
    load_openapi, collect_parameters, substitute_path_params,
    build_param_value, construct_json_string_from_schema
)
from .sqlmap import (
    ensure_sqlmap, construct_sqlmap_command, enumerate_if_vulnerable, run_sqlmap
)
from .utils import ensure_dir, safe_summary_to_filename
from .output_aggregator import OutputAggregator


def scan_single_endpoint(endpoint_data, server_url, sqlmap_path, logs_dir, extra_flags, args, spec, base_dir, output_aggregator):
    """Scan a single endpoint synchronously (for concurrent execution)"""
    from .output_aggregator import create_endpoint_result, extract_injection_details, create_evidence_list, evaluate_vulnerability

    raw_path, method, operation, summary, safe_name = endpoint_data

    try:
        # Get the full path_item from spec
        path_item = spec['paths'][raw_path]

        base_cmd = construct_sqlmap_command(
            server_url, raw_path, method, path_item, operation,
        spec, base_dir,
        sqlmap_path, os.path.join(logs_dir, safe_name + '_sqlmap'),
        extra_flags
        )

        # Run discovery -> then optional enumerate
        scan_url = server_url.rstrip('/') + substitute_path_params(
            raw_path,
            collect_parameters(path_item, operation, spec, base_dir),
            spec,
            base_dir
        )

        vulnerable, raw_out, enumeration_results = enumerate_if_vulnerable(
            base_cmd,
            scan_url,
            logs_dir,
            safe_name,
            sqlmap_path,
            args.confirm,
            args.max_tables,
            args.max_rows,
            os.path.join(logs_dir, 'master_log.txt'),
            args.log_full_output
        )

        # Create aggregated result
        injection_details = extract_injection_details(raw_out) if vulnerable else {}
        evidence = create_evidence_list(raw_out, enumeration_results) if vulnerable else []
        evaluation = evaluate_vulnerability(injection_details, enumeration_results) if vulnerable else {}

        endpoint_result = create_endpoint_result(
            method=method,
            path=raw_path,
            summary=summary,
            vulnerable=vulnerable,
            scan_url=scan_url,
            sqlmap_output=raw_out,
            injection_details=injection_details,
            enumeration_results=enumeration_results,
            evidence=evidence,
            evaluation=evaluation
        )

        output_aggregator.add_endpoint_result(endpoint_result)

        return f"Completed scanning {method.upper()} {raw_path}"

    except Exception as e:
        logging.error(f'Exception during scanning {method.upper()} {raw_path}: {e}')
        # Add failed endpoint to aggregator
        failed_result = create_endpoint_result(
            method=method,
            path=raw_path,
            summary=summary,
            vulnerable=False,
            scan_url=scan_url if 'scan_url' in locals() else server_url + raw_path,
            sqlmap_output=str(e),
            evaluation={"error": str(e)}
        )
        output_aggregator.add_endpoint_result(failed_result)
        return f"Failed scanning {method.upper()} {raw_path}: {e}"


def main_cli():
    """Main CLI entry point"""
    ap = setup_cli_parser()
    args = ap.parse_args()

    # Configure logging
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Add a handler for console output
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

    if args.sqlmap == './sqlmap-dev/sqlmap.py':
        sqlmap_path = ensure_sqlmap()
    else:
        from pathlib import Path
        sqlmap_path = Path(args.sqlmap)
        if not sqlmap_path.exists():
            raise FileNotFoundError(f"SQLMap not found at {sqlmap_path}")

    spec, base_dir = load_openapi(args.openapi)
    servers = spec.get('servers', [{'url': 'http://localhost:5000'}])
    base_server_url = servers[0].get('url', 'http://localhost:5000')
    if args.server_url:
        base_server_url = args.server_url

    # Generate server URLs for multiple ports if specified
    server_urls = []
    if args.ports:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(base_server_url)
        for port in args.ports:
            # Replace the port in the URL
            netloc = parsed.hostname + f':{port}'
            if parsed.username or parsed.password:
                netloc = f"{parsed.username}:{parsed.password}@{parsed.hostname}:{port}"
            new_url = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
            server_urls.append(new_url)
        logging.info(f"Scanning {len(server_urls)} ports: {args.ports}")
    else:
        server_urls = [base_server_url]

    # build global extra flags
    from .config import DEFAULT_SQLMAP_EXTRA
    extra_flags = list(DEFAULT_SQLMAP_EXTRA)
    if args.threads:
        extra_flags += ['--threads', str(args.threads)]
    if args.technique:
        extra_flags += ['--technique', args.technique]

    # Scan each server URL
    for server_url in server_urls:
        logging.info(f"Starting scan for server: {server_url}")

        # Create port-specific logs directory
        if args.ports and len(server_urls) > 1:
            parsed = urlparse(server_url)
            port_suffix = f"_port_{parsed.port}" if parsed.port else ""
            port_logs_dir = args.logs + port_suffix
        else:
            port_logs_dir = args.logs

        ensure_dir(port_logs_dir)

        master_log_file = os.path.join(port_logs_dir, 'master_log.txt')

        # Add a handler for file output (per port)
        port_file_handler = logging.FileHandler(master_log_file)
        port_file_handler.setLevel(log_level)
        port_file_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
        logger.addHandler(port_file_handler)

        # Collect all endpoints to scan
        endpoints_to_scan = []

        for raw_path, path_item in spec.get('paths', {}).items():
            for method in ('get','post','put','delete','patch','head','options'):
                if method in path_item:
                    operation = path_item[method]
                    has_params = bool(path_item.get('parameters') or operation.get('parameters'))
                    has_body = 'requestBody' in operation
                    if not (has_params or has_body):
                        continue

                    # Apply endpoint filtering
                    endpoint_path = f"{method.upper()} {raw_path}"
                    if args.include_pattern:
                        if not re.search(args.include_pattern, endpoint_path, re.IGNORECASE):
                            logging.debug(f'Skipping endpoint (not matching include pattern): {endpoint_path}')
                            continue
                    if args.exclude_pattern:
                        if re.search(args.exclude_pattern, endpoint_path, re.IGNORECASE):
                            logging.debug(f'Skipping endpoint (matching exclude pattern): {endpoint_path}')
                            continue

                    summary = operation.get('summary') or operation.get('operationId') or f"{method}_{raw_path}"
                    safe_name = safe_summary_to_filename(summary)

                    endpoints_to_scan.append((raw_path, method, operation, summary, safe_name))

        logging.info(f"Found {len(endpoints_to_scan)} endpoints to scan on {server_url}")

        # Initialize output aggregator in the workspace root folder
        workspace_root = os.path.dirname(os.getcwd())  # One directory up from sqlmap-agent
        if args.ports and len(server_urls) > 1:
            parsed = urlparse(server_url)
            port_suffix = f"_port_{parsed.port}" if parsed.port else ""
            output_file = os.path.join(workspace_root, f'output{port_suffix}.json')
        else:
            output_file = os.path.join(workspace_root, 'output.json')
        output_aggregator = OutputAggregator(output_file)

        # Update scan metadata
        scan_settings = {
        "threads": args.threads,
        "technique": args.technique,
        "confirm": args.confirm,
        "max_dbs": args.max_dbs,
        "max_tables": args.max_tables,
        "max_rows": args.max_rows,
        "timeout": args.timeout,
        "concurrency": args.concurrency
        }
        output_aggregator.update_scan_metadata(server_url, len(endpoints_to_scan), scan_settings)

        # Scan endpoints concurrently
        if args.concurrency > 1:
            logging.info(f"Scanning with concurrency level: {args.concurrency}")

            def scan_with_thread_pool():
                with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                    # Submit all tasks
                    futures = [
                        executor.submit(scan_single_endpoint, endpoint_data, server_url, sqlmap_path, port_logs_dir, extra_flags, args, spec, base_dir, output_aggregator)
                        for endpoint_data in endpoints_to_scan
                    ]

                    # Collect results
                    for future in futures:
                        try:
                            result = future.result()
                            logging.info(result)
                        except Exception as e:
                            logging.error(f"Concurrent scan task failed: {e}")

            # Run the concurrent scanning
            scan_with_thread_pool()
        else:
            # Sequential scanning (original behavior)
            logging.info("Scanning endpoints sequentially")

            for endpoint_data in endpoints_to_scan:
                raw_path, method, operation, summary, safe_name = endpoint_data

                try:
                    base_cmd = construct_sqlmap_command(
                        server_url, raw_path, method, spec['paths'][raw_path], operation,
                        spec, base_dir,
                        sqlmap_path, os.path.join(port_logs_dir, safe_name + '_sqlmap'),
                        extra_flags
                    )

                    # optionally flush session per-target
                    if args.flush_session:
                        try:
                            # produce the same concrete path used by the scan (substitute path params)
                            substituted_path = substitute_path_params(
                                raw_path,
                                collect_parameters(spec['paths'][raw_path], operation, spec, base_dir),
                                spec,
                                base_dir
                            )
                            url_for_flush = server_url.rstrip('/') + substituted_path

                            # Build a safer flush command: non-interactive + minimal payload for POST-like methods
                            flush_cmd = [
                                sys.executable,
                                str(sqlmap_path),
                                '--batch',
                                '--flush-session',
                                '-u',
                                url_for_flush,
                            ]

                            flush_log = os.path.join(port_logs_dir, safe_name + '_flush.log')

                            if method.lower() in ('post', 'put', 'patch'):
                                payload = None
                                if 'requestBody' in operation:
                                    content = operation['requestBody'].get('content', {})
                                    if 'application/x-www-form-urlencoded' in content:
                                        props = content['application/x-www-form-urlencoded'].get('schema', {}).get('properties', {}) or {}
                                        payload = urlencode({k: build_param_value({'name': k, 'schema': v}, spec, base_dir) for k, v in props.items()}, doseq=True)
                                    elif 'multipart/form-data' in content:
                                        props = content['multipart/form-data'].get('schema', {}).get('properties', {}) or {}
                                        payload = urlencode({k: build_param_value({'name': k, 'schema': v}, spec, base_dir) for k, v in props.items()}, doseq=True)
                                    elif 'application/json' in content:
                                        schema = content['application/json'].get('schema', {}) or {}
                                        payload = construct_json_string_from_schema(schema, spec, base_dir)
                                if not payload:
                                    payload = 'test=1'
                                if payload.strip().startswith('{'):
                                    flush_cmd += ['-H', 'Content-Type: application/json']
                                flush_cmd += ['--data', payload]

                            # run flush (non-interactive)
                            run_sqlmap(flush_cmd, master_log_file=master_log_file, log_full_output=args.log_full_output, timeout=args.timeout, use_json=False)
                            logging.info(f'Flushed sqlmap session for {url_for_flush} (log: {flush_log})')

                        except Exception as e:
                            logging.warning(f'Warning: error when flushing session: {e}')

                    # Run discovery -> then optional enumerate
                    try:
                        scan_url = server_url.rstrip('/') + substitute_path_params(
                            raw_path,
                            collect_parameters(spec['paths'][raw_path], operation, spec, base_dir),
                            spec,
                            base_dir
                        )
                        vulnerable, raw_out, enumeration_results = enumerate_if_vulnerable(
                            base_cmd,
                            scan_url,
                            port_logs_dir,
                            safe_name,
                            sqlmap_path,
                            args.confirm,
                            args.max_tables,
                            args.max_rows,
                            master_log_file,
                            args.log_full_output
                        )

                        # Create aggregated result
                        from .output_aggregator import create_endpoint_result, extract_injection_details, create_evidence_list, evaluate_vulnerability
                        injection_details = extract_injection_details(raw_out) if vulnerable else {}
                        evidence = create_evidence_list(raw_out, enumeration_results) if vulnerable else []
                        evaluation = evaluate_vulnerability(injection_details, enumeration_results) if vulnerable else {}

                        endpoint_result = create_endpoint_result(
                            method=method,
                            path=raw_path,
                            summary=summary,
                            vulnerable=vulnerable,
                            scan_url=scan_url,
                            sqlmap_output=raw_out,
                            injection_details=injection_details,
                            enumeration_results=enumeration_results,
                            evidence=evidence,
                            evaluation=evaluation
                        )

                        output_aggregator.add_endpoint_result(endpoint_result)
                    except Exception as e:
                        logging.error(f'Exception during scanning: {e}')
                        # Add failed endpoint to aggregator
                        failed_result = create_endpoint_result(
                            method=method,
                            path=raw_path,
                            summary=summary,
                            vulnerable=False,
                            scan_url=scan_url,
                            sqlmap_output=str(e),
                            evaluation={"error": str(e)}
                        )
                        output_aggregator.add_endpoint_result(failed_result)

                except Exception as e:
                    logging.error(f'Exception during scanning {method.upper()} {raw_path}: {e}')
                    # Add failed endpoint to aggregator
                    failed_result = create_endpoint_result(
                        method=method,
                        path=raw_path,
                        summary=summary,
                        vulnerable=False,
                        scan_url=server_url + raw_path,
                        sqlmap_output=str(e),
                        evaluation={"error": str(e)}
                    )
                    output_aggregator.add_endpoint_result(failed_result)

        # Finalize the aggregated output
        output_aggregator.finalize_scan()

        # Remove the port-specific file handler
        logger.removeHandler(port_file_handler)
        port_file_handler.close()
