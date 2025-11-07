"""
Main scanning orchestration logic
"""

import logging
import os
import sys
from urllib.parse import urlparse

from .config import setup_cli_parser
from .openapi import load_openapi
from .sqlmap import (
    ensure_sqlmap, construct_sqlmap_command, enumerate_if_vulnerable
)
from .utils import ensure_dir


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

        for raw_path, path_item in spec.get('paths', {}).items():
            for method in ('get','post','put','delete','patch','head','options'):
                if method in path_item:
                    operation = path_item[method]
                    has_params = bool(path_item.get('parameters') or operation.get('parameters'))
                    has_body = 'requestBody' in operation
                    if not (has_params or has_body):
                        continue
                    summary = operation.get('summary') or operation.get('operationId') or f"{method}_{raw_path}"
                    from .utils import safe_summary_to_filename
                    safe_name = safe_summary_to_filename(summary)

                    base_cmd = construct_sqlmap_command(
                        server_url, raw_path, method, path_item, operation,
                        spec, base_dir,
                        sqlmap_path, os.path.join(port_logs_dir, safe_name + '_sqlmap'),
                        extra_flags
                    )

                    # optionally flush session per-target
                    if args.flush_session:
                        try:
                            # produce the same concrete path used by the scan (substitute path params)
                            from .openapi import collect_parameters, substitute_path_params
                            substituted_path = substitute_path_params(
                                raw_path,
                                collect_parameters(path_item, operation, spec, base_dir),
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
                                        from urllib.parse import urlencode
                                        from .openapi import build_param_value
                                        props = content['application/x-www-form-urlencoded'].get('schema', {}).get('properties', {}) or {}
                                        payload = urlencode({k: build_param_value({'name': k, 'schema': v}, spec, base_dir) for k, v in props.items()}, doseq=True)
                                    elif 'multipart/form-data' in content:
                                        from urllib.parse import urlencode
                                        from .openapi import build_param_value
                                        props = content['multipart/form-data'].get('schema', {}).get('properties', {}) or {}
                                        payload = urlencode({k: build_param_value({'name': k, 'schema': v}, spec, base_dir) for k, v in props.items()}, doseq=True)
                                    elif 'application/json' in content:
                                        from .openapi import construct_json_string_from_schema
                                        schema = content['application/json'].get('schema', {}) or {}
                                        payload = construct_json_string_from_schema(schema, spec, base_dir)
                                if not payload:
                                    payload = 'test=1'
                                if payload.strip().startswith('{'):
                                    flush_cmd += ['-H', 'Content-Type: application/json']
                                flush_cmd += ['--data', payload]

                            # run flush (non-interactive)
                            from .sqlmap import run_sqlmap
                            run_sqlmap(flush_cmd, master_log_file=master_log_file, log_full_output=args.log_full_output, timeout=args.timeout)
                            logging.info(f'Flushed sqlmap session for {url_for_flush} (log: {flush_log})')

                        except Exception as e:
                            logging.warning(f'Warning: error when flushing session: {e}')

                    # Run discovery -> then optional enumerate
                    try:
                        scan_url = server_url.rstrip('/') + substitute_path_params(
                            raw_path,
                            collect_parameters(path_item, operation, spec, base_dir),
                            spec,
                            base_dir
                        )
                        vulnerable, raw_out = enumerate_if_vulnerable(
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
                    except Exception as e:
                        logging.error(f'Exception during scanning: {e}')

        # Remove the port-specific file handler
        logger.removeHandler(port_file_handler)
        port_file_handler.close()
