"""
SQLMap command construction and execution
"""

import logging
import os
import subprocess
import time
import sys
import re
from pathlib import Path

from .utils import shell_join, detected_injection_in_output, extract_db_names
from .openapi import collect_parameters, substitute_path_params, build_param_value, construct_json_string_from_schema


def ensure_sqlmap(sqlmap_dir='sqlmap-dev'):
    """Ensure SQLMap is available by cloning it if not present."""
    sqlmap_path = Path(sqlmap_dir) / 'sqlmap.py'
    if not sqlmap_path.exists():
        logging.info("SQLMap not found. Cloning from GitHub...")
        result = subprocess.run(['git', 'clone', '--depth', '1', 'https://github.com/sqlmapproject/sqlmap.git', sqlmap_dir], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to clone SQLMap: {result.stderr}")
        logging.info("SQLMap cloned successfully.")
    return sqlmap_path


def build_base_sqlmap_cmd(sqlmap_path, url, output_dir, extra_flags=None):
    """Build base SQLMap command"""
    cmd = [sys.executable, str(sqlmap_path), '-u', url, '--output-dir', str(output_dir)]
    if extra_flags:
        cmd.extend(extra_flags)
    return cmd


def run_sqlmap(cmd_list, master_log_file, log_full_output, capture_output=True, timeout=None, use_json=False):
    """Run sqlmap command. Return (returncode, stdout+stderr text, json_data)."""
    logging.info(f'Executing command: {shell_join(cmd_list)}')
    try:
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1
        )

        out_lines = []
        start = time.time()

        try:
            for line in proc.stdout:
                if line is None:
                    break
                out_lines.append(line)
                # Filter out ASCII art and non-critical warnings
                if not re.match(r'^\s*(\[\*\]|___|\|)|\\s*$', line) and 'testing connection' not in line and 'using' + chr(92) + ' as the output directory' not in line:
                    logging.info(line.rstrip())
                # check timeout between lines
                if timeout and (time.time() - start) > timeout:
                    proc.kill()
                    out_lines.append('\n[ERROR] Timeout reached and process killed\n')
                    break

            if proc.poll() is None:
                if timeout:
                    elapsed = time.time() - start
                    remaining = max(0.1, timeout - elapsed)
                    try:
                        proc.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        out_lines.append('\n[ERROR] Timeout reached during wait() and process killed\n')
                else:
                    proc.wait()

        except KeyboardInterrupt:
            try:
                proc.kill()
            except Exception:
                pass
            out_lines.append('\n[ERROR] KeyboardInterrupt - process killed by parent\n')
            raise

        rc = proc.poll()
        full = ''.join(out_lines)

        if log_full_output and master_log_file:
            try:
                with open(master_log_file, 'a', encoding='utf-8') as f:
                    f.write(f'\n{"-"*20} EXECUTING COMMAND {"-"*20}\n')
                    f.write(shell_join(cmd_list) + '\n')
                    f.write(f'{"-"*50}\n')
                    f.write(full)
            except Exception as e:
                logging.warning(f'Could not write to master log file: {e}')

        return rc, full, None

    except FileNotFoundError as e:
        return 255, f'[ERROR] sqlmap executable not found: {e}', None
    except Exception as e:
        return 254, f'[ERROR] Exception running sqlmap: {e}', None


def construct_sqlmap_command(server_url, raw_path, method, path_item, operation, spec, base_dir, sqlmap_path, output_dir, extra_flags):
    """Construct complete SQLMap command for endpoint"""
    params = collect_parameters(path_item, operation, spec, base_dir)
    query_params = [p for p in params if p.get('in') == 'query']
    path_params = [p for p in params if p.get('in') == 'path']
    header_params = [p for p in params if p.get('in') == 'header']
    cookie_params = [p for p in params if p.get('in') == 'cookie']

    path = substitute_path_params(raw_path, params, spec, base_dir)
    base = server_url.rstrip('/')
    url = base + path

    # initial cmd
    cmd = build_base_sqlmap_cmd(sqlmap_path, url, output_dir, extra_flags)

    # security headers / query params
    from .openapi import security_headers_and_params
    sec_headers, sec_queries = security_headers_and_params(operation, spec)
    for hn, hv in sec_headers.items():
        cmd.extend(['-H', f'{hn}: {hv}'])

    data_string = None
    param_focus = []

    if method.lower() in ('get', 'delete', 'head', 'options'):
        if query_params or sec_queries:
            from urllib.parse import urlencode
            qs = {}
            for p in query_params:
                qs[p['name']] = build_param_value(p, spec, base_dir)
            qs.update(sec_queries)
            url_with_qs = url + ('?' if '?' not in url else '&') + urlencode(qs, doseq=True)
            # replace -u with new url
            cmd[cmd.index('-u')+1] = url_with_qs
            param_focus = [p['name'] for p in query_params]
    else:
        if 'requestBody' in operation:
            content = operation['requestBody'].get('content', {})
            if 'application/json' in content:
                schema = content['application/json'].get('schema', {})
                json_str = construct_json_string_from_schema(schema, spec, base_dir)
                data_string = json_str
                cmd.extend(['-H', 'Content-Type: application/json', '--data', json_str])
            elif 'application/x-www-form-urlencoded' in content:
                from urllib.parse import urlencode
                props = content['application/x-www-form-urlencoded'].get('schema', {}).get('properties', {})
                qs = {k: build_param_value({'name': k, 'schema': v}, spec, base_dir) for k, v in props.items()}
                data_string = urlencode(qs, doseq=True)
                cmd.extend(['--data', data_string])
            elif 'multipart/form-data' in content:
                from urllib.parse import urlencode
                props = content['multipart/form-data'].get('schema', {}).get('properties', {})
                qs = {k: build_param_value({'name': k, 'schema': v}, spec, base_dir) for k, v in props.items()}
                data_string = urlencode(qs, doseq=True)
                cmd.extend(['--data', data_string])
        if data_string is None and query_params:
            from urllib.parse import urlencode
            qs = {p['name']: build_param_value(p, spec, base_dir) for p in query_params}
            data_string = urlencode(qs)
            cmd.extend(['--data', data_string])
            param_focus = [p['name'] for p in query_params]

    for h in header_params:
        val = build_param_value(h, spec, base_dir)
        cmd.extend(['-H', f'{h["name"]}: {val}'])

    if cookie_params:
        cookie_str = '; '.join([f'{c["name"]}={build_param_value(c, spec, base_dir)}' for c in cookie_params])
        cmd.extend(['--cookie', cookie_str])

    if param_focus:
        cmd.extend(['-p', ','.join(param_focus)])

    return cmd


def execute_and_capture(cmd_list, logs_dir, summary, log_full_output, use_json=False):
    """Execute command and capture output"""
    from .utils import ensure_dir, safe_summary_to_filename

    ensure_dir(logs_dir)
    safe_name = safe_summary_to_filename(summary)
    log_file = os.path.join(logs_dir, f'{safe_name}.log')
    rc, out, json_data = run_sqlmap(cmd_list, master_log_file=None, log_full_output=log_full_output, use_json=use_json)
    return rc, out, log_file, json_data


def enumerate_if_vulnerable(base_cmd, url, logs_dir, summary, sqlmap_path, confirm, max_tables, max_rows, master_log_file, log_full_output):
    """Run discovery scan and optionally enumerate if vulnerable"""
    # run a discovery (non-destructive) scan
    discovery = list(base_cmd)
    # ensure tactics if not forced already
    if not any(arg.startswith('--technique') for arg in discovery):
        discovery.extend(['--technique', 'BU'])
    # add level/risk only if they don't already exist in args
    if not any(arg.startswith('--level') for arg in discovery):
        discovery.extend(['--level', '3'])
    if not any(arg.startswith('--risk') for arg in discovery):
        discovery.extend(['--risk', '1'])

    rc, out, logfile, _ = execute_and_capture(discovery, logs_dir, summary + '_discovery', log_full_output, use_json=False)

    # Check for injection using text parsing (JSON disabled for now)
    injection_detected = detected_injection_in_output(out)

    if not injection_detected:
        logging.info(f'No clear injection detected during discovery for {url}')
        return False, out, {}

    logging.warning(f'Potential injection detected. Output saved to {logfile}')
    with open(os.path.join(logs_dir, f'{summary}_vulnerable.log'), 'w', encoding='utf-8') as f:
        f.write(out)

    if not confirm:
        logging.warning('--confirm not set: skipping enumeration (DB listing / dumping). Use --confirm to enable.')
        return True, out

    # get DB list
    dbs_cmd = list(base_cmd) + ['--dbs']
    rc, out_dbs, dbs_log, _ = execute_and_capture(dbs_cmd, logs_dir, summary + '_dbs', log_full_output)
    dbs = extract_db_names(out_dbs)
    if not dbs:
        logging.warning(f'Could not parse DB names, but sqlmap output saved to {dbs_log}')
    else:
        logging.info(f'Found DBs: {dbs}')

    # enumerate tables per DB (limited)
    all_found = {}
    for db in dbs[:max_tables]:
        tables_cmd = list(base_cmd) + ['-D', db, '--tables']
        rc, out_tables, tables_log, _ = execute_and_capture(tables_cmd, logs_dir, f'{summary}_tables_{db}', log_full_output)
        # crude parse for table names
        tables = re.findall(r'Table: (.+)\n', out_tables)
        if not tables:
            # try alternative parsing
            tables = re.findall(r'\\|\\s*(\\w+)\\s*\\|', out_tables)
        tables = list(dict.fromkeys([t.strip() for t in tables if t.strip()]))
        logging.info(f'DB {db} - tables found (limit {max_tables}): {tables[:max_tables]}')
        all_found[db] = tables

        # dump each table (limited by max_rows)
        for tbl in tables[:max_tables]:
            dump_cmd = list(base_cmd) + ['-D', db, '-T', tbl, '--dump', '--limit', str(max_rows)]
            rc, out_dump, dump_log, _ = execute_and_capture(dump_cmd, logs_dir, f'{summary}_dump_{db}_{tbl}', log_full_output)
            logging.info(f'Dump for {db}.{tbl} saved to {dump_log}')

    return True, out, all_found
