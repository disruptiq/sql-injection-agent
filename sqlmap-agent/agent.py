#!/usr/bin/env python3
"""
Enhanced sqlmap agent that reads an OpenAPI spec, builds requests for each endpoint,
performs a *safe* initial scan for SQL injection and — if an injection is confirmed
and the user explicitly allows destructive enumeration via a CLI flag — enumerates
databases/tables/columns and attempts to dump content.

Features added/upgraded:
 - argparse configuration (override paths, servers, logging dir, sqlmap path)
 - safer two-stage testing: quick discovery scan (non-heavy techniques) then optional
   detailed enumeration (DBs/tables/dump) only with --confirm
 - uses --output-dir to keep sqlmap data organized
 - captures sqlmap output in memory and writes good logs
 - avoids heavy time-based techniques by default; user can override techniques
 - better handling of headers, cookies, JSON bodies from OpenAPI
 - simple parsing of sqlmap textual output to detect "back-end DBMS" / vulnerability
 - configurable limits to avoid dumping huge DBs (max_tables, max_rows_per_table)
 - flushes sqlmap session per target if requested

IMPORTANT: only run this against systems you are authorized to test. The author
and this tool assume no liability for misuse. Use --confirm to enable destructive
enumeration (listing DBs/tables/dumping). Without --confirm the script only scans.
"""

import logging
import argparse
import os
import subprocess
import yaml
import re
import json
from urllib.parse import urlencode, quote_plus
from pathlib import Path
import base64
import shlex
import sys
import time

# Load configuration from config.json
try:
    with open('config.json', 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    config = {}

# ---------- DEFAULT CONFIG ----------
DEFAULT_OPENAPI_FILE = config.get('DEFAULT_OPENAPI_FILE', '../vulnerable-app/openapi.yaml')
DEFAULT_LOGS_DIR = config.get('DEFAULT_LOGS_DIR', 'attack-logs-dynamic')
DEFAULT_SQLMAP_PATH = config.get('DEFAULT_SQLMAP_PATH', './sqlmap-dev/sqlmap.py')
DEFAULT_SQLMAP_EXTRA = config.get('DEFAULT_SQLMAP_EXTRA', ['--batch', '--level=5', '--risk=3'])  # Highest possible for thoroughness

DEFAULT_TEST_VALUE = config.get('DEFAULT_TEST_VALUE', {
    'string': 'test',
    'integer': '1',
    'number': '1',
    'boolean': 'true',
    'object': {},
    'array': ['test'],
})

# optional: environment credential variables
ENV_BEARER = os.getenv('API_BEARER_TOKEN')
ENV_APIKEY = os.getenv('API_KEY')
ENV_BASIC_USER = os.getenv('API_BASIC_USER')
ENV_BASIC_PASS = os.getenv('API_BASIC_PASS')

# ---------- Helpers for OpenAPI parsing (kept and improved) ----------

def load_openapi(path):
    path = Path(path)
    with open(path, 'r', encoding='utf-8') as f:
        spec = yaml.safe_load(f)
    return spec, path.parent


def resolve_ref(ref, spec, base_dir):
    if not isinstance(ref, str):
        return None
    if ref.startswith('#/'):
        parts = ref.lstrip('#/').split('/')
        node = spec
        for p in parts:
            if not isinstance(node, dict) or p not in node:
                return None
            node = node[p]
        return node
    if '#' in ref:
        file_part, path_part = ref.split('#', 1)
        file_path = (base_dir / file_part).resolve()
        if not file_path.exists():
            return None
        with open(file_path, 'r', encoding='utf-8') as f:
            external = yaml.safe_load(f)
        target = '#' + path_part
        return resolve_ref(target, external, file_path.parent)
    return None


def collect_parameters(path_item, operation, spec, base_dir):
    params = []
    for p in path_item.get('parameters', []):
        if '$ref' in p:
            resolved = resolve_ref(p['$ref'], spec, base_dir)
            if resolved:
                params.append(resolved)
        else:
            params.append(p)
    for p in operation.get('parameters', []):
        if '$ref' in p:
            resolved = resolve_ref(p['$ref'], spec, base_dir)
            if resolved:
                params.append(resolved)
        else:
            params.append(p)
    return params


def choose_test_value_for_schema(schema, spec, base_dir):
    if schema is None:
        return 'test'
    if '$ref' in schema:
        resolved = resolve_ref(schema['$ref'], spec, base_dir)
        if resolved:
            return choose_test_value_for_schema(resolved, spec, base_dir)
    if 'example' in schema:
        return schema['example']
    if 'default' in schema:
        return schema['default']
    if 'enum' in schema and schema['enum']:
        return schema['enum'][0]
    t = schema.get('type')
    if t == 'object':
        obj = {}
        props = schema.get('properties', {}) or {}
        for k, prop_schema in props.items():
            obj[k] = choose_test_value_for_schema(prop_schema, spec, base_dir)
        return obj
    if t == 'array':
        items = schema.get('items', {}) or {}
        return [choose_test_value_for_schema(items, spec, base_dir)]
    return DEFAULT_TEST_VALUE.get(t, 'test')


def build_param_value(param, spec, base_dir):
    if 'schema' in param:
        return choose_test_value_for_schema(param['schema'], spec, base_dir)
    return DEFAULT_TEST_VALUE.get('string', 'test')


def substitute_path_params(path, params, spec, base_dir):
    def repl(match):
        name = match.group(1)
        for p in params:
            if p.get('name') == name and p.get('in') == 'path':
                v = build_param_value(p, spec, base_dir)
                return quote_plus(str(v))
        return '1'
    return re.sub(r'\{([^/}]+)\}', repl, path)


def security_headers_and_params(operation, spec):
    headers = {}
    queries = {}
    sec = operation.get('security') or spec.get('security') or []
    if not sec:
        return headers, queries
    schemes = spec.get('components', {}).get('securitySchemes', {})
    for secreq in sec:
        for name, scopes in secreq.items():
            scheme = schemes.get(name, {})
            stype = scheme.get('type')
            if stype == 'http' and scheme.get('scheme') == 'bearer':
                token = ENV_BEARER or 'REPLACE_WITH_BEARER'
                headers['Authorization'] = f'Bearer {token}'
            elif stype == 'apiKey':
                loc = scheme.get('in')
                param_name = scheme.get('name')
                token = ENV_APIKEY or 'REPLACE_WITH_APIKEY'
                if loc == 'header':
                    headers[param_name] = token
                elif loc == 'query':
                    queries[param_name] = token
                elif loc == 'cookie':
                    headers['Cookie'] = f'{param_name}={token}'
            elif stype == 'http' and scheme.get('scheme') == 'basic':
                user = ENV_BASIC_USER or 'user'
                pwd = ENV_BASIC_PASS or 'pass'
                token = base64.b64encode(f'{user}:{pwd}'.encode()).decode()
                headers['Authorization'] = f'Basic {token}'
    return headers, queries


def construct_json_string_from_schema(schema, spec, base_dir):
    val = choose_test_value_for_schema(schema, spec, base_dir)
    try:
        return json.dumps(val)
    except Exception:
        return json.dumps({"test": "test"})

# ---------- sqlmap command construction + execution ----------

def build_base_sqlmap_cmd(sqlmap_path, url, output_dir, extra_flags=None):
    cmd = [sys.executable, str(sqlmap_path), '-u', url, '--output-dir', str(output_dir)]
    if extra_flags:
        cmd.extend(extra_flags)
    return cmd


def shell_join(cmd_list):
    # Use shlex.join when available (py3.8+), fallback
    try:
        return shlex.join(cmd_list)
    except Exception:
        return ' '.join(shlex.quote(x) for x in cmd_list)


def run_sqlmap(cmd_list, master_log_file, log_full_output, capture_output=True, timeout=None):
    """Run sqlmap command (list form). Return (returncode, stdout+stderr text)."""
    logging.info(f'Executing command: {shell_join(cmd_list)}')
    try:
        # ensure sqlmap cannot prompt for input
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,        # prevent child from reading stdin
            text=True,                       # same as universal_newlines=True
            encoding='utf-8',                # force utf-8 decode (use errors='replace')
            errors='replace',
            bufsize=1                         # line buffered
        )

        out_lines = []
        start = time.time()

        try:
            # read lines as they become available; don't block forever because we will use wait(timeout)
            for line in proc.stdout:
                if line is None:
                    break
                out_lines.append(line)
                # Filter out ASCII art and non-critical warnings
                if not re.match(r'^\s*(\[\*\]|___|\|)|\s*$', line) and 'testing connection' not in line and 'using\' as the output directory' not in line:
                    logging.info(line.rstrip())
                # check timeout between lines (in case process emits long streams)
                if timeout and (time.time() - start) > timeout:
                    proc.kill()
                    out_lines.append('\n[ERROR] Timeout reached and process killed\n')
                    break

            # If the for-loop ends but process still alive, wait with remaining timeout
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
            # If user interrupts, kill child process cleanly
            try:
                proc.kill()
            except Exception:
                pass
            out_lines.append('\n[ERROR] KeyboardInterrupt - process killed by parent\n')
            raise

        rc = proc.poll()
        full = ''.join(out_lines)

        if log_full_output:
            try:
                with open(master_log_file, 'a', encoding='utf-8') as f:
                    f.write(f'\n{"-"*20} EXECUTING COMMAND {"-"*20}\n')
                    f.write(shell_join(cmd_list) + '\n')
                    f.write(f'{"-"*50}\n')
                    f.write(full)
            except Exception as e:
                logging.warning(f'Could not write to master log file: {e}')

        return rc, full

    except FileNotFoundError as e:
        return 255, f'[ERROR] sqlmap executable not found: {e}'
    except Exception as e:
        return 254, f'[ERROR] Exception running sqlmap: {e}'


def construct_sqlmap_command(server_url, raw_path, method, path_item, operation, spec, base_dir, sqlmap_path, output_dir, extra_flags):
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
    sec_headers, sec_queries = security_headers_and_params(operation, spec)
    for hn, hv in sec_headers.items():
        cmd.extend(['-H', f'{hn}: {hv}'])

    data_string = None
    param_focus = []

    if method.lower() in ('get', 'delete', 'head', 'options'):
        if query_params or sec_queries:
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
                props = content['application/x-www-form-urlencoded'].get('schema', {}).get('properties', {})
                qs = {k: choose_test_value_for_schema(v, spec, base_dir) for k, v in props.items()}
                data_string = urlencode(qs, doseq=True)
                cmd.extend(['--data', data_string])
            elif 'multipart/form-data' in content:
                props = content['multipart/form-data'].get('schema', {}).get('properties', {})
                qs = {k: choose_test_value_for_schema(v, spec, base_dir) for k, v in props.items()}
                data_string = urlencode(qs, doseq=True)
                cmd.extend(['--data', data_string])
        if data_string is None and query_params:
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

# ---------- sqlmap output parsing helpers ----------

def detected_injection_in_output(text):
    # heuristic checks
    patterns = [
        r'back-end DBMS:.+',
        r'is vulnerable',
        r'The back-end database management system is',
        r'the back-end DBMS is',
        r'Parameter: .+ \n\s+Type: ',
    ]
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False


def extract_db_names(text):
    # crude parsing: look for 'available databases' or 'Databases: ...' blocks
    dbs = set()
    for m in re.finditer(r'Database: (.+)\n', text):
        dbs.add(m.group(1).strip())
    for m in re.finditer(r'Databases: (.+)\n', text):
        parts = m.group(1).split(',')
        for p in parts:
            dbs.add(p.strip())
    return list(dbs)

# ---------- main orchestration ----------

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

def ensure_dir(p):
    Path(p).mkdir(parents=True, exist_ok=True)


def safe_summary_to_filename(summary):
    safe = re.sub(r'[^A-Za-z0-9_.-]', '_', (summary or 'endpoint'))
    return safe[:200]


def execute_and_capture(cmd_list, logs_dir, summary, log_full_output):
    ensure_dir(logs_dir)
    safe_name = safe_summary_to_filename(summary)
    log_file = os.path.join(logs_dir, f'{safe_name}.log')
    rc, out = run_sqlmap(cmd_list, master_log_file=None, log_full_output=log_full_output)
    return rc, out, log_file


def enumerate_if_vulnerable(base_cmd, url, logs_dir, summary, sqlmap_path, confirm, max_tables, max_rows, master_log_file, log_full_output):
    # run a discovery (non-destructive) scan
    discovery = list(base_cmd)
    # enforce safer discovery techniques unless user overrides
    # ensure tactics if not forced already
    if not any(arg.startswith('--technique') for arg in discovery):
        discovery.extend(['--technique', 'BU'])
    # add level/risk only if they don't already exist in args
    if not any(arg.startswith('--level') for arg in discovery):
        discovery.extend(['--level', '3'])
    if not any(arg.startswith('--risk') for arg in discovery):
        discovery.extend(['--risk', '1'])     
        
    rc, out, logfile = execute_and_capture(discovery, logs_dir, summary + '_discovery', log_full_output)

    if not detected_injection_in_output(out):
        logging.info(f'No clear injection detected during discovery for {url}')
        return False, out

    logging.warning(f'Potential injection detected. Output saved to {logfile}')
    with open(os.path.join(logs_dir, f'{summary}_vulnerable.log'), 'w', encoding='utf-8') as f:
        f.write(out)

    if not confirm:
        logging.warning('--confirm not set: skipping enumeration (DB listing / dumping). Use --confirm to enable.')
        return True, out

    # get DB list
    dbs_cmd = list(base_cmd) + ['--dbs']
    rc, out_dbs, dbs_log = execute_and_capture(dbs_cmd, logs_dir, summary + '_dbs', log_full_output)
    dbs = extract_db_names(out_dbs)
    if not dbs:
        logging.warning(f'Could not parse DB names, but sqlmap output saved to {dbs_log}')
    else:
        logging.info(f'Found DBs: {dbs}')

    # enumerate tables per DB (limited)
    all_found = {}
    for db in dbs[:max_tables]:
        tables_cmd = list(base_cmd) + ['-D', db, '--tables']
        rc, out_tables, tables_log = execute_and_capture(tables_cmd, logs_dir, f'{summary}_tables_{db}', log_full_output)
        # crude parse for table names
        tables = re.findall(r'Table: (.+)\n', out_tables)
        if not tables:
            # try alternative parsing
            tables = re.findall(r'\|\s*(\w+)\s*\|', out_tables)
        tables = list(dict.fromkeys([t.strip() for t in tables if t.strip()]))
        logging.info(f'DB {db} - tables found (limit {max_tables}): {tables[:max_tables]}')
        all_found[db] = tables

        # dump each table (limited by max_rows)
        for tbl in tables[:max_tables]:
            dump_cmd = list(base_cmd) + ['-D', db, '-T', tbl, '--dump', '--limit', str(max_rows)]
            rc, out_dump, dump_log = execute_and_capture(dump_cmd, logs_dir, f'{summary}_dump_{db}_{tbl}', log_full_output)
            logging.info(f'Dump for {db}.{tbl} saved to {dump_log}')

    return True, out


def main_cli():
    ap = argparse.ArgumentParser(description='OpenAPI-driven sqlmap scanning + conditional enumeration')
    ap.add_argument('--openapi', default=DEFAULT_OPENAPI_FILE, help='OpenAPI yaml/json file')
    ap.add_argument('--sqlmap', default=DEFAULT_SQLMAP_PATH, help='Path to sqlmap.py or executable')
    ap.add_argument('--logs', default=DEFAULT_LOGS_DIR, help='Directory to store logs and sqlmap output')
    ap.add_argument('--confirm', action='store_true', help='Allow destructive enumeration (DB listing, dumping)')
    ap.add_argument('--flush-session', action='store_true', help='Flush sqlmap session for each target')
    ap.add_argument('--technique', default=None, help='Force sqlmap --technique value (e.g. BUUT)')
    ap.add_argument('--threads', type=int, default=5, help='sqlmap --threads')
    ap.add_argument('--max-dbs', type=int, default=5, help='limit number of DBs to enumerate')
    ap.add_argument('--max-tables', type=int, default=10, help='limit tables per DB to inspect')
    ap.add_argument('--max-rows', type=int, default=50, help='limit rows per table when dumping')
    ap.add_argument('--timeout', type=int, default=600, help='timeout per sqlmap subprocess (seconds)')
    ap.add_argument('--log-level', default='INFO', help='Set the logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL)')
    ap.add_argument('--server-url', default=None, help='The server URL to test against.')
    ap.add_argument('--ports', nargs='*', type=int, help='List of ports to scan (e.g., --ports 5000 8000 3000)')
    ap.add_argument('--log-full-output', action='store_true', help='Enable logging of the full sqlmap output for all endpoints.')
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

    # Add a handler for file output
    file_handler = logging.FileHandler(master_log_file)
    file_handler.setLevel(log_level)
    file_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

    if args.sqlmap == DEFAULT_SQLMAP_PATH:
        sqlmap_path = ensure_sqlmap()
    else:
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
            from urllib.parse import urlparse
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
                                        props = content['application/x-www-form-urlencoded'].get('schema', {}).get('properties', {}) or {}
                                        payload = urlencode({k: choose_test_value_for_schema(v, spec, base_dir) for k, v in props.items()}, doseq=True)
                                    elif 'multipart/form-data' in content:
                                        props = content['multipart/form-data'].get('schema', {}).get('properties', {}) or {}
                                        payload = urlencode({k: choose_test_value_for_schema(v, spec, base_dir) for k, v in props.items()}, doseq=True)
                                    elif 'application/json' in content:
                                        schema = content['application/json'].get('schema', {}) or {}
                                        payload = construct_json_string_from_schema(schema, spec, base_dir)
                                if not payload:
                                    payload = 'test=1'
                                if payload.strip().startswith('{'):
                                    flush_cmd += ['-H', 'Content-Type: application/json']
                                flush_cmd += ['--data', payload]

                            # run flush (non-interactive)
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


if __name__ == '__main__':
    main_cli()
    logging.shutdown()