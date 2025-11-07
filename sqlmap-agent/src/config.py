"""
Configuration management and CLI argument parsing
"""

import json
import os

# Load configuration from config.json
try:
    with open('../config.json', 'r') as f:
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


def setup_cli_parser():
    """Set up the command line argument parser"""
    import argparse

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
    ap.add_argument('--include-pattern', help='Regex pattern to include only matching endpoints (e.g., "/api/users.*")')
    ap.add_argument('--exclude-pattern', help='Regex pattern to exclude matching endpoints (e.g., "/health.*")')
    ap.add_argument('--concurrency', type=int, default=1, help='Number of endpoints to scan concurrently (default: 1)')
    ap.add_argument('--log-full-output', action='store_true', help='Enable logging of the full sqlmap output for all endpoints.')

    return ap
