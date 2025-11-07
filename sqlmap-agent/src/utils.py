"""
General utility functions
"""

import re
import shlex
import sys
from pathlib import Path


def shell_join(cmd_list):
    """Join command list into shell-compatible string"""
    try:
        return shlex.join(cmd_list)
    except Exception:
        return ' '.join(shlex.quote(x) for x in cmd_list)


def safe_summary_to_filename(summary):
    """Convert summary to safe filename"""
    safe = re.sub(r'[^A-Za-z0-9_.-]', '_', (summary or 'endpoint'))
    return safe[:200]


def ensure_dir(p):
    """Ensure directory exists"""
    Path(p).mkdir(parents=True, exist_ok=True)


def extract_db_names(text):
    """Extract database names from sqlmap output"""
    dbs = set()
    for m in re.finditer(r'Database: (.+)\n', text):
        dbs.add(m.group(1).strip())
    for m in re.finditer(r'Databases: (.+)\n', text):
        parts = m.group(1).split(',')
        for p in parts:
            dbs.add(p.strip())
    return list(dbs)


def detected_injection_in_output(text):
    """Check if sqlmap output indicates injection was detected"""
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
