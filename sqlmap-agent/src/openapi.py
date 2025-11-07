"""
OpenAPI specification parsing and utilities
"""

import yaml
import re
from urllib.parse import quote_plus
from pathlib import Path

from .config import DEFAULT_TEST_VALUE


def load_openapi(path):
    """Load and parse OpenAPI specification"""
    path = Path(path)
    with open(path, 'r', encoding='utf-8') as f:
        spec = yaml.safe_load(f)
    return spec, path.parent


def resolve_ref(ref, spec, base_dir):
    """Resolve $ref in OpenAPI spec"""
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
    """Collect all parameters for an operation"""
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
    """Choose appropriate test value for schema"""
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
    """Build parameter value from schema"""
    if 'schema' in param:
        return choose_test_value_for_schema(param['schema'], spec, base_dir)
    return DEFAULT_TEST_VALUE.get('string', 'test')


def substitute_path_params(path, params, spec, base_dir):
    """Substitute path parameters in URL"""
    def repl(match):
        name = match.group(1)
        for p in params:
            if p.get('name') == name and p.get('in') == 'path':
                v = build_param_value(p, spec, base_dir)
                return quote_plus(str(v))
        return '1'
    return re.sub(r'\\{([^/}]+)\\}', repl, path)


def security_headers_and_params(operation, spec):
    """Extract security headers and parameters"""
    from .config import ENV_BEARER, ENV_APIKEY, ENV_BASIC_USER, ENV_BASIC_PASS
    import base64

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
    """Construct JSON string from schema"""
    import json
    val = choose_test_value_for_schema(schema, spec, base_dir)
    try:
        return json.dumps(val)
    except Exception:
        return json.dumps({"test": "test"})
