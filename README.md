# Sqlmap OpenAPI Agent

This repository contains a Python script (`sqlmap-agent/agent.py`) that reads an OpenAPI (Swagger) specification and automatically builds `sqlmap` commands to test each endpoint for SQL injection. It performs a *two-stage* process: a safer discovery scan by default, and optional conditional enumeration (listing databases, tables, dumping rows) when explicitly allowed.

> **Important — legal & safety**: Only run this tool against systems you **own** or are **explicitly authorized** to test. The author assumes no liability for misuse. Use the `--confirm` flag only when you have written permission to enumerate and dump database contents.

---

## Contents

* `sqlmap-agent/agent.py` — main script.
* `sqlmap-agent/config.json` — configuration file for default settings.
* `vulnerable-app/` — sample vulnerable application with OpenAPI spec and Docker setup.
* `attack-logs-dynamic/` — default logs directory created by the script (after running).

---

# Features

* Reads OpenAPI v2/v3 YAML or JSON and builds requests for each path/method.
* Safer **discovery** stage (non-heavy techniques) by default to find likely injection points.
* Optional **enumeration** (DB listing, table listing, dumping) behind `--confirm` flag.
* Supports common auth schemes from OpenAPI: Bearer, API Key, Basic (via env vars).
* Respects content types: `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`.
* Writes per-endpoint logs and sqlmap `--output-dir` artifacts.
* Configurable limits for enumeration (max DBs/tables/rows) and timeouts.
* Optionally flushes sqlmap session per target.

---

# Prerequisites

1. **Python 3.8+**

```bash
python --version
```

2. **sqlmap**

* The script automatically clones and uses sqlmap from GitHub if not present. Alternatively, specify a custom path via `--sqlmap`.

3. **OpenAPI file**

    * A valid OpenAPI/Swagger YAML or JSON file. Default path is configurable in `config.json` (initially `../vulnerable-app/openapi.yaml`).

4. **(Optional) Authentication environment variables**

   * `API_BEARER_TOKEN` — used for `bearer` HTTP auth.
   * `API_KEY` — used for `apiKey` security schemes.
   * `API_BASIC_USER`, `API_BASIC_PASS` — used for `basic` HTTP auth.

5. **Permission / legal authorization** — get written permission before enumeration.

---

# Installation

Clone this repository:

```bash
git clone https://github.com/disruptiq/sql-injection-agent.git
cd sql-injection-agent-from-openapi-spec
```

Install dependencies (pyyaml for YAML parsing):

```bash
pip install pyyaml
```

The script will automatically clone sqlmap if not present.

---

# Quick start

1. Navigate to the sqlmap-agent directory:

```bash
cd sqlmap-agent
```

2. Run a discovery scan (safe default):

```bash
python agent.py
```

By default this will look for the OpenAPI file specified in `config.json` (initially `../vulnerable-app/openapi.yaml`), auto-clone sqlmap if needed, and write logs to the directory specified in `config.json` (initially `attack-logs-dynamic/`).

---

# Usage & Modes

Run `python agent.py --help` for full CLI help. Below are common modes and examples.

## 1) Discovery-only (default, safe)

Scans each endpoint using non-heavy techniques (`--technique BU` by default) and writes logs. It *does not* list or dump DB contents.

```bash
python agent.py --openapi path/to/openapi.yaml --sqlmap /path/to/sqlmap.py --logs ./logs_discovery
```

## 2) Discovery + enumeration (DB listing / table dumping)

Add `--confirm` to permit listing databases/tables and dumping rows when an injection is detected.

```bash
python agent.py --openapi path/to/openapi.yaml --sqlmap /path/to/sqlmap.py --logs ./logs_full --confirm
```

**Caution:** enumeration is destructive and may be slow. Use only with explicit permission.

## 3) Force specific sqlmap techniques

Override techniques string (sqlmap syntax) with `--technique` (e.g. `BU`, `U`, `T`).

```bash
python agent.py --technique BU --confirm
```

> Note: `T` (time-based) can be heavy and may cause server slowdowns or 500 errors.

## 4) Increase concurrency

Adjust sqlmap threads with `--threads` (default 5):

```bash
python agent.py --threads 10
```

## 5) Flush sqlmap session between targets

Avoid reusing previous session state:

```bash
python agent.py --flush-session
```

## 6) Limit dumping scope

Control enumeration scope to avoid huge data dumps:

```bash
python agent.py --confirm --max-dbs 3 --max-tables 5 --max-rows 20
```

## 7) Per-process timeout

Kill sqlmap child processes after N seconds (default 300s):

```bash
python agent.py --timeout 120
```

## 8) Use system sqlmap binary

If `sqlmap` is installed on PATH or you have a binary, point `--sqlmap` to it:

```bash
python agent.py --sqlmap /usr/local/bin/sqlmap
```

## 9) Narrow scan to one endpoint

The script scans all paths in the OpenAPI file. To scan a single endpoint:

* Create a small OpenAPI file with only the path you want and pass `--openapi small.yaml`, or
* Manually run the printed sqlmap command (the script prints executed commands).

## 10) Dry-run / debug

To only see the built commands (without executing), either:

* Inspect the printed `[ * ] Exec:` lines while running, or
* Edit the `run_sqlmap` function in the script to skip `Popen` and just `print` commands.

---

# CLI Arguments (summary)

* `--openapi` — path to OpenAPI YAML/JSON (default `../vulnerable-app/openapi.yaml`).
* `--sqlmap` — path to `sqlmap.py` or `sqlmap` executable.
* `--logs` — directory where logs and sqlmap output will be saved (default `attack-logs-dynamic`).
* `--confirm` — allow destructive enumeration (DB listing, dumping).
* `--flush-session` — flush sqlmap session per target.
* `--technique` — force sqlmap `--technique` value (e.g. `BU`, `U`, `T`).
* `--threads` — number of sqlmap threads (default 5).
* `--max-dbs` — max DBs to enumerate (default 5).
* `--max-tables` — max tables per DB to enumerate (default 10).
* `--max-rows` — max rows per table when dumping (default 50).
* `--timeout` — per-sqlmap subprocess timeout in seconds (default 300).

Run `python agent.py --help` for complete details.

---

# Output & Logs

* Each endpoint produces a safe filename under `--logs` (e.g. `logs/endpoint_name.log`) and a `*_summary.txt` file with the first portion of sqlmap output.
* When enumeration runs, sqlmap's `--output-dir` is set to a subfolder so sqlmap artifacts (dumps, sessions) are stored in a dedicated location per endpoint.

---

# Troubleshooting

* `sqlmap executable not found` — ensure `--sqlmap` points to a valid file or `sqlmap` is on PATH.
* Permission errors writing logs — ensure the user can write to the specified `--logs` directory.
* No injection found but expected — try increasing `--level`/`--risk` or add `T` (time) to `--technique` (careful).
* Server returns 500 during test — lower `--risk`/`--level`, avoid `T` (timing), or run against a staging instance.

---

# Extending the script

Ideas for future improvements:

* Add `--endpoint-filter` (regex) to target specific paths.
* Use sqlmap's JSON output (if available) for more robust parsing instead of heuristics.
* Add a mode that aggregates a CSV/summary of all findings.
* Add concurrency to scan multiple endpoints in parallel (careful with resource usage).

---

# Example full command (Windows)

```bash
python agent.py --openapi ..\\vulnerable-app\\openapi.yaml --sqlmap ..\\sqlmap-dev\\sqlmap.py --logs .\\attack_logs_run --confirm --threads 8 --max-dbs 4 --timeout 600
```

---

# Final notes

* This tool is designed to help security assessors automate repetitive sqlmap command construction from an OpenAPI spec. It trades absolute exhaustiveness for safety-by-default. Adjust flags carefully when you need deeper enumeration.