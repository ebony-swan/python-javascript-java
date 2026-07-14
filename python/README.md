# Python VulnApp (Flask)

Deliberately vulnerable Flask app — one of three parallel implementations in
this lab (see the [repo README](../README.md)). For security education only;
never expose to an untrusted network.

## Requirements
- Python 3.11+

## Run
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python run.py
```
Then open **http://127.0.0.1:5000/** — the index lists every registered endpoint.

The SQLite database (`app/vulnapp.db`) is dropped and re-seeded on every startup,
so the demo is always deterministic. Seeded users: `alice`, `bob` (role `user`)
and `admin` (role `admin`); notes `id=2` and `id=4` are private.

## How it's organized
- `run.py` — entry point.
- `app/__init__.py` — application factory; **auto-registers** any module in
  `app/vulns/` that defines a `bp` (Blueprint). No central wiring to edit.
- `app/db.py`, `app/schema.sql` — shared schema + seed data.
- `app/vulns/` — one module per OWASP category; multiple annotated permutations
  each:

| Module | Category | Prefix |
|--------|----------|--------|
| `injection_sql.py` | SQL Injection | `/injection/sql` |
| `injection_command.py` | Command Injection | `/injection/command` |
| `injection_xss.py` | Cross-Site Scripting | `/injection/xss` |
| `access_control.py` | Broken Access Control | `/access` |
| `crypto.py` | Cryptographic Failures | `/crypto` |
| `deserialization.py` | Insecure Deserialization | `/deserialization` |
| `ssrf.py` | Server-Side Request Forgery | `/ssrf` |
| `path_traversal.py` | Path Traversal | `/path` |

## Try it
```bash
# SQL injection auth bypass
curl "http://127.0.0.1:5000/injection/sql/login?username=admin'--&password=x"
# Reflected XSS
curl "http://127.0.0.1:5000/injection/xss/hello?name=<script>alert(1)</script>"
```
See [`../docs/`](../docs/README.md) for the full catalog with likelihood ratings.
