# PHP VulnApp

> **🚧 Work in progress.** This app is intentionally incomplete: **SQL injection**
> and **command injection** are implemented; the remaining categories (XSS, broken
> access control, cryptographic failures, insecure deserialization, SSRF, path
> traversal) are **slated for a later build**. Until then, PHP is excluded from
> the benchmark engine's scoring (see `benchmark/baseline.json → deferred_languages`).

Deliberately vulnerable PHP app — companion to the five complete apps in this lab
(see the [repo README](../README.md)). For security education only; never expose
to an untrusted network.

## Requirements
- PHP 8 with the `pdo_sqlite`, `curl`, `openssl`, and `dom`/`SimpleXML`
  extensions (all default in most PHP 8 builds).

## Run
```bash
php -S 127.0.0.1:8082 index.php
```
Then open **http://127.0.0.1:8082/** — the index lists every registered endpoint.

Uses a **file-backed SQLite** database (`data/vulnapp.db`), seeded on first run.
(PHP's built-in server is shared-nothing, so a file — not in-memory — lets stored
data such as the stored-XSS comments persist across requests.) Seeded users:
`alice`, `bob` (role `user`) and `admin` (role `admin`); notes `id=2` and `id=4`
are private. Delete `data/vulnapp.db` to reset.

## How it's organized
- `index.php` — front controller; **auto-loads** every file in `vulns/` and
  dispatches by method + path.
- `lib.php` — `route()` registry, `get_db()`, `json_response()`, seed data.
- `vulns/` — one file per OWASP category. Implemented so far:
  `injection_sql.php` ✅ and `injection_command.php` ✅. Planned for the later
  build: `injection_xss.php`, `access_control.php`, `crypto.php`,
  `deserialization.php`, `ssrf.php`, `path_traversal.php`.

## Try it
```bash
curl "http://127.0.0.1:8082/injection/sql/login?username=admin'--&password=x"
```
See [`../docs/`](../docs/README.md) for the full catalog with likelihood ratings.
