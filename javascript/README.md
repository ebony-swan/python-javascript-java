# JavaScript VulnApp (Express)

Deliberately vulnerable Express app — one of three parallel implementations in
this lab (see the [repo README](../README.md)). For security education only;
never expose to an untrusted network.

## Requirements
- **Node.js ≥ 22.5** (uses the built-in `node:sqlite`, so there is no native
  build step).

## Run
```bash
npm install
npm start
```
Then open **http://127.0.0.1:3000/** — the index lists every registered endpoint.

The in-memory SQLite database is re-seeded on every startup. Seeded users:
`alice`, `bob` (role `user`) and `admin` (role `admin`); notes `id=2` and `id=4`
are private.

> **Intentionally vulnerable dependencies:** `node-serialize@0.0.4` and
> `lodash@4.17.11` are pinned on purpose to back the deserialization /
> prototype-pollution demos. Expect SCA tools to flag them.

## How it's organized
- `server.js` — entry point; **auto-mounts** any file in `routes/` that exports
  `{ base, router }`. No central wiring to edit.
- `db.js` — shared schema + seed data (`node:sqlite`).
- `routes/` — one module per OWASP category; multiple annotated permutations
  each:

| Module | Category | Prefix |
|--------|----------|--------|
| `injection_sql.js` | SQL Injection | `/injection/sql` |
| `injection_command.js` | Command Injection | `/injection/command` |
| `injection_xss.js` | Cross-Site Scripting | `/injection/xss` |
| `access_control.js` | Broken Access Control | `/access` |
| `crypto.js` | Cryptographic Failures | `/crypto` |
| `deserialization.js` | Insecure Deserialization | `/deserialization` |
| `ssrf.js` | Server-Side Request Forgery | `/ssrf` |
| `path_traversal.js` | Path Traversal | `/path` |

## Try it
```bash
# SQL injection auth bypass
curl "http://127.0.0.1:3000/injection/sql/login?username=admin'--&password=x"
# Reflected XSS
curl "http://127.0.0.1:3000/injection/xss/hello?name=<script>alert(1)</script>"
```
See [`../docs/`](../docs/README.md) for the full catalog with likelihood ratings.
