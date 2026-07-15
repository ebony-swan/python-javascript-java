# Go VulnApp (net/http)

Deliberately vulnerable Go app — one of six parallel implementations in this lab
(see the [repo README](../README.md)). For security education only; never expose
to an untrusted network.

## Requirements
- Go ≥ 1.22 (uses the Go 1.22 `ServeMux` method+pattern routing).

## Run
```bash
go run .
```
Then open **http://127.0.0.1:8081/** — the index lists every registered endpoint.

Uses a shared **in-memory SQLite** (pure-Go `modernc.org/sqlite`, no cgo),
re-seeded on startup. Seeded users: `alice`, `bob` (role `user`) and `admin`
(role `admin`); notes `id=2` and `id=4` are private.

## How it's organized
- `main.go` — entry point; mounts everything from the route registry.
- `registry.go` — modules call `register("METHOD /path", desc, handler)` from
  their `init()`, so they're **auto-discovered** with no central wiring to edit.
- `db.go`, `util.go` — shared schema/seed and helpers (`writeJSON`,
  `queryToMaps`, `md5hex`).
- One `*.go` file per OWASP category (all in `package main`): `injection_sql.go`,
  `injection_command.go`, `injection_xss.go`, `access_control.go`, `crypto.go`,
  `deserialization.go`, `ssrf.go`, `path_traversal.go`.

## Try it
```bash
curl "http://127.0.0.1:8081/injection/sql/login?username=admin'--&password=x"
```

> **A note on Go and deserialization:** Go is memory-safe and lacks a
> pickle/`ObjectInputStream`-style gadget mechanism, so its deserialization
> permutations are genuinely *lower severity* than the other languages'. The
> annotations rate this honestly rather than inventing an RCE.

See [`../docs/`](../docs/README.md) for the full catalog with likelihood ratings.
