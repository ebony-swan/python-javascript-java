# C# VulnApp (ASP.NET Core)

Deliberately vulnerable ASP.NET Core app — one of six parallel implementations in
this lab (see the [repo README](../README.md)). For security education only;
never expose to an untrusted network.

## Requirements
- .NET SDK 9

## Run
```bash
dotnet run
```
Then open **http://127.0.0.1:5001/** — the index lists every registered endpoint.

Uses a shared **in-memory SQLite** (`Microsoft.Data.Sqlite`), seeded on startup.
Seeded users: `alice`, `bob` (role `user`) and `admin` (role `admin`); notes
`id=2` and `id=4` are private.

> **Intentionally vulnerable dependency usage:** `Newtonsoft.Json` is pinned and
> used with `TypeNameHandling.All` on purpose to back the deserialization demo.

## How it's organized
- `Program.cs` — entry point; `MapControllers()` **auto-discovers** the
  attribute-routed controllers.
- `Db.cs` — shared schema/seed + helpers (`Db.Query`, `Db.Md5`).
- `Controllers/` — one `[ApiController]` per OWASP category:
  `SqlInjectionController`, `CommandInjectionController`, `XssController`,
  `AccessControlController`, `CryptoController`, `DeserializationController`,
  `SsrfController`, `PathTraversalController`.

## Try it
```bash
curl "http://127.0.0.1:5001/injection/sql/login?username=admin'--&password=x"
```
See [`../docs/`](../docs/README.md) for the full catalog with likelihood ratings.
