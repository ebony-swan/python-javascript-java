# Java VulnApp (Spring Boot)

Deliberately vulnerable Spring Boot app — one of three parallel implementations
in this lab (see the [repo README](../README.md)). For security education only;
never expose to an untrusted network.

## Requirements
- **JDK 21**
- Maven (or use the system `mvn`)

## Run
```bash
mvn spring-boot:run
```
Then open **http://127.0.0.1:8080/** — the index lists every registered endpoint.

Uses an in-memory **H2** database, re-created from `schema.sql` + `data.sql` on
every startup. Seeded users: `alice`, `bob` (role `user`) and `admin` (role
`admin`); notes `id=2` and `id=4` are private. (Note: H2 returns column names
UPPERCASED, so JSON keys look like `USERNAME`.)

## How it's organized
- `VulnAppApplication.java` — Spring Boot entry point.
- `IndexController.java` — renders the endpoint index at `/`.
- `com.example.vulnapp.vulns.*` — one `@RestController`/`@Controller` per OWASP
  category, discovered automatically by component scan. Multiple annotated
  permutations each:

| Class | Category | Prefix |
|-------|----------|--------|
| `SqlInjectionController` | SQL Injection | `/injection/sql` |
| `CommandInjectionController` | Command Injection | `/injection/command` |
| `XssController` | Cross-Site Scripting | `/injection/xss` |
| `AccessControlController` | Broken Access Control | `/access` |
| `CryptoController` | Cryptographic Failures | `/crypto` |
| `DeserializationController` | Insecure Deserialization | `/deserialization` |
| `SsrfController` | Server-Side Request Forgery | `/ssrf` |
| `PathTraversalController` | Path Traversal | `/path` |

## Try it
```bash
# SQL injection auth bypass
curl "http://127.0.0.1:8080/injection/sql/login?username=admin'--&password=x"
# Reflected XSS
curl "http://127.0.0.1:8080/injection/xss/hello?name=<script>alert(1)</script>"
```
See [`../docs/`](../docs/README.md) for the full catalog with likelihood ratings.
