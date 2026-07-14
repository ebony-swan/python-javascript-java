# Multi-Language OWASP Top 10 Vulnerability Lab

> ⚠️ **This repository contains intentional, working security vulnerabilities.**
> It exists for security education, secure-code training, and demonstrating
> SAST/SCA/DAST tooling. **Never deploy it, never expose it to an untrusted
> network, and never run it against data you care about.** Run it only on
> `127.0.0.1`, ideally inside a throwaway container/VM.

Inspired by [OWASP NodeGoat](https://github.com/OWASP/NodeGoat), this project
takes the same idea — a deliberately vulnerable app you can exploit and then
learn to fix — and does three things differently:

1. **Three languages, one lab.** The *same* OWASP categories are implemented in
   **Java** (Spring Boot), **JavaScript** (Express), and **Python** (Flask), so
   you can compare how each flaw looks — and how each ecosystem's defaults help
   or hurt — side by side.
2. **Multiple permutations per vulnerability.** Each category ships several
   *variations* of the same weakness (e.g. SQL injection via concatenation, via
   string-formatting, and via a dynamic `ORDER BY`), not just one canonical
   example.
3. **Everything on one branch.** Unlike NodeGoat's approach of scattering
   variations across branches, every language, category, and permutation lives
   together on a single branch for easy scanning and study.

Every vulnerable handler carries an inline annotation block rating **two kinds
of likelihood** (see [`docs/`](docs/README.md)):

- **Exploitation likelihood** — how easily an attacker could exploit it.
- **Prevalence today** — how commonly the pattern still appears in real code,
  rated separately for **modern/greenfield** teams vs. teams carrying
  **~10‑year‑old technical debt**.

---

## Repository layout

```
.
├── java/          Spring Boot 3 app (Java 21, Maven, H2)      -> http://127.0.0.1:8080/
├── javascript/    Express app (Node 22, node:sqlite)          -> http://127.0.0.1:3000/
├── python/        Flask app (Python 3.11, sqlite3)            -> http://127.0.0.1:5000/
└── docs/          Vulnerability catalog + likelihood analysis + OWASP 2021↔2025 mapping
```

Each app auto-discovers its vulnerability modules and serves an **index of every
endpoint** at `/`, so once it's running you can see the whole attack surface at
a glance.

## Vulnerability coverage (the "core code-level" set)

All six categories are implemented in **all three languages** with multiple
permutations each.

| # | Category | OWASP 2021 → 2025 | Permutations |
|---|----------|-------------------|--------------|
| 1 | **Injection** | A03 → A05 | SQLi (concat · format · dynamic `ORDER BY`), Command (shell concat · 2nd shell tool · argument injection), XSS (reflected · stored · DOM · unescaped-template/context) |
| 2 | **Broken Access Control** | A01 → A01 | IDOR · missing function-level authz · mass assignment · client-controlled role |
| 3 | **Cryptographic Failures** | A02 → A04 | weak hash · hard-coded secret · weak cipher/ECB · insecure randomness |
| 4 | **Insecure Deserialization** | A08 → A08 | native (pickle / `node-serialize` / `ObjectInputStream`) · unsafe config format (YAML / `eval`) · integrity-specific (`eval` / prototype pollution / `XMLDecoder`) |
| 5 | **SSRF** | A10 → A01 (folded) | fetch user URL · internal/metadata webhook · blocklist bypass |
| 6 | **Path Traversal** | A01 / A05 | file read (`../`) · file download concat · Zip Slip (arbitrary write) |

See [`docs/README.md`](docs/README.md) for the full catalog with per-permutation
likelihood ratings and remediation, and
[`docs/owasp-mapping.md`](docs/owasp-mapping.md) for the complete 2021→2025
category shift.

**Benchmarking a scanner against this lab?** See
[`docs/expected-scan-results.md`](docs/expected-scan-results.md) — the
ground-truth answer key: **86 intentional findings (23 Critical / 45 High /
18 Medium / 0 Low)** scored with CVSS v3.1 (81 SAST + 5 SCA), plus the 24 safe
reference handlers a good tool must *not* flag.

## Running the apps

Each app is standalone. Full instructions live in each app's `README.md`.

**Python (Flask)** — http://127.0.0.1:5000/
```bash
cd python
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python run.py
```

**JavaScript (Express)** — http://127.0.0.1:3000/  (requires Node ≥ 22.5)
```bash
cd javascript
npm install
npm start
```

**Java (Spring Boot)** — http://127.0.0.1:8080/  (requires JDK 21)
```bash
cd java
mvn spring-boot:run
```

## A note on the intentionally vulnerable dependencies

The JavaScript app pins a couple of deliberately old, vulnerable libraries
(`node-serialize@0.0.4`, `lodash@4.17.11`) because they are integral to the
deserialization / prototype-pollution demos. These will (correctly) light up a
Software Composition Analysis (SCA) scan — that's expected.

## Ethics & scope

Use this only where you are authorized to: your own machine, a training lab, or
a sanctioned exercise. The payloads here are real; running them anywhere you
don't own or control may be illegal.
