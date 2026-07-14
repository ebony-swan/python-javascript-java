# Vulnerability Catalog & Likelihood Analysis

This directory documents every vulnerability in the lab, in all three languages,
and rates each one along **two independent axes**:

1. **Exploitation likelihood** — *if the code is reachable, how likely is an
   attacker to succeed?*
2. **Prevalence today** — *how often does this exact pattern still appear in
   real production code in 2026?* — rated separately for **greenfield / modern**
   teams and teams carrying **~10‑year‑old technical debt**.

Keeping these two axes separate matters. A pattern can be **trivial to exploit
but rare in modern code** (e.g. `eval()`-based deserialization), or **only
moderately exploitable yet extremely common** (e.g. a dynamic SQL `ORDER BY`
clause, which every ORM leaves you to hand-roll). Risk is where the two axes
meet.

## Per-category documents

| Category | Doc | OWASP 2021 → 2025 |
|----------|-----|-------------------|
| Injection (SQLi, Command, XSS) | [`01-injection.md`](01-injection.md) | A03 → A05 |
| Broken Access Control | [`02-broken-access-control.md`](02-broken-access-control.md) | A01 → A01 |
| Cryptographic Failures | [`03-cryptographic-failures.md`](03-cryptographic-failures.md) | A02 → A04 |
| Insecure Deserialization | [`04-insecure-deserialization.md`](04-insecure-deserialization.md) | A08 → A08 |
| Server-Side Request Forgery | [`05-ssrf.md`](05-ssrf.md) | A10 → A01 (folded) |
| Path Traversal | [`06-path-traversal.md`](06-path-traversal.md) | A01 / A05 |
| OWASP 2021 ↔ 2025 mapping | [`owasp-mapping.md`](owasp-mapping.md) | — |

---

## How to read an in-code annotation

Every vulnerable handler in every app carries a header block in this shape
(comment syntax varies by language):

```
PERMUTATION 2 — SQL injection via f-string interpolation (UNION data theft)
OWASP 2021: A03 Injection      OWASP 2025: A05 Injection
CWE-89: Improper Neutralization of Special Elements used in an SQL Command
EXPLOITATION LIKELIHOOD: HIGH — a UNION SELECT dumps hashes/SSNs, no auth, no tooling
PREVALENCE TODAY: greenfield MEDIUM (raw SQL persists in search/reporting) | legacy HIGH
EXAMPLE: GET /injection/sql/search?q=zzz' UNION SELECT username, password, ssn FROM users--
FIX: parameterize the WHERE clause
```

The docs in this folder aggregate those annotations into per-category tables and
add cross-language commentary.

---

## Rubric 1 — Exploitation likelihood

*How likely is a motivated attacker to exploit the flaw, assuming they can reach
the endpoint?* This blends five factors:

| Factor | Raises likelihood | Lowers likelihood |
|--------|-------------------|-------------------|
| **Authentication** | Reachable pre-auth | Requires a privileged session |
| **Skill / tooling** | Copy-paste payload | Custom gadget chain, deep protocol knowledge |
| **Reliability** | Deterministic, one request | Race, timing, or environment-dependent |
| **Interaction** | No victim needed | Needs a victim to click / act (e.g. reflected XSS) |
| **Impact** | RCE / auth bypass / full data theft | Minor info leak |

| Rating | Meaning |
|--------|---------|
| **CRITICAL** | Pre-auth, trivial, deterministic, and high impact — typically unauthenticated RCE or a full authentication bypass in a single request. |
| **HIGH** | Easily exploited with well-known payloads and high reliability. May require a valid session or a victim click, but no exotic skill. |
| **MEDIUM** | Exploitable, but gated by a condition: blind/oracle extraction, a known gadget in the classpath, a specific config, or meaningful attacker effort. |
| **LOW** | Narrow preconditions or low impact; exploitable in principle but rarely worth it. |

> These ratings describe the flaw **in isolation, as written**. Real-world risk
> also depends on exposure (is the endpoint internet-facing?), compensating
> controls (WAF, network segmentation), and data sensitivity — all out of scope
> for a single code sample.

---

## Rubric 2 — Prevalence today (modern vs. legacy)

*How often is this pattern still written or still running in 2026?* We rate two
archetypes separately because the answer is usually different for each:

- **Greenfield / modern** — a new codebase on current frameworks with
  safe-by-default behavior: ORMs that parameterize (JPA/Hibernate, SQLAlchemy,
  Prisma), templating that auto-escapes (Thymeleaf, Jinja2, React), managed
  crypto, JSON-first APIs, dependency scanning in CI.
- **Legacy / ~10‑year technical debt** — a codebase begun around 2013–2016:
  hand-built SQL strings, home-grown crypto, native serialization for sessions
  or RMI, string-concatenated shell calls, deprecated APIs still in production
  because "it works and nobody wants to touch it."

| Rating | Meaning |
|--------|---------|
| **HIGH** | You should expect to find this pattern in a codebase of this archetype. |
| **MEDIUM** | Common enough to encounter regularly, but not the default. |
| **LOW** | Occurs, but usually only in a neglected corner or by mistake. |
| **RARE** | The framework/ecosystem actively prevents it; seeing it is a red flag. |

### Why the two archetypes diverge — the reasoning we applied

- **Safe-by-default frameworks erase whole classes.** Modern ORMs parameterize,
  modern template engines auto-escape, modern crypto libraries pick the mode for
  you. So "classic" SQLi-by-concatenation and stored XSS drop toward **LOW/RARE**
  in greenfield code but stay **HIGH** in legacy code written before those
  defaults existed.
- **Some flaws frameworks *don't* prevent stay common everywhere.** IDOR, mass
  assignment, SSRF-by-URL-fetch, dynamic `ORDER BY`, and prototype pollution are
  design/authorization problems the framework can't fix for you, so they remain
  **MEDIUM–HIGH** even in brand-new code.
- **Deserialization is bimodal.** Native Java/Python deserialization is **RARE**
  in JSON-first greenfield apps but **HIGH** in decade-old code that serialized
  sessions or used RMI/Java EE.
- **New tech introduces *new* instances of old bugs.** Microservices multiply
  SSRF surface; NoSQL brings its own injection; and LLM-generated code frequently
  reintroduces string-concatenated SQL and shell calls — nudging some "legacy"
  patterns back up in otherwise-modern shops.

The per-category documents apply this reasoning permutation by permutation.
