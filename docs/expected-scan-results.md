# Expected Scan Results (Ground-Truth Baseline)

This is the **answer key** for the lab: what an *ideal* SaaS security scan
(SAST + SCA) should report when run against this repository — total findings and
the breakdown by **CVSS v3.1** severity. Use it to benchmark a scanner's
**recall** (did it find them all?) and **precision** (did it avoid flagging the
safe code?).

## Headline numbers

| | Findings | Critical | High | Medium | Low |
|---|---:|---:|---:|---:|---:|
| **Code-level (SAST)** | **135** | 32 | 72 | 31 | 0 |
| **Dependencies (SCA)** | **5** | 2 | 2 | 1 | 0 |
| **TOTAL** | **140** | **34** | **74** | **32** | **0** |

Covers the **five complete languages** (Python, JavaScript, Java, Go, C#) at 27
planted vulnerabilities each. The **PHP** app is a work in progress and is
intentionally excluded from scoring until it is complete.

Plus a small, tool-dependent tail of **app-level / hardening findings** (~5,
mostly Low–Medium) described at the end. The **140** above is the crisp,
intentional true-positive set.

> **Why zero Low?** Every planted flaw is a genuine, exploitable weakness
> (Medium or above). The only "Low" a scanner should surface here is
> informational hardening (verbose errors, missing headers, debug mode), and how
> many of those a tool emits varies — so they are listed separately rather than
> in the headline.

---

## How to read these scores (caveats)

- **CVSS v3.1 was designed to score specific known vulnerabilities (CVEs).**
  SAST findings don't have CVEs, so each code-level finding is mapped to a
  **representative CVSS v3.1 base score** using a consistent rubric: the app is
  network-reachable and has **no authentication**, so most findings are
  `AV:N / PR:N`. Real tools emit their own severities (or CWE/OWASP mappings);
  treat these as a calibrated approximation, not gospel.
- **Counting unit = one distinct vulnerability**, not one endpoint or one
  data-flow path. E.g. stored XSS spans two endpoints (`POST /comment` +
  `GET /comments`) but is **one** finding. Tools that count per-sink or
  per-tainted-path may report more.
- **SCA depends on the feed.** `node-serialize@0.0.4` and `lodash@4.17.11` are
  the *intentional* vulnerable dependencies. A scanner may also surface drifting
  transitive advisories (Express sub-deps, H2, etc.); those are not counted here.

**CVSS v3.1 severity bands:** Critical 9.0–10.0 · High 7.0–8.9 · Medium 4.0–6.9
· Low 0.1–3.9.

---

## Code-level findings (SAST) — 27 per language

Each language implements the same 27 vulnerabilities. Severities are identical
across languages **except** the two rows flagged below, where the idiomatic sink
changes the impact.

| # | Category / Permutation | CWE | CVSS | Severity |
|---|------------------------|-----|-----:|----------|
| 1 | SQLi — auth bypass (string concat) | CWE-89 | 9.8 | Critical |
| 2 | SQLi — UNION data theft (interpolation) | CWE-89 | 9.8 | Critical |
| 3 | SQLi — blind, dynamic `ORDER BY` | CWE-89 | 7.5 | High |
| 4 | Command — shell concat (`ping`) | CWE-78 | 9.8 | Critical |
| 5 | Command — 2nd shell tool (`nslookup`/`host`) | CWE-78 | 9.8 | Critical |
| 6 | Command — argument injection (`tar`, no shell) | CWE-78 | 8.1 | High |
| 7 | XSS — reflected | CWE-79 | 6.1 | Medium |
| 8 | XSS — stored | CWE-79 | 6.1 | Medium |
| 9 | XSS — DOM-based | CWE-79 | 6.1 | Medium |
| 10 | XSS — unescaped template / context ⚠️ | CWE-79 / 1336 | 6.1 / **9.8** | Medium / **Critical (Python)** |
| 11 | Access — IDOR (note by id) | CWE-639 | 7.5 | High |
| 12 | Access — missing function-level authz | CWE-862 | 7.5 | High |
| 13 | Access — mass assignment (priv-esc) | CWE-915 | 8.8 | High |
| 14 | Access — client-controlled role | CWE-602 | 8.6 | High |
| 15 | Crypto — weak unsalted hash (MD5/SHA-1) | CWE-916 | 5.9 | Medium |
| 16 | Crypto — hard-coded secret / token key | CWE-798 | 7.5 | High |
| 17 | Crypto — weak cipher / ECB / static key | CWE-327 | 5.9 | Medium |
| 18 | Crypto — insecure randomness for tokens | CWE-338 | 7.5 | High |
| 19 | Deser — native (pickle / node-serialize / ObjectInputStream / `TypeNameHandling`) ⚠️ | CWE-502 | 9.8 | Critical / **Medium (Go)** |
| 20 | Deser — unsafe config format (YAML / `eval`) ⚠️ | CWE-502 / 95 / 94 | 9.8 | Critical / **High (Go template injection)** |
| 21 | Deser — integrity-specific ⚠️ | CWE-502 / 1321 | 9.8 / **8.1** | Critical / **High (JS proto-pollution)** / **Medium (Go type confusion)** |
| 22 | SSRF — fetch user URL | CWE-918 | 8.6 | High |
| 23 | SSRF — internal / metadata webhook | CWE-918 | 7.5 | High |
| 24 | SSRF — blocklist bypass | CWE-918 | 8.6 | High |
| 25 | Path — arbitrary file read (`../`) | CWE-22 | 7.5 | High |
| 26 | Path — download path concat | CWE-22 | 7.5 | High |
| 27 | Path — Zip Slip (arbitrary write) | CWE-22 | 8.8 | High |

⚠️ **Row 10 (XSS unescaped template):** Python renders user input as a Jinja
template → **Server-Side Template Injection → RCE (CVSS 9.8 Critical)**. Java
(`th:utext`), JavaScript and C# (HTML-attribute context), and Go
(`text/template`) are plain XSS (6.1 Medium).

⚠️ **Rows 19–21 (deserialization) — Go is the outlier.** Python, JavaScript,
Java and C# each carry three RCE-class deserialization sinks (9.8 Critical):
native (`pickle` / `node-serialize` / `ObjectInputStream` / Json.NET
`TypeNameHandling`), an unsafe config format (`yaml.unsafe_load` / SnakeYAML /
YamlDotNet / `eval`), and an integrity-specific sink (Python `eval()`, Java
`XMLDecoder`, C# type-controlled `XmlSerializer`). The two exceptions:

- **JavaScript row 21** is prototype pollution (CWE-1321, 8.1 High), not direct RCE.
- **Go rows 19–21** have no equivalent gadget chain at all — Go is memory-safe
  and its `encoding/*` decoders do not instantiate attacker-named types — so
  they are a decode issue (Medium), `text/template` injection (CWE-94, High),
  and type confusion (Medium).

Go's lower ratings are deliberate and rated honestly rather than inflated for
symmetry; they are why Go totals 4 Critical where the others total 6–8.

### Per-language tally

| Language | Total | Critical | High | Medium | Low |
|----------|------:|---------:|-----:|-------:|----:|
| **Python** | 27 | 8 | 14 | 5 | 0 |
| **Java** | 27 | 7 | 14 | 6 | 0 |
| **C#** | 27 | 7 | 14 | 6 | 0 |
| **JavaScript** | 27 | 6 | 15 | 6 | 0 |
| **Go** | 27 | 4 | 15 | 8 | 0 |
| **SAST total** | **135** | **32** | **72** | **31** | **0** |

*Every language plants the same 27 vulnerabilities; only the severity mix
differs, because the idiomatic sink differs.* Python leads on Criticals because
its template-injection (SSTI) and three RCE-class deserialization sinks all
reach code execution. C# matches Java exactly — Json.NET `TypeNameHandling`,
YamlDotNet, and a type-controlled `XmlSerializer` give it the same three
deserialization RCEs. JavaScript has one fewer Critical because its
integrity-specific deserialization is prototype pollution (High) rather than
direct RCE. **Go is the deliberate low end at 4 Critical**: it is memory-safe
and has no equivalent deserialization gadget chain, so all three of its deser
rows land Medium/High (see rows 19–21). A scanner that reports Go as
*less* vulnerable here is correct, not broken.

---

## Dependency findings (SCA) — 5

All in the JavaScript app, which pins two deliberately-outdated libraries. (The
deserialization flaws in the other four languages are **code-level, not
vulnerable dependencies** — `PyYAML 6.0.2`, `requests`, `SnakeYAML 2.x`,
`Newtonsoft.Json 13.0.3`, `YamlDotNet 16.2.0` and Go's stdlib decoders are all
current, patched versions used unsafely. That contrast is itself a teaching
point: SCA would find **nothing** in Python/Java/C#/Go here; the risk is
entirely in how the code calls them.)

| Package | Version | CVE | Type | CVSS | Severity |
|---------|---------|-----|------|-----:|----------|
| node-serialize | 0.0.4 | CVE-2017-5941 | RCE via `unserialize()` | 9.8 | Critical |
| lodash | 4.17.11 | CVE-2019-10744 | Prototype pollution (`defaultsDeep`) | 9.1 | Critical |
| lodash | 4.17.11 | CVE-2020-8203 | Prototype pollution | 7.4 | High |
| lodash | 4.17.11 | CVE-2021-23337 | Command injection via `template` | 7.2 | High |
| lodash | 4.17.11 | CVE-2020-28500 | ReDoS | 5.3 | Medium |

**SCA subtotal:** 5 findings — 2 Critical, 2 High, 1 Medium.

---

## The benchmark: precision & recall

An **ideal** scan is not just "find 140." It must also **not** raise false alarms:

- **Recall target — 140 / 140.** Missing any planted flaw is a false negative.
- **Precision target — 0 false positives**, specifically on the **control group**:
  every module ends with a clearly-labelled **SAFE reference handler**
  (parameterized query, escaped output, allow-listed path, `yaml.safe_load`,
  CSPRNG, etc.). There are **8 safe handlers per app across the five complete
  languages = 41 total** (the JavaScript crypto module contributes two) — the
  `*-safe` / `/safe` / `read-safe` endpoints. A tool that flags these is
  over-reporting.

| Metric | Ideal result |
|--------|--------------|
| True positives detected | 140 / 140 |
| False negatives | 0 |
| False positives (on the 41 safe handlers) | 0 |

---

## Beyond the 140: app-level / hardening findings (tool-dependent)

A thorough scanner will legitimately add a handful more, mostly **Low–Medium**.
These are excluded from the headline because their count varies a lot by tool and
ruleset:

| Finding | Where | CWE | Typical severity |
|---------|-------|-----|------------------|
| Hard-coded Flask `SECRET_KEY` | `python/app/__init__.py` | CWE-798 | High |
| Debug mode enabled (`debug=True`) | `python/run.py` | CWE-489 | Medium–High |
| Unsalted MD5 stored as password | `python/app/db.py` seed | CWE-916 | Medium |
| Verbose error / query disclosure in responses | SQLi & command handlers (all langs) | CWE-209 | Low |
| Missing security headers (CSP, X-Frame-Options) | all apps | CWE-693 | Low / Info |

Expect roughly **+3 to +6** findings from this category depending on the scanner.

---

## One-line answer

> **~140 intentional findings: 34 Critical, 74 High, 32 Medium, 0 Low** (135 SAST
> + 5 SCA across five languages), with a further ~3–6 Low/Medium hardening
> findings depending on the tool — and **zero** findings expected on the 41 safe
> reference handlers.
