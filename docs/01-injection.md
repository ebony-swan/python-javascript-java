# 01 — Injection (SQL, Command, XSS)

**OWASP 2021:** A03 Injection → **OWASP 2025:** A05 Injection
**Primary CWEs:** CWE-89 (SQLi), CWE-78/88 (Command), CWE-79 (XSS), CWE-1336 (SSTI)

Injection happens whenever untrusted input is mixed into an interpreter's syntax
— SQL, a shell command line, or an HTML/JS document — without keeping data and
code separate. It is the single most reliably exploitable class in this lab.

> **Likelihood legend.** *Exploitation* = how easily an attacker succeeds if the
> endpoint is reachable. *Prevalence* is split: **G** = greenfield/modern shop,
> **L** = legacy / ~10-yr technical debt. See [`README.md`](README.md) for the
> full rubric.

---

## 1a. SQL Injection — `/injection/sql` (CWE-89)

| # | Endpoint | Mechanism | Exploitation | Prev. G | Prev. L |
|---|----------|-----------|--------------|:-------:|:-------:|
| 1 | `GET /login` | string concatenation (auth bypass) | **HIGH** | LOW–MED | HIGH |
| 2 | `GET /search` | format-string interpolation (UNION dump) | **HIGH** | MEDIUM | HIGH |
| 3 | `GET /notes?sort=` | dynamic `ORDER BY` (identifier can't be bound) | **MEDIUM** | MED–HIGH | HIGH |

- **P1 — concatenation / auth bypass.** `username=admin'--` comments out the
  password check and logs you in as admin. One request, no auth, no tooling →
  **HIGH**. *Prevalence:* modern ORMs (SQLAlchemy, JPA/Hibernate, Prisma)
  parameterize by default so this is **LOW–MED** in greenfield, but **HIGH** in
  decade-old hand-built JDBC/PHP query code. LLM-generated snippets frequently
  reintroduce it.
- **P2 — interpolation / UNION theft.** `q=zzz' UNION SELECT username, password,
  ssn FROM users--` dumps every hash and SSN through a search box. *Prevalence:*
  **MEDIUM** in greenfield (raw SQL survives in search/reporting/analytics paths
  ORMs handle poorly), **HIGH** in legacy.
- **P3 — dynamic `ORDER BY`.** SQL **identifiers** (column names, sort
  direction) cannot be bound as parameters, so developers concatenate them.
  Exploited via boolean/error-based oracles → **MEDIUM** exploitation, but
  **MED–HIGH** prevalence *even in modern ORM apps* because the framework can't
  parameterize it for you.

**Fix:** parameterized queries / prepared statements everywhere; allow-list
identifiers for sort/column names. See each app's `…login-safe` handler.

---

## 1b. Command Injection — `/injection/command` (CWE-78 / CWE-88)

| # | Endpoint | Mechanism | Exploitation | Prev. G | Prev. L |
|---|----------|-----------|--------------|:-------:|:-------:|
| 1 | `GET /ping?host=` | concatenated string run via a **shell** | **HIGH** | LOW | HIGH |
| 2 | `GET /dns?domain=` | second shell tool (`nslookup`/`host`) | **HIGH** | LOW | MED–HIGH |
| 3 | `GET /backup?filename=` | **argument** injection into `tar` (no shell) | **MEDIUM** | MEDIUM | MEDIUM |

- **P1/P2 — shell metacharacters.** `host=127.0.0.1;id` runs `id`. Pre-auth RCE
  → **HIGH**. *Prevalence:* **LOW** in greenfield — modern code rarely shells
  out and uses `argv` arrays/`shell=False` when it does — but **HIGH** in legacy
  scripts that build command strings.
- **P3 — argument injection.** Even *without* a shell, passing
  `filename=--checkpoint=1 --checkpoint-action=exec=sh -c id` turns a `tar` call
  into code execution. The lesson: array-exec is **not automatically safe** if
  the attacker controls an argument that the target binary treats as an option.
  **MEDIUM** on both axes — developers who "did the safe thing" with `argv`
  still get bitten.

**Fix:** avoid the shell; use `argv` arrays with a fixed program; strictly
validate/allow-list arguments; use `--` to end option parsing. See `…backup-safe`.

---

## 1c. Cross-Site Scripting (XSS) — `/injection/xss` (CWE-79, CWE-1336)

| # | Endpoint | Type | Exploitation | Prev. G | Prev. L |
|---|----------|------|--------------|:-------:|:-------:|
| 1 | `GET /hello?name=` | **Reflected** (HTML body context) | **HIGH** | MEDIUM | HIGH |
| 2 | `POST /comment` + `GET /comments` | **Stored** | **HIGH** | MEDIUM | HIGH |
| 3 | `GET /dom` | **DOM-based** (client-side `innerHTML` sink) | **MEDIUM** | MEDIUM | MED–HIGH |
| 4 | `GET /profile?name=` | **Disabled escaping / context** (see below) | **HIGH** | LOW | MEDIUM |

- **P1 Reflected / P2 Stored.** `name=<script>alert(1)</script>` (or a stored
  comment) executes in the victim's browser. Stored is worse — it persists and
  fires against *every* viewer, including admins. *Prevalence:* auto-escaping
  templates (React, Jinja2, Angular, Thymeleaf) make this **MEDIUM** in
  greenfield (rich-text/`dangerouslySetInnerHTML`/legacy partials still leak) and
  **HIGH** in legacy string-built HTML.
- **P3 DOM-based.** The payload never reaches the server — client JS reads
  `location.hash` and assigns it to `innerHTML`: `/injection/xss/dom#<img src=x
  onerror=alert(1)>`. Server-side defenses can't see it → **MEDIUM**.
- **P4 Disabled escaping — the language-idiomatic footgun:**
  - **Python:** `render_template_string` renders input *as a Jinja template* —
    not just XSS but **Server-Side Template Injection** (`name={{7*7}}`→`49`,
    escalating to RCE; CWE-1336). Exploitation **HIGH/CRITICAL**.
  - **JavaScript:** input reflected into an **attribute** context
    (`<input value="…">`); `name=" onmouseover=alert(1) x="` breaks out —
    showing that naive `<`/`>` escaping is insufficient per context.
  - **Java:** Thymeleaf `th:utext` **disables** the default escaping and emits
    raw HTML.
  *Prevalence:* **LOW** in greenfield (SAST flags `render_template_string`/`utext`
  on sight), **MEDIUM** in legacy.

**Fix:** contextual output encoding by default; never disable auto-escaping;
render user data as *data*, not templates; set a Content-Security-Policy. See
`…hello-safe`.
