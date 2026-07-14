# 02 — Broken Access Control

**OWASP 2021:** A01 Broken Access Control → **OWASP 2025:** A01 Broken Access Control
**Primary CWEs:** CWE-639 (IDOR), CWE-862 (missing authorization), CWE-915 (mass assignment), CWE-602 (client-side enforcement)

Broken access control is #1 in *both* editions. Unlike injection, frameworks
**can't fix it for you** — authorization is application logic, so these patterns
stay common even in brand-new code. That makes the "greenfield" prevalence here
notably higher than for injection.

Endpoints: `/access`.

| # | Endpoint | Flaw | CWE | Exploitation | Prev. G | Prev. L |
|---|----------|------|-----|--------------|:-------:|:-------:|
| 1 | `GET /note?id=` | **IDOR** — no ownership check | 639 | **HIGH** | HIGH | HIGH |
| 2 | `GET /admin/users` | **Missing function-level authz** | 862 | **HIGH** | MEDIUM | HIGH |
| 3 | `POST /profile` | **Mass assignment** → privilege escalation | 915 | **HIGH** | MEDIUM | HIGH |
| 4 | `GET /dashboard` | **Client-controlled authorization** | 602 | **HIGH** | LOW | MEDIUM |

- **P1 — IDOR.** `?id=2` returns alice's *private* note; `?id=4` returns the
  admin runbook. A single integer selects the object and nothing checks who owns
  it. Trivial enumeration → **HIGH** exploitation. *Prevalence:* **HIGH on both
  axes** — ORMs happily fetch any row by id, so unless the developer *adds* an
  ownership check, every greenfield app is one `findById()` away from this.
- **P2 — Missing function-level authorization.** `/admin/users` returns every
  user's hash, email, and SSN with no authentication or role check. *Prevalence:*
  **MEDIUM** greenfield (auth middleware/decorators are standard, but it's easy to
  forget one route), **HIGH** legacy (authz sprinkled ad hoc).
- **P3 — Mass assignment.** `POST /profile` writes *every* field in the body,
  including `role`, so a normal user sends `{"username":"alice","role":"admin"}`
  and escalates. *Prevalence:* **MEDIUM** greenfield — explicit DTOs/serializers
  with allow-lists help, but "bind the whole request object" ORMs (Rails, Spring
  `@ModelAttribute`, Mongoose) reintroduce it — **HIGH** legacy.
- **P4 — Client-controlled authorization.** The admin decision is read from a
  client-supplied `X-Role` header / `?role=` param and trusted. *Prevalence:*
  **LOW** greenfield (server-verified session/JWT claims are the norm), **MEDIUM**
  legacy (hidden-field/header "roles" from a pre-token era).

**Fix:** enforce authorization **server-side** on every request against the
authenticated principal; check ownership before returning/mutating an object;
bind an explicit allow-list of fields; deny by default. See the `…note-safe`
handler, which only returns a note that is public or owned by the current user.
