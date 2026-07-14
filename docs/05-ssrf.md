# 05 — Server-Side Request Forgery (SSRF)

**OWASP 2021:** A10 Server-Side Request Forgery → **OWASP 2025:** folded into A01 Broken Access Control
**Primary CWE:** CWE-918

SSRF tricks the server into making requests the attacker chooses — reaching
internal services, cloud metadata endpoints, and admin panels that are firewalled
from the outside. In 2025 OWASP merged SSRF into Broken Access Control (it is,
in effect, the server's network access being controlled by the attacker). The
rise of microservices and cloud metadata has *increased* its relevance.

Endpoints: `/ssrf`.

| # | Endpoint | Flaw | Exploitation | Prev. G | Prev. L |
|---|----------|------|--------------|:-------:|:-------:|
| 1 | `GET /fetch?url=` | fetch any user URL, no allow-list | **HIGH** | MEDIUM | HIGH |
| 2 | `POST /webhook` | blind/internal SSRF via callback URL | **MEDIUM** | HIGH | HIGH |
| 3 | `GET /preview?url=` | naive substring blocklist, bypassable | **HIGH** | MEDIUM | HIGH |

- **P1 — direct fetch.** One `url=` param and the server GETs whatever you name,
  returning the body — point it at `http://169.254.169.254/latest/meta-data/`
  (AWS/GCP/Azure metadata) to steal cloud credentials, or at internal admin
  services. **HIGH** exploitation. *Prevalence:* **MEDIUM** greenfield — URL-fetch
  features (link previews, image proxies, PDF/screenshot renderers, importers)
  are everywhere and rarely allow-listed — **HIGH** legacy.
- **P2 — blind webhook.** The response isn't returned, but the *request* is the
  weapon: internal port scanning, hitting state-changing internal endpoints, and
  metadata theft still work blind. **MEDIUM** exploitation, but **HIGH prevalence
  on both axes** — user-supplied webhooks/callbacks are a standard product
  feature that teams rarely think of as SSRF.
- **P3 — blocklist bypass.** The endpoint blocks the substrings `localhost` /
  `127.0.0.1`, then fetches — defeated by `http://127.0.0.1.nip.io`,
  `http://0177.0.0.1` (octal), `http://2130706433` (decimal), `http://[::1]`, or an
  external URL that 302-redirects inward. **HIGH** — the "fix" is illusory.
  *Prevalence:* **MEDIUM** greenfield / **HIGH** legacy — string blocklists are the
  default wrong answer teams reach for.

**Fix:** allow-list schemes and destination hosts; resolve the hostname and
reject private/link-local ranges (`127.0.0.0/8`, `10/8`, `172.16/12`,
`192.168/16`, `169.254/16`) *after* resolution; disable or re-validate redirects;
block the metadata IP explicitly. See `…fetch-safe`.
