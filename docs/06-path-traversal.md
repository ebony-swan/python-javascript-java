# 06 — Path Traversal

**OWASP 2021:** A01 Broken Access Control (path traversal) → **OWASP 2025:** A01 / A05-adjacent
**Primary CWE:** CWE-22 (improper limitation of a pathname to a restricted directory)

Path traversal is what happens when user input reaches a filesystem path without
containment: `../` sequences (or absolute paths) escape the intended directory to
read — or write — arbitrary files.

Each app ships a "public" directory it is *supposed* to serve from
(`…/data/public/welcome.txt`) and a `secret.txt` one level up as the target.

Endpoints: `/path`.

| # | Endpoint | Flaw | Exploitation | Prev. G | Prev. L |
|---|----------|------|--------------|:-------:|:-------:|
| 1 | `GET /read?file=` | arbitrary file **read** via unchecked join | **HIGH** | MEDIUM | HIGH |
| 2 | `GET /download?name=` | same, framed as a download | **HIGH** | MEDIUM | HIGH |
| 3 | `POST /extract` | arbitrary file **write** (Zip Slip) | **MED–HIGH** | MEDIUM | MED–HIGH |

- **P1 — file read.** `?file=../secret.txt` escapes the public dir (verified);
  `../../../../etc/passwd` and absolute paths work too. Pre-auth, deterministic,
  zero tooling → **HIGH**. *Prevalence:* **MEDIUM** greenfield — frameworks ship
  safe static-file helpers, but "serve/preview a file by name" endpoints get
  hand-rolled constantly — **HIGH** legacy.
- **P2 — file download.** Identical traversal behind a `Content-Disposition`
  attachment header ("download this export/attachment by name"). Same ratings.
- **P3 — Zip Slip (arbitrary write).** Simulated archive extraction writes each
  entry to `join(extractDir, entry.name)` with no containment, so an entry named
  `../../pwned.txt` lands outside the target dir. Arbitrary **write** is more
  powerful than read — overwrite a web-root file, a cron job, or an SSH key for
  RCE → **MEDIUM–HIGH**. *Prevalence:* **MEDIUM** on both axes — stdlib extractors
  (`zipfile.extractall`) now sanitize members, but hand-rolled extraction and
  older libraries still ship the bug (Zip Slip affected thousands of projects).

**Fix:** canonicalize the resolved path (`os.path.realpath` /
`Path.toRealPath()` / `getCanonicalPath()`) and verify it stays within the
intended base directory *before* opening or writing; reject absolute paths and
`..` segments; never trust archive entry names. See `…read-safe`.
