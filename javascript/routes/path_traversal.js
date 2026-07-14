/**
 * Path Traversal — OWASP 2021 A01 Broken Access Control | OWASP 2025 A01 / A05.
 *
 * Same annotation format as the reference SQL-injection module: each
 * permutation carries a standard header describing the flaw, its CWE, an
 * exploitation-likelihood rating, a prevalence estimate, an example request,
 * and the corresponding safe pattern. The dangerous sink on each handler is
 * flagged inline with `VULNERABLE:`.
 *
 * The file-serving handlers are anchored at BASE_PUBLIC (data/public/, holds
 * welcome.txt); the target the endpoints are NOT supposed to reach is
 * data/secret.txt one level up. The genuine dangerous primitive here is
 * `path.resolve(base, userInput)`: developers reach for it believing it
 * "cleans" a path, but it neither contains the result to `base` nor rejects
 * absolute inputs — an absolute argument REPLACES the base entirely, and `../`
 * segments climb above it.
 *
 * Sinks demonstrated (all genuine, all exploitable when the app runs):
 *   P1  fs.readFileSync(path.resolve(base, file))    -> arbitrary file READ    (CWE-22)
 *   P2  createReadStream(path.resolve(base, name))   -> arbitrary file DOWNLOAD (CWE-22)
 *   P3  fs.writeFileSync(path.join(dir, entry.name)) -> Zip Slip arbitrary WRITE (CWE-22)
 */
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();

// Directory the file endpoints are SUPPOSED to be restricted to, and the
// extraction target for the Zip-Slip demo. Both live under data/.
const BASE_PUBLIC = path.join(__dirname, '..', 'data', 'public');
const EXTRACT_DIR = path.join(BASE_PUBLIC, 'incoming');

// ===========================================================================
// PERMUTATION 1 — Arbitrary file read via path.resolve(base, userInput)
// OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
//   (absolute-path variant is CWE-36 Absolute Path Traversal)
// EXPLOITATION LIKELIHOOD: HIGH — pre-auth, a single GET, fully deterministic,
//   no tooling. `?file=../secret.txt` escapes the public dir; `?file=/etc/passwd`
//   (absolute) makes resolve() discard the base outright; enough `../` climbs to
//   filesystem root. Classic "download report/template/avatar by name" bug.
// PREVALENCE TODAY: greenfield MEDIUM (static assets now go through hardened
//   middleware like express.static/send that reject `..`, and object storage
//   replaces filesystem reads — but every hand-rolled "serve this file by name"
//   route, plus misplaced faith in path.resolve/normalize as a sanitizer, keeps
//   reintroducing it; a very common AI-generated snippet) | legacy/10yr
//   tech-debt HIGH (file-by-name endpoints written before containment checks
//   were routine are everywhere in older codebases).
// EXAMPLE:
//   GET /path/read?file=welcome.txt                          -> intended file
//   GET /path/read?file=../secret.txt                        -> escapes -> data/secret.txt (flag)
//   GET /path/read?file=/etc/passwd                          -> absolute replaces base
//   GET /path/read?file=../../../../../../../../etc/passwd   -> climb to root then /etc/passwd
// FIX: resolve THEN verify containment — reject unless the resolved path equals
//   base or startsWith(base + path.sep); canonicalize with fs.realpathSync to
//   defeat symlinks, or better serve an allow-listed id -> filename map.
//   See /path/read-safe.
// ===========================================================================
router.get('/read', (req, res) => {
  const file = req.query.file || '';
  // VULNERABLE: user input resolved against the base with no containment check —
  // `../` escapes and an absolute path replaces BASE_PUBLIC entirely.
  const resolved = path.resolve(BASE_PUBLIC, file);
  try {
    const contents = fs.readFileSync(resolved, 'utf8');
    res.json({ base: BASE_PUBLIC, file, resolved, contents });
  } catch (err) {
    res.status(404).json({ base: BASE_PUBLIC, file, resolved, error: err.message });
  }
});

// ===========================================================================
// PERMUTATION 2 — Traversal in a file download (Content-Disposition attachment)
// OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
//   (absolute-path variant is CWE-36 Absolute Path Traversal)
// EXPLOITATION LIKELIHOOD: HIGH — same primitive as P1, framed as a download:
//   pre-auth, one GET, deterministic. The attacker points `?name=` at any file
//   and the server streams it back as an attachment. Absolute paths accepted.
// PREVALENCE TODAY: greenfield MEDIUM (custom download endpoints that build a
//   Content-Disposition and stream a file chosen by a request parameter remain
//   common even in modern apps, since framework static handlers do not cover
//   "download this generated/user file by name") | legacy/10yr tech-debt HIGH
//   (report/invoice/export download servlets and CGI-era `?file=` handlers are a
//   canonical source of traversal in old code).
// EXAMPLE:
//   curl -OJ 'localhost:3000/path/download?name=../secret.txt'   # -> data/secret.txt (flag)
//   curl      'localhost:3000/path/download?name=/etc/passwd'    # -> absolute path
// FIX: resolve and enforce the same base-containment check before streaming, or
//   map an opaque id to a server-side filename; never pass request input to the
//   filesystem. See /path/read-safe for the containment pattern.
// ===========================================================================
router.get('/download', (req, res) => {
  const name = req.query.name || '';
  // VULNERABLE: download target resolved from user input with no containment —
  // traversal and absolute paths stream any file the process can read.
  const resolved = path.resolve(BASE_PUBLIC, name);
  res.setHeader('Content-Disposition', `attachment; filename="${path.basename(resolved)}"`);
  res.setHeader('X-Resolved-Path', resolved); // echo the effective path (like the SQL demo echoes the query)
  const stream = fs.createReadStream(resolved);
  stream.on('error', (err) => {
    if (!res.headersSent) res.status(404).json({ base: BASE_PUBLIC, name, resolved, error: err.message });
  });
  stream.pipe(res);
});

// ===========================================================================
// PERMUTATION 3 — Zip Slip: arbitrary file WRITE on archive extraction
// OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
// EXPLOITATION LIKELIHOOD: MEDIUM-HIGH — the write itself is trivial and
//   deterministic: an entry named `../../pwned.txt` lands OUTSIDE the extraction
//   directory. Escalation to RCE is high-impact but contingent on a useful write
//   target (web root, cron.d, a startup/rc file, .ssh/authorized_keys), which is
//   what makes it MEDIUM-HIGH rather than a guaranteed HIGH.
// PREVALENCE TODAY: greenfield LOW (mainstream archive libraries added Zip-Slip
//   guards after the 2018 Zip-Slip disclosure — modern unzip/tar reject `..` by
//   default — so new code that uses them is usually safe) | legacy/10yr
//   tech-debt MEDIUM (hand-rolled "loop the entries and write each to
//   destDir + entry.name" extractors, and pre-2018 library versions, still ship
//   in older upload/import/plugin pipelines).
// EXAMPLE:
//   curl -s localhost:3000/path/extract -H 'Content-Type: application/json' \
//     -d '{"entries":[{"name":"notes/ok.txt","content":"hi"},
//                     {"name":"../../pwned.txt","content":"owned"}]}'
//   -> the second entry resolves outside EXTRACT_DIR (…/javascript/data/pwned.txt)
// FIX: for every entry, resolve the target and reject it unless it stays within
//   the extraction dir (resolved === dir || startsWith(dir + path.sep)); drop
//   absolute names and any path containing `..`. See /path/extract-safe.
// ===========================================================================
router.post('/extract', (req, res) => {
  const entries = (req.body && req.body.entries) || [];
  const results = [];
  try {
    fs.mkdirSync(EXTRACT_DIR, { recursive: true });
    for (const entry of entries) {
      const name = (entry && entry.name) || '';
      const content = entry && entry.content != null ? String(entry.content) : '';
      // VULNERABLE: entry name joined onto the extraction dir with no containment
      // — a `../` in the name writes the file OUTSIDE EXTRACT_DIR (Zip Slip).
      const target = path.join(EXTRACT_DIR, name);
      const written = path.resolve(target);
      fs.mkdirSync(path.dirname(written), { recursive: true });
      fs.writeFileSync(written, content);
      const escaped = written !== path.resolve(EXTRACT_DIR) &&
        !written.startsWith(path.resolve(EXTRACT_DIR) + path.sep);
      results.push({ name, written, escaped });
    }
    res.json({ extractDir: path.resolve(EXTRACT_DIR), results });
  } catch (err) {
    res.status(500).json({ extractDir: path.resolve(EXTRACT_DIR), error: err.message, results });
  }
});

// ===========================================================================
// SAFE REFERENCE — canonicalize the resolved path and verify it stays within
// the intended base directory. Shown so the vulnerable/safe pair can be diffed
// by SAST tooling and learners. Mirrors os.path.realpath+startswith (Python) /
// Path.toRealPath().startsWith (Java): resolve, containment-check the string,
// then realpath the result to defeat symlink escapes before any read.
// ===========================================================================
router.get('/read-safe', (req, res) => {
  const file = req.query.file || '';
  const baseReal = fs.realpathSync(BASE_PUBLIC); // canonical base
  const resolved = path.resolve(baseReal, file);
  // SAFE: reject anything that does not stay under the base directory.
  if (resolved !== baseReal && !resolved.startsWith(baseReal + path.sep)) {
    return res.status(403).json({ file, resolved, error: 'path escapes base directory' });
  }
  try {
    const real = fs.realpathSync(resolved); // SAFE: canonicalize to defeat symlink escapes
    if (real !== baseReal && !real.startsWith(baseReal + path.sep)) {
      return res.status(403).json({ file, resolved: real, error: 'symlink escapes base directory' });
    }
    res.json({ file, resolved: real, contents: fs.readFileSync(real, 'utf8') });
  } catch (err) {
    res.status(404).json({ file, resolved, error: err.message });
  }
});

module.exports = { base: '/path', router };
