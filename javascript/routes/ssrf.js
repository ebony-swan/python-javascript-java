/**
 * Server-Side Request Forgery (SSRF) —
 *   OWASP 2021 A10 Server-Side Request Forgery
 *   -> folded into OWASP 2025 A01 Broken Access Control.
 *
 * Same annotation format as the SQL-injection reference module: each
 * permutation carries a standard header describing the flaw, its CWE, an
 * exploitation-likelihood rating, prevalence today, an example payload, and
 * the corresponding safe pattern. The genuine dangerous sink for JavaScript —
 * the global `fetch()` issuing a request to a user-controlled URL — is used
 * unvalidated so the demos are really exploitable. Every outbound request uses
 * a short AbortSignal.timeout(3000) so the demo never hangs, and errors are
 * caught and returned alongside the exact URL that was requested.
 */
'use strict';

const express = require('express');
const dns = require('dns').promises;

const router = express.Router();

// How much of a fetched body to echo back (keeps responses readable while
// still proving the internal/metadata content was actually reachable).
const SNIPPET = 512;
const TIMEOUT_MS = 3000;

// ===========================================================================
// PERMUTATION 1 — Server-side GET to a fully user-controlled URL (classic SSRF)
// OWASP 2021 A10 Server-Side Request Forgery  ->  folded into OWASP 2025 A01 Broken Access Control
// CWE-918: Server-Side Request Forgery (SSRF)
// EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic, no tooling: the
//   server fetches whatever URL you pass and hands you the body, so you read
//   internal-only services, link-local cloud metadata (169.254.169.254) and
//   file:// / gopher targets straight from the response.
// PREVALENCE TODAY: greenfield MEDIUM (URL-preview / import-from-URL / image-proxy
//   / PDF-render features are everywhere and no framework blocks SSRF by default —
//   there is no ORM-equivalent safe layer — but security-aware shops now reach for
//   SSRF-guard middleware and IMDSv2) | legacy/10yr tech-debt HIGH (hand-rolled
//   RSS/feed readers, link unfurlers, XML/SOAP fetchers and avatar-by-URL uploads
//   from the IMDSv1 era fetch attacker URLs with zero destination validation).
// EXAMPLE:
//   GET /ssrf/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
//   GET /ssrf/fetch?url=http://127.0.0.1:3000/injection/sql/search%3Fq=x   (reach internal-only apps)
//   GET /ssrf/fetch?url=file:///etc/passwd
// FIX: allow-list scheme+host, resolve DNS and block private/link-local IP
//   ranges, disable redirects (see /ssrf/fetch-safe).
// ===========================================================================
router.get('/fetch', async (req, res) => {
  const url = req.query.url || 'http://example.com/';
  try {
    // VULNERABLE: user-supplied URL fetched with no allow-list / IP filtering.
    const resp = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    const body = await resp.text();
    res.json({
      requested: url,
      status: resp.status,
      contentType: resp.headers.get('content-type'),
      snippet: body.slice(0, SNIPPET),
    });
  } catch (err) {
    res.status(502).json({ requested: url, error: err.message });
  }
});

// ===========================================================================
// PERMUTATION 2 — Blind webhook / callback SSRF (internal reach & port scan)
// OWASP 2021 A10 Server-Side Request Forgery  ->  folded into OWASP 2025 A01 Broken Access Control
// CWE-918: Server-Side Request Forgery (SSRF)
// EXPLOITATION LIKELIHOOD: MEDIUM — the response body is NOT returned (blind),
//   so credential *reading* off the metadata service is indirect; but the status
//   code + round-trip time still leak whether an internal host:port is open
//   (port scanning) and the request itself is enough to hit unauthenticated
//   internal actions (e.g. an admin API that acts on a bare GET/POST).
// PREVALENCE TODAY: greenfield HIGH (webhook/callback URLs are a core integration
//   pattern in modern SaaS and are *meant* to be arbitrary, so devs deliberately
//   skip destination validation) | legacy/10yr tech-debt MEDIUM (fewer webhook
//   features in older apps, but ping-back / notify-URL settings that fire a
//   server-side request to a stored URL do exist and are unvalidated).
// EXAMPLE:
//   curl -X POST /ssrf/webhook -H 'Content-Type: application/json' \
//        -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
//   curl -X POST /ssrf/webhook -d '{"url":"http://10.0.0.5:6379/"}'   (blind internal port probe)
// FIX: allow-list the destination, resolve+block private ranges, and require the
//   caller to pre-register/verify webhook hosts (see /ssrf/fetch-safe).
// ===========================================================================
router.post('/webhook', async (req, res) => {
  const url = (req.body && req.body.url) || '';
  const started = Date.now();
  try {
    // VULNERABLE: server fires a request at a user-supplied callback URL. The
    // body is intentionally discarded ("blind"), but the request still reaches
    // internal services and leaks liveness via status + timing.
    const resp = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    res.json({
      requested: url,
      delivered: true,
      status: resp.status,
      elapsedMs: Date.now() - started,
    });
  } catch (err) {
    res.status(502).json({
      requested: url,
      delivered: false,
      elapsedMs: Date.now() - started,
      error: err.message,
    });
  }
});

// ===========================================================================
// PERMUTATION 3 — SSRF behind a naive substring blocklist (trivially bypassable)
// OWASP 2021 A10 Server-Side Request Forgery  ->  folded into OWASP 2025 A01 Broken Access Control
// CWE-918: Server-Side Request Forgery (SSRF)
// EXPLOITATION LIKELIHOOD: HIGH — the filter only rejects the literal strings
//   "localhost" / "127.0.0.1", and the body IS returned, so well-known IP
//   encodings and wildcard-DNS reach loopback/link-local anyway. A blocklist is
//   a denylist of a boundless input space — every encoding is a bypass.
// PREVALENCE TODAY: greenfield MEDIUM (a dev who has *heard* of SSRF bolts on a
//   quick string check, which passes review/SAST yet blocks nothing) |
//   legacy/10yr tech-debt MEDIUM (older "fixes" that grep the URL for bad hosts
//   linger; WHATWG-URL octal/decimal normalization makes them useless).
// EXAMPLE (all evade the substring test, all hit loopback/metadata):
//   GET /ssrf/preview?url=http://2130706433/                 (decimal  -> 127.0.0.1)
//   GET /ssrf/preview?url=http://0177.0.0.1/                 (octal    -> 127.0.0.1)
//   GET /ssrf/preview?url=http://[::1]:3000/                 (IPv6 loopback)
//   GET /ssrf/preview?url=http://127.0.0.2.nip.io/           (wildcard DNS -> 127.0.0.2, no literal match)
//   GET /ssrf/preview?url=http://169.254.169.254/latest/meta-data/   (link-local, not in blocklist at all)
//   GET /ssrf/preview?url=http://evil.example/redirect       (302 -> internal; fetch follows redirects)
// FIX: never blocklist by substring. Parse the URL, allow-list scheme+host,
//   resolve DNS and reject private/link-local IPs, disable redirects (/ssrf/fetch-safe).
// ===========================================================================
router.get('/preview', async (req, res) => {
  const url = req.query.url || 'http://example.com/';
  // Naive, bypassable blocklist: only the literal loopback spellings are caught.
  if (url.includes('localhost') || url.includes('127.0.0.1')) {
    return res.status(400).json({ requested: url, error: 'blocked by policy (localhost/127.0.0.1)' });
  }
  try {
    // VULNERABLE: substring blocklist passed -> fetch reaches loopback/metadata
    // via octal/decimal/IPv6/wildcard-DNS/redirect. (fetch follows redirects.)
    const resp = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    const body = await resp.text();
    res.json({
      requested: url,
      finalUrl: resp.url,
      status: resp.status,
      snippet: body.slice(0, SNIPPET),
    });
  } catch (err) {
    res.status(502).json({ requested: url, error: err.message });
  }
});

// ===========================================================================
// SAFE REFERENCE — allow-list scheme+host, resolve DNS, block private/link-local
// ranges, and disable redirects. Shown so the vulnerable/safe pair can be diffed
// by SAST tooling and learners.
//   * scheme restricted to http/https (no file:, gopher:, ftp:, data:);
//   * host must be on an explicit allow-list (defeats octal/decimal/IPv6 tricks —
//     none of them equal an allowed name);
//   * every resolved A/AAAA address is checked against RFC1918 / loopback /
//     link-local ranges, so a name that resolves inward (nip.io, DNS rebinding)
//     is rejected;
//   * redirects disabled so a 302 cannot bounce the request to an internal target.
// ===========================================================================
const ALLOW_SCHEMES = new Set(['http:', 'https:']);
const ALLOW_HOSTS = new Set(['example.com', 'www.example.com', 'api.github.com']);

function ipv4ToLong(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function inCidr(ip, base, bits) {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToLong(ip) & mask) === (ipv4ToLong(base) & mask);
}

function isPrivateIp(ip, family) {
  if (family === 6) {
    // Reject IPv6 loopback (::1), link-local (fe80::/10) and IPv4-mapped forms.
    const low = ip.toLowerCase();
    if (low === '::1' || low.startsWith('fe80:') || low.startsWith('fc') || low.startsWith('fd')) return true;
    const mapped = low.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return mapped ? isPrivateIp(mapped[1], 4) : false;
  }
  return (
    inCidr(ip, '127.0.0.0', 8) ||    // loopback
    inCidr(ip, '10.0.0.0', 8) ||     // RFC1918
    inCidr(ip, '172.16.0.0', 12) ||  // RFC1918
    inCidr(ip, '192.168.0.0', 16) || // RFC1918
    inCidr(ip, '169.254.0.0', 16) || // link-local (cloud metadata)
    inCidr(ip, '0.0.0.0', 8)         // "this" network / 0.0.0.0
  );
}

router.get('/fetch-safe', async (req, res) => {
  const raw = req.query.url || 'http://example.com/';
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return res.status(400).json({ requested: raw, error: 'unparseable URL' });
  }
  if (!ALLOW_SCHEMES.has(parsed.protocol)) {
    return res.status(400).json({ requested: raw, error: `scheme not allowed: ${parsed.protocol}` });
  }
  if (!ALLOW_HOSTS.has(parsed.hostname)) {
    return res.status(400).json({ requested: raw, error: `host not on allow-list: ${parsed.hostname}` });
  }
  try {
    const addrs = await dns.lookup(parsed.hostname, { all: true });
    for (const a of addrs) {
      if (isPrivateIp(a.address, a.family)) {
        return res.status(400).json({ requested: raw, error: `resolves to private/link-local address: ${a.address}` });
      }
    }
    // Safe: vetted scheme+host, no private resolution, redirects refused.
    const resp = await fetch(raw, { redirect: 'error', signal: AbortSignal.timeout(TIMEOUT_MS) });
    const body = await resp.text();
    res.json({ requested: raw, status: resp.status, snippet: body.slice(0, SNIPPET) });
  } catch (err) {
    res.status(502).json({ requested: raw, error: err.message });
  }
});

module.exports = { base: '/ssrf', router };
