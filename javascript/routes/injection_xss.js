/**
 * Cross-Site Scripting (XSS) — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
 *
 * Same annotation format as the SQL-injection reference module: every
 * permutation carries a standard header (flaw, CWE, exploitation likelihood,
 * greenfield-vs-legacy prevalence, an example payload, and the safe pattern).
 * The dangerous sink on each handler is flagged with a `VULNERABLE:` comment,
 * and the file ends with ONE clearly-labelled SAFE reference handler.
 *
 * The genuine dangerous sink here is writing untrusted input into an HTML
 * response (server side) or into `innerHTML` (client side) WITHOUT escaping.
 */
'use strict';

const express = require('express');

const router = express.Router();

// ===========================================================================
// PERMUTATION 1 — Reflected XSS: untrusted query param echoed into HTML body
// OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
// CWE-79: Improper Neutralization of Input During Web Page Generation
// EXPLOITATION LIKELIHOOD: HIGH — reflected and deterministic, works pre-auth;
//   only friction is that a victim must open the attacker's crafted link.
// PREVALENCE TODAY: greenfield LOW (React/Vue/Angular/Svelte auto-escape
//   interpolated text; SAST flags raw-HTML sinks) | legacy/10yr tech-debt HIGH
//   (string-concatenated HTML, classic EJS/JSP/PHP echo with no output encoding).
// EXAMPLE:
//   GET /injection/xss/hello?name=<script>alert(1)</script>
// FIX: HTML-entity-encode on output (see /injection/xss/hello-safe).
// ===========================================================================
router.get('/hello', (req, res) => {
  const name = req.query.name || 'world';
  // VULNERABLE: user input interpolated straight into the HTML body, unescaped.
  const html =
    `<!doctype html><html><head><meta charset="utf-8"><title>Hello</title></head>` +
    `<body><h1>Hello, ${name}!</h1>` +
    `<p>Your <code>name</code> parameter was reflected verbatim into this page.</p>` +
    `</body></html>`;
  res.send(html);
});

// ===========================================================================
// PERMUTATION 2 — Stored XSS: comment persisted unescaped, replayed to viewers
// OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
// CWE-79: Improper Neutralization of Input During Web Page Generation
// EXPLOITATION LIKELIHOOD: HIGH — the payload persists server-side and fires in
//   every viewer's browser (including admins) with no crafted link or targeting.
// PREVALENCE TODAY: greenfield LOW-MEDIUM (auto-escaping templates neutralize
//   most stored values, but rich-text/markdown/HTML-allowed fields and
//   dangerouslySetInnerHTML reintroduce it) | legacy/10yr tech-debt HIGH
//   (unescaped render of user content, sometimes stored years ago).
// EXAMPLE:
//   curl -X POST localhost:3000/injection/xss/comment \
//        -d 'text=<script>alert(document.cookie)</script>'
//   GET /injection/xss/comments        # payload executes for every visitor
// FIX: escape each comment at render time (or sanitize an allow-list of HTML).
// ===========================================================================
const comments = []; // module-level in-memory store — NO escaping in or out.

router.post('/comment', (req, res) => {
  const text = (req.body && req.body.text) || req.query.text || '';
  // VULNERABLE: raw comment stored verbatim; it is rendered unescaped later.
  comments.push(text);
  res.json({ stored: text, count: comments.length, view: '/injection/xss/comments' });
});

router.get('/comments', (req, res) => {
  // VULNERABLE: every stored comment concatenated into the page unescaped, so a
  // single malicious comment runs in every visitor's browser.
  const items = comments.map((c) => `<li>${c}</li>`).join('\n');
  const html =
    `<!doctype html><html><head><meta charset="utf-8"><title>Comments</title></head>` +
    `<body><h1>Comments (${comments.length})</h1><ul>${items}</ul></body></html>`;
  res.send(html);
});

// ===========================================================================
// PERMUTATION 3 — DOM-based XSS: client JS copies location.hash into innerHTML
// OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
// CWE-79: Improper Neutralization of Input During Web Page Generation
// EXPLOITATION LIKELIHOOD: MEDIUM-HIGH — the bug is entirely client-side; a
//   victim must open a crafted #fragment link, and the fragment never leaves the
//   browser, so server/WAF logging cannot see the payload.
// PREVALENCE TODAY: greenfield MEDIUM (framework text-binding is safe, but
//   innerHTML / dangerouslySetInnerHTML / .html() sinks fed from location/URL
//   still ship) | legacy/10yr tech-debt HIGH (jQuery .html(), document.write,
//   hand-rolled hash routers everywhere).
// EXAMPLE:
//   GET /injection/xss/dom#<img src=x onerror=alert(1)>
// FIX: use textContent / setHTML() / a sanitizer (DOMPurify); never innerHTML.
// ===========================================================================
router.get('/dom', (req, res) => {
  // The SERVER returns a static page — the payload after `#` never reaches it.
  // The flaw lives in the inline client script below, which assigns the URL
  // fragment to innerHTML.
  const html =
    `<!doctype html><html><head><meta charset="utf-8"><title>DOM XSS</title></head>` +
    `<body><h1>DOM XSS demo</h1>` +
    `<p>Put a payload after the <code>#</code>, e.g. ` +
    `<code>#&lt;img src=x onerror=alert(1)&gt;</code></p>` +
    `<div id="out">(reads location.hash)</div>` +
    `<script>` +
    `var payload = decodeURIComponent(location.hash.slice(1));` +
    // VULNERABLE (client-side sink): fragment written straight into innerHTML.
    `document.getElementById('out').innerHTML = payload;` +
    `</script>` +
    `</body></html>`;
  res.send(html);
});

// ===========================================================================
// PERMUTATION 4 — Reflected XSS in an HTML ATTRIBUTE context (breakout)
// OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
// CWE-79: Improper Neutralization of Input During Web Page Generation
// EXPLOITATION LIKELIHOOD: HIGH — reflected and deterministic; breaking out of
//   the quoted attribute needs no `<`/`>` chars, and `autofocus onfocus=...`
//   fires with zero user interaction. Demonstrates that naive angle-bracket-only
//   escaping is insufficient — attribute context needs quote/entity encoding.
// PREVALENCE TODAY: greenfield LOW-MEDIUM (frameworks encode per output context,
//   but hand-rolled "strip &lt;&gt;" helpers and quoted/unquoted attribute
//   interpolation slip through review) | legacy/10yr tech-debt HIGH (custom
//   escape utilities that only neutralize angle brackets).
// EXAMPLE:
//   GET /injection/xss/profile?name=" onmouseover=alert(1) x="
//   GET /injection/xss/profile?name=" autofocus onfocus=alert(1) x="
// FIX: context-aware encode; for a double-quoted attribute at least escape " to
//   &quot; (see /injection/xss/hello-safe, which encodes all HTML metacharacters).
// ===========================================================================
router.get('/profile', (req, res) => {
  const name = req.query.name || 'guest';
  // VULNERABLE: reflected inside a double-quoted attribute with no encoding, so a
  // bare `"` closes the attribute and lets the attacker inject event handlers.
  const html =
    `<!doctype html><html><head><meta charset="utf-8"><title>Profile</title></head>` +
    `<body><h1>Profile</h1>` +
    `<form><label>Name: <input name="name" value="${name}"></label></form>` +
    `<p>Angle-bracket-only escaping would NOT save this attribute context.</p>` +
    `</body></html>`;
  res.send(html);
});

// ===========================================================================
// SAFE REFERENCE — HTML-entity-encode untrusted output. Escaping the full set of
// HTML metacharacters (& < > " ') keeps the value inert in BOTH element-body and
// quoted-attribute contexts. Shown so the vulnerable/safe pair diffs cleanly.
// ===========================================================================
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

router.get('/hello-safe', (req, res) => {
  const name = req.query.name || 'world';
  const safe = escapeHtml(name); // SAFE: encoded before it touches the HTML.
  const html =
    `<!doctype html><html><head><meta charset="utf-8"><title>Hello (safe)</title></head>` +
    `<body><h1>Hello, ${safe}!</h1>` +
    `<form><label>Name: <input name="name" value="${safe}"></label></form>` +
    `</body></html>`;
  res.send(html);
});

module.exports = { base: '/injection/xss', router };
