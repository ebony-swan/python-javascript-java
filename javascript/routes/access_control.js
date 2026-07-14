/**
 * Broken Access Control — OWASP 2021 A01 | OWASP 2025 A01.
 *
 * Same annotation format as the SQL-injection reference module: each
 * permutation carries a standard header describing the flaw, its CWE, an
 * exploitation-likelihood rating, prevalence today, an example request, and
 * the corresponding safe pattern. Access-control flaws are business-logic
 * bugs — no framework enforces object- or function-level authorization for
 * you — so the vulnerable handlers below simply OMIT the check that should be
 * there. They are left unguarded on purpose so the demos are really
 * exploitable; a single clearly-labelled SAFE handler shows the fix.
 */
'use strict';

const express = require('express');
const { getDb } = require('../db');

const router = express.Router();

// ===========================================================================
// PERMUTATION 1 — IDOR: direct object reference with no ownership check
// OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
// CWE-639: Authorization Bypass Through User-Controlled Key
// EXPLOITATION LIKELIHOOD: HIGH — post-auth but trivial: the note id is a
//   sequential integer in the URL, so an attacker simply enumerates ?id=1,2,3…
//   and reads every user's PRIVATE notes (ids 2 and 4). No tooling, fully
//   deterministic, high-impact data exposure.
// PREVALENCE TODAY: greenfield MEDIUM (no framework/ORM enforces object-level
//   authorization — it is app-specific logic that is easy to forget; row-level
//   security and policy layers help only when teams actually add them) |
//   legacy/10yr tech-debt HIGH (CRUD-by-primary-key endpoints written before
//   ownership checks were routine remain everywhere; IDOR is the #1 A01 finding).
// EXAMPLE:
//   GET /access/note?id=2   -> alice's private "Bank PIN reminder"
//   GET /access/note?id=4   -> admin's private "Ops runbook" (prod db password)
// FIX: scope every fetch to the caller — WHERE id = ? AND (private = 0 OR
//   owner = ?) — using the SERVER-side session identity (see /access/note-safe).
// ===========================================================================
router.get('/note', (req, res) => {
  const id = req.query.id;
  // VULNERABLE: note fetched by id alone — no owner/private authorization check.
  const sql = 'SELECT id, owner, title, body, private FROM notes WHERE id = ?';
  try {
    const note = getDb().prepare(sql).get(id);
    res.json({ query: sql, id, note: note || null });
  } catch (err) {
    res.status(500).json({ query: sql, error: err.message });
  }
});

// ===========================================================================
// PERMUTATION 2 — Missing function-level authorization on an admin endpoint
// OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
// CWE-862: Missing Authorization
// EXPLOITATION LIKELIHOOD: HIGH — the "admin" path is protected by nothing but
//   its name (security by URL obscurity). Any anonymous caller hits it directly
//   and dumps every user's password hash, email and SSN. Pre-auth, one request.
// PREVALENCE TODAY: greenfield MEDIUM (frameworks offer route guards/decorators,
//   but applying them is opt-in and a newly added admin/internal route is easily
//   shipped without one — deny-by-default is still not the norm) | legacy/10yr
//   tech-debt HIGH (admin/debug/export endpoints that assume "no link in the UI"
//   equals "unreachable" are a classic finding in older codebases).
// EXAMPLE:
//   GET /access/admin/users   -> full users table incl. md5 hashes + SSNs
// FIX: enforce authentication AND role at the boundary (require an authenticated
//   session, assert role === 'admin' via server-side state) before the handler
//   runs; deny by default.
// ===========================================================================
router.get('/admin/users', (req, res) => {
  // VULNERABLE: no authentication and no role check — anyone reaches this.
  const sql = 'SELECT id, username, password, email, role, ssn FROM users';
  try {
    const users = getDb().prepare(sql).all();
    res.json({ query: sql, note: 'no auth/role check performed', users });
  } catch (err) {
    res.status(500).json({ query: sql, error: err.message });
  }
});

// ===========================================================================
// PERMUTATION 3 — Mass assignment / privilege escalation
// OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
// CWE-915: Improperly Controlled Modification of Dynamically-Determined Object
//          Attributes (mass assignment / auto-binding)
// EXPLOITATION LIKELIHOOD: HIGH — the profile update binds EVERY field present
//   in the JSON body straight onto the row, so a normal user adds one extra key
//   ("role":"admin") and escalates to administrator in a single request.
//   Deterministic, no tooling.
// PREVALENCE TODAY: greenfield MEDIUM (safe-by-default guards exist — DTOs,
//   zod/class-validator strict schemas, allow-listed columns — but the ORM
//   convenience patterns  Model.update(req.body)  and  {...user, ...req.body}
//   remain extremely common and re-open it whenever the schema step is skipped)
//   | legacy/10yr tech-debt HIGH (hand-rolled "update all posted fields" loops
//   over request bodies are a staple of older CRUD code).
// EXAMPLE:
//   curl -X POST /access/profile -H 'Content-Type: application/json' \
//        -d '{"username":"alice","email":"a@x.com","role":"admin"}'
//   -> alice.role becomes 'admin' even though role was never meant to be editable
// FIX: bind only an explicit allow-list of user-editable fields (never role);
//   e.g. destructure { email } = req.body and update just that column.
// ===========================================================================
router.post('/profile', (req, res) => {
  const body = req.body || {};
  const username = body.username;
  if (!username) {
    return res.status(400).json({ error: 'username required' });
  }
  // VULNERABLE: every posted field is written to the row — including role —
  // with no allow-list, so the client controls which columns get updated.
  const fields = Object.keys(body).filter((k) => k !== 'username');
  const setClause = fields.map((k) => `${k} = ?`).join(', ');
  const values = fields.map((k) => body[k]);
  const sql = `UPDATE users SET ${setClause} WHERE username = ?`;
  try {
    getDb().prepare(sql).run(...values, username);
    const updated = getDb()
      .prepare('SELECT id, username, email, role, ssn FROM users WHERE username = ?')
      .get(username);
    res.json({ query: sql, boundFields: fields, updated: updated || null });
  } catch (err) {
    res.status(500).json({ query: sql, error: err.message });
  }
});

// ===========================================================================
// PERMUTATION 4 — Client-controlled authorization ("trust the X-Role header")
// OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
// CWE-602: Client-Side Enforcement of Server-Side Security
// EXPLOITATION LIKELIHOOD: HIGH — the admin decision is read from a value the
//   client fully controls (an "X-Role" request header or ?role= param). The
//   attacker just sets it to "admin" and the server hands back admin-only data.
//   Pre-auth, one request, no tooling.
// PREVALENCE TODAY: greenfield LOW (identity in new apps is derived from a
//   validated session/JWT verified server-side; trusting a raw request header
//   for authz is a textbook antipattern SAST/review flag — though it resurfaces
//   in service meshes that blindly trust gateway-set identity headers on a
//   directly-reachable service) | legacy/10yr tech-debt HIGH (hand-rolled auth
//   that reads a role from a header, cookie or hidden field and believes it is
//   common in older enterprise and internal apps).
// EXAMPLE:
//   curl -H 'X-Role: admin' /access/dashboard
//   GET  /access/dashboard?role=admin
//   -> returns admin-only data to an unauthenticated caller
// FIX: never derive privilege from client input; look up the role from the
//   server-side session/token for the authenticated principal.
// ===========================================================================
router.get('/dashboard', (req, res) => {
  // VULNERABLE: authorization decided from a client-supplied header/param.
  const role = req.get('X-Role') || req.query.role || 'user';
  const isAdmin = role === 'admin';
  if (isAdmin) {
    const secrets = getDb()
      .prepare('SELECT id, username, email, role, ssn FROM users')
      .all();
    return res.json({
      claimedRole: role,
      access: 'admin',
      adminData: { flag: 'ADMIN_DASHBOARD_UNLOCKED', users: secrets },
    });
  }
  res.json({ claimedRole: role, access: 'user', adminData: null });
});

// ===========================================================================
// SAFE REFERENCE — server-side ownership/role enforcement.
// The caller's identity comes from server-side state (here simulated by
// ?current=, defaulting to 'alice'; in a real app it is the authenticated
// session/token — never a note field or a client header). A note is returned
// only when it is public OR owned by the current user; a private note owned by
// someone else yields 403, so id enumeration leaks nothing.
// ===========================================================================
router.get('/note-safe', (req, res) => {
  const id = req.query.id;
  const current = req.query.current || 'alice'; // SAFE: identity from server side
  const note = getDb()
    .prepare('SELECT id, owner, title, body, private FROM notes WHERE id = ?')
    .get(id);
  if (!note) {
    return res.status(404).json({ id, note: null });
  }
  if (note.private && note.owner !== current) {
    return res.status(403).json({ id, error: 'forbidden', currentUser: current });
  }
  res.json({ id, currentUser: current, note });
});

module.exports = { base: '/access', router };
