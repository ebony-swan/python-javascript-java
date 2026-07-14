/**
 * SQL Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
 *
 * Reference module: the comment/annotation format used here is mirrored by
 * every other vulnerability module in this app. Each permutation carries a
 * standard header describing the flaw, its CWE, an exploitation-likelihood
 * rating, an example payload, and the corresponding safe pattern.
 */
'use strict';

const express = require('express');
const { getDb } = require('../db');

const router = express.Router();

// ===========================================================================
// PERMUTATION 1 — SQL injection via template-literal concatenation (auth bypass)
// OWASP 2021: A03 Injection      OWASP 2025: A05 Injection
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
// EXPLOITATION LIKELIHOOD: HIGH
//   Reachable pre-authentication, deterministic, no tooling required.
//   The textbook  ' OR '1'='1  / username=admin'--  payloads bypass login.
// PREVALENCE TODAY: greenfield LOW-MED (modern ORMs parameterize by default;
//   recurs in raw SQL and AI-generated snippets) | legacy/10yr tech-debt HIGH.
// EXAMPLE:
//   GET /injection/sql/login?username=admin'--&password=whatever
//   GET /injection/sql/login?username=x' OR '1'='1&password=x
// FIX: parameterize (see /injection/sql/login-safe).
// ===========================================================================
router.get('/login', (req, res) => {
  const username = req.query.username || '';
  const password = req.query.password || '';
  // VULNERABLE: user input concatenated straight into the SQL string.
  const sql =
    `SELECT id, username, role FROM users ` +
    `WHERE username = '${username}' AND password = '${password}'`;
  try {
    const row = getDb().prepare(sql).get();
    res.json({ authenticated: !!row, as: row || null, query: sql });
  } catch (err) {
    res.status(500).json({ query: sql, error: err.message });
  }
});

// ===========================================================================
// PERMUTATION 2 — SQL injection via string concatenation (UNION data theft)
// OWASP 2021: A03 Injection      OWASP 2025: A05 Injection
// CWE-89
// EXPLOITATION LIKELIHOOD: HIGH
//   A UNION SELECT reads arbitrary columns/tables (e.g. dump password hashes
//   and SSNs from the users table) through a search box.
// PREVALENCE TODAY: greenfield MEDIUM (raw SQL persists in search/reporting/
//   analytics paths) | legacy/10yr tech-debt HIGH.
// EXAMPLE:
//   GET /injection/sql/search?q=zzz' UNION SELECT username, password, ssn FROM users--
// FIX: parameterize the WHERE clause.
// ===========================================================================
router.get('/search', (req, res) => {
  const q = req.query.q || '';
  // VULNERABLE: untrusted input concatenated into a LIKE clause.
  const sql = `SELECT title, body, owner FROM notes WHERE body LIKE '%${q}%'`;
  try {
    const results = getDb().prepare(sql).all();
    res.json({ query: sql, results });
  } catch (err) {
    res.status(500).json({ query: sql, error: err.message });
  }
});

// ===========================================================================
// PERMUTATION 3 — SQL injection via a dynamic ORDER BY clause
// OWASP 2021: A03 Injection      OWASP 2025: A05 Injection
// CWE-89
// EXPLOITATION LIKELIHOOD: MEDIUM
//   Column/keyword positions cannot be bound as parameters, so developers
//   often concatenate sort fields. Exploitable for blind boolean/error-based
//   extraction; needs more skill than a UNION.
// PREVALENCE TODAY: greenfield MED-HIGH (SQL identifiers/sort columns cannot be
//   bound, so concatenated ORDER BY stays common in modern ORM apps) | legacy HIGH.
// EXAMPLE:
//   GET /injection/sql/notes?sort=body--
//   GET /injection/sql/notes?sort=(CASE WHEN (SELECT 1)=1 THEN title ELSE body END)
// FIX: allow-list sortable column names.
// ===========================================================================
router.get('/notes', (req, res) => {
  const sort = req.query.sort || 'id';
  // VULNERABLE: sort field concatenated into ORDER BY.
  const sql = `SELECT id, owner, title FROM notes ORDER BY ${sort}`;
  try {
    const results = getDb().prepare(sql).all();
    res.json({ query: sql, results });
  } catch (err) {
    res.status(500).json({ query: sql, error: err.message });
  }
});

// ===========================================================================
// SAFE REFERENCE — parameterized query. Shown so the vulnerable/safe pair can
// be diffed by SAST tooling and learners.
// ===========================================================================
router.get('/login-safe', (req, res) => {
  const username = req.query.username || '';
  const password = req.query.password || '';
  const row = getDb()
    .prepare('SELECT id, username, role FROM users WHERE username = ? AND password = ?')
    .get(username, password);
  res.json({ authenticated: !!row, as: row || null });
});

module.exports = { base: '/injection/sql', router };
