/**
 * Insecure Deserialization / Software & Data Integrity Failures —
 * OWASP 2021 A08 Software and Data Integrity Failures |
 * OWASP 2025 A08 Software and Data Integrity Failures.
 *
 * Same annotation format as the reference SQL-injection module: each
 * permutation carries a standard header describing the flaw, its CWE, an
 * exploitation-likelihood rating, a prevalence estimate, an example payload,
 * and the corresponding safe pattern. The dangerous sink on each handler is
 * flagged inline with `VULNERABLE:`.
 *
 * Sinks demonstrated (all genuine, all exploitable when the app runs):
 *   P1  node-serialize .unserialize()   -> RCE via _$$ND_FUNC$$_ IIFE   (CWE-502)
 *   P2  eval('(' + data + ')')          -> arbitrary code execution     (CWE-95)
 *   P3  hand-rolled recursive merge     -> prototype pollution __proto__ (CWE-1321)
 */
'use strict';

const express = require('express');
const serialize = require('node-serialize');

const router = express.Router();

// A textbook recursive merge — the exact shape found in countless "deepMerge",
// "extend", and config-loader helpers. It walks the source object and copies
// keys into the target; nested objects recurse. It performs NO key filtering,
// so an attacker-supplied `__proto__` key mutates Object.prototype. Used by
// PERMUTATION 3 below.
function unsafeMerge(target, source) {
  for (const key in source) {
    const value = source[key];
    if (value !== null && typeof value === 'object') {
      if (target[key] === null || typeof target[key] !== 'object') target[key] = {};
      unsafeMerge(target[key], value); // recurses into target['__proto__'] === Object.prototype
    } else {
      target[key] = value;
    }
  }
  return target;
}

// ===========================================================================
// PERMUTATION 1 — Native object deserialization of attacker data (node-serialize)
// OWASP 2021 A08 Software and Data Integrity Failures  ->  OWASP 2025 A08 Software and Data Integrity Failures
// CWE-502: Deserialization of Untrusted Data
// EXPLOITATION LIKELIHOOD: HIGH — unserialize() eval()s any function carried in
//   the `_$$ND_FUNC$$_` marker; a trailing `()` makes it an IIFE that fires at
//   parse time for reliable, deterministic pre-auth RCE. Needs the known
//   node-serialize gadget/marker, so slightly less turnkey than plain eval.
// PREVALENCE TODAY: greenfield RARE (nobody adds node-serialize to a new app;
//   JSON.parse is the default and the library is abandoned + npm-audit/SAST
//   flagged) | legacy/10yr tech-debt LOW (niche even historically, but survives
//   in old code that needed to serialize functions/live sessions).
// EXAMPLE:
//   curl -s localhost:3000/deserialization/native -H 'Content-Type: application/json' \
//     -d '{"payload":"{\"x\":\"_$$ND_FUNC$$_function(){return require('child_process').execSync('id').toString()}()\"}"}'
//   -> response echoes the `id` command output.
// FIX: never deserialize untrusted input into live objects; use JSON.parse
//   (data-only) and validate against a schema. See /deserialization/safe.
// ===========================================================================
router.post('/native', (req, res) => {
  const payload = (req.body && req.body.payload) || '';
  try {
    // VULNERABLE: unserialize() eval()s embedded _$$ND_FUNC$$_ functions.
    const obj = serialize.unserialize(payload);
    const preview = {};
    for (const k of Object.keys(obj || {})) {
      preview[k] = typeof obj[k] === 'function' ? '[function]' : obj[k];
    }
    res.json({ payload, result: preview });
  } catch (err) {
    res.status(500).json({ payload, error: err.message });
  }
});

// ===========================================================================
// PERMUTATION 2 — Unsafe "config" parsing via eval() (CWE-95 code injection)
// OWASP 2021 A08 Software and Data Integrity Failures  ->  OWASP 2025 A08 Software and Data Integrity Failures
// CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
// EXPLOITATION LIKELIHOOD: CRITICAL — wrapping user text in eval('(' + data + ')')
//   executes ANY JavaScript with zero gadget needed; a one-liner yields pre-auth
//   RCE, fully deterministic. The most turnkey sink in this file.
// PREVALENCE TODAY: greenfield LOW (eval is the canonical "never do this";
//   eslint no-eval and every SAST rule flag it; JSON.parse is idiomatic) |
//   legacy/10yr tech-debt MEDIUM (eval('('+resp+')') was the pre-JSON.parse way
//   to parse AJAX/JSONP responses and loosely-typed config, still in old code).
// EXAMPLE:
//   curl -s localhost:3000/deserialization/eval -H 'Content-Type: application/json' \
//     -d '{"data":"{ maxItems: 6*7 }"}'                       # -> config {maxItems:42}
//   curl -s localhost:3000/deserialization/eval -H 'Content-Type: application/json' \
//     -d '{"data":"require('child_process').execSync('id').toString()"}'   # -> RCE
// FIX: parse configuration with JSON.parse (data only). See /deserialization/safe.
// ===========================================================================
router.post('/eval', (req, res) => {
  const data = (req.body && req.body.data) || '';
  try {
    // VULNERABLE: attacker-controlled string evaluated as live JavaScript.
    const config = eval('(' + data + ')');
    res.json({ data, evaluated: '(' + data + ')', config });
  } catch (err) {
    res.status(500).json({ data, error: err.message });
  }
});

// ===========================================================================
// PERMUTATION 3 — Prototype pollution via recursive merge of user JSON
// OWASP 2021 A08 Software and Data Integrity Failures  ->  OWASP 2025 A08 Software and Data Integrity Failures
// CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
// EXPLOITATION LIKELIHOOD: HIGH — polluting Object.prototype via a `__proto__`
//   key is trivial and deterministic; every object app-wide inherits the value.
//   Direct impact ranges from DoS / auth-bypass (e.g. injected isAdmin) to RCE
//   when a downstream gadget (template engine, child_process options) reads it —
//   the escalation is what needs a gadget, the pollution itself does not.
// PREVALENCE TODAY: greenfield MEDIUM (hand-rolled deepMerge / config loaders /
//   query-string parsers keep reintroducing it; a very active CVE class since
//   2018 even though many libs are now hardened) | legacy/10yr tech-debt HIGH
//   (pre-2018 lodash/jQuery.extend and unguarded custom merges still shipping).
// EXAMPLE:
//   curl -s localhost:3000/deserialization/merge -H 'Content-Type: application/json' \
//     -d '{"json":"{\"__proto__\":{\"isAdmin\":true}}"}'
//   -> response.probe.isAdmin === true, read off a brand-new unrelated object.
// FIX: reject/strip __proto__|constructor|prototype keys, build with
//   Object.create(null) or Map, or use a hardened merge. See /deserialization/safe.
// ===========================================================================
router.post('/merge', (req, res) => {
  const raw = (req.body && req.body.json) || '{}';
  let source;
  try {
    source = JSON.parse(raw); // JSON.parse keeps __proto__ as an inert OWN key...
  } catch (err) {
    return res.status(400).json({ input: raw, error: err.message });
  }
  const before = Object.getOwnPropertyNames(Object.prototype);
  const target = {};
  // VULNERABLE: recursive merge honors a `__proto__` key and writes through to
  // Object.prototype, polluting every object in the process.
  unsafeMerge(target, source);
  const after = Object.getOwnPropertyNames(Object.prototype);
  const pollutedKeys = after.filter((k) => !before.includes(k));

  // Read the pollution back off a freshly-created, completely unrelated object:
  const probe = {};
  const leakedOnFreshObject = {};
  for (const k of pollutedKeys) leakedOnFreshObject[k] = probe[k];

  res.json({
    input: raw,
    merged: target,
    pollutedKeys,
    leakedOnFreshObject,
    probe: { isAdmin: probe.isAdmin, polluted: probe.polluted },
  });
});

// ===========================================================================
// SAFE REFERENCE — data-only parsing with a prototype-pollution guard. Shown so
// the vulnerable/safe pair can be diffed by SAST tooling and learners. JSON.parse
// yields inert data (no functions execute, no code runs); the merge guard drops
// the dangerous keys before any recursion.
// ===========================================================================
router.post('/safe', (req, res) => {
  const raw = (req.body && req.body.data) || '{}';
  let parsed;
  try {
    parsed = JSON.parse(raw); // SAFE: pure data, no code/function evaluation.
  } catch (err) {
    return res.status(400).json({ input: raw, error: err.message });
  }
  // SAFE merge: allow-list nothing dangerous — refuse the pollution vectors.
  const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
  const target = Object.create(null); // no prototype to pollute
  for (const key of Object.keys(parsed)) {
    if (FORBIDDEN.has(key)) continue;
    target[key] = parsed[key];
  }
  res.json({ input: raw, parsed, safeMerged: { ...target } });
});

module.exports = { base: '/deserialization', router };
