/**
 * Cryptographic Failures — OWASP 2021 A02 | OWASP 2025 A04.
 *
 * Mirrors the reference module (routes/injection_sql.js): every permutation
 * carries the standard header block describing the flaw, its CWE, an
 * exploitation-likelihood rating, prevalence today, an example request, and
 * the corresponding safe pattern. The dangerous sink on each handler is marked
 * with an inline "VULNERABLE:" comment. One SAFE reference handler closes out
 * the file.
 *
 * WARNING: intentional weak crypto — never use any of this in real code.
 */
'use strict';

const express = require('express');
const crypto = require('crypto');
const { getDb } = require('../db');

const router = express.Router();

// ---------------------------------------------------------------------------
// HARD-CODED SECRETS (the whole point of P2 / P3): committing key material to
// source means anyone with read access to the repo — insiders, a leaked
// tarball, a public mirror, a decompiled bundle — owns the keys forever. There
// is no rotation, no per-environment separation, no vault. See P2 and P3.
// ---------------------------------------------------------------------------
// VULNERABLE: HMAC signing key is a hard-coded literal (CWE-798/321).
const TOKEN_SIGNING_KEY = 's3cr3t-hardcoded-hmac-key-do-not-ship';
// VULNERABLE: AES key is a hard-coded 16-byte literal (CWE-798/321), reused
// forever with no IV — see P3.
const AES_KEY = Buffer.from('0123456789abcdef', 'utf8'); // 16 bytes => AES-128

// ===========================================================================
// PERMUTATION 1 — Weak, unsalted password hashing (MD5 + SHA-1)
// OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
// CWE-916: Use of Password Hash With Insufficient Computational Effort (also CWE-327)
// EXPLOITATION LIKELIHOOD: HIGH — once a hash leaks (SQLi dump, backup, log),
//   unsalted MD5/SHA-1 are cracked instantly via precomputed rainbow tables or
//   commodity GPU brute-force; no per-hash work, no salt to defeat lookups.
// PREVALENCE TODAY: greenfield LOW (modern auth libs/frameworks default to
//   bcrypt/scrypt/argon2 with per-user salts) | legacy/10yr tech-debt HIGH
//   (MD5/SHA-1 password columns are everywhere and migrating them is painful).
// EXAMPLE:
//   GET /crypto/hash?password=admin123
//   -> md5 0192023a7bbd73250516f069df18b500 matches the seeded admin row and is
//      the first hit in any rainbow table.
// FIX: use a salted, deliberately-slow KDF (scrypt/bcrypt/argon2); never MD5/SHA-1
//   for passwords. See /crypto/hash-safe.
// ===========================================================================
router.get('/hash', (req, res) => {
  const password = req.query.password || '';
  // VULNERABLE: fast, unsalted general-purpose hashes used for passwords.
  const md5 = crypto.createHash('md5').update(password).digest('hex');
  const sha1 = crypto.createHash('sha1').update(password).digest('hex');
  res.json({
    password,
    md5,
    sha1,
    scheme: 'unsalted MD5 (same as the users table) + unsalted SHA-1',
    note: 'No salt and a fast hash => rainbow-table / GPU brute-force trivial.',
  });
});

// ===========================================================================
// PERMUTATION 2 — Hard-coded signing secret (forgeable tokens)
// OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
// CWE-798: Use of Hard-coded Credentials (also CWE-321: Hard-coded Cryptographic Key)
// EXPLOITATION LIKELIHOOD: CRITICAL — the HMAC key is a literal in this file, so
//   anyone with the source recomputes valid signatures for any user/role and
//   forges an admin token offline; deterministic, no tooling, full auth bypass.
// PREVALENCE TODAY: greenfield MEDIUM (secret scanning/12-factor config help, but
//   hard-coded keys still slip into new repos and default configs) | legacy/10yr
//   tech-debt HIGH (pre-vault codebases pin keys in source and config files).
// EXAMPLE:
//   GET /crypto/token?user=admin
//   Attacker with the source signs {"user":"admin","role":"admin"} using the
//   published key and presents the token to any endpoint that trusts it.
// FIX: load secrets from a KMS/vault or env, rotate them, and keep them out of
//   source control (git history is forever).
// ===========================================================================
router.get('/token', (req, res) => {
  const user = req.query.user || 'guest';
  const row = getDb()
    .prepare('SELECT role FROM users WHERE username = ?')
    .get(user);
  const role = row ? row.role : 'user';
  const payload = Buffer.from(
    JSON.stringify({ user, role, iat: Date.now() })
  ).toString('base64url');
  // VULNERABLE: token signed with the hard-coded TOKEN_SIGNING_KEY literal.
  const sig = crypto
    .createHmac('sha256', TOKEN_SIGNING_KEY)
    .update(payload)
    .digest('base64url');
  const token = `${payload}.${sig}`;
  res.json({
    user,
    role,
    token,
    signing_key_used: TOKEN_SIGNING_KEY,
    note: 'Key is a hard-coded literal in crypto.js -> tokens are forgeable by anyone with the source.',
  });
});

// ===========================================================================
// PERMUTATION 3 — Weak cipher mode: AES-ECB with a static key and no IV
// OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
// CWE-327: Use of a Broken or Risky Cryptographic Algorithm (ECB mode / static key)
// EXPLOITATION LIKELIHOOD: HIGH — ECB encrypts each 16-byte block independently,
//   so identical plaintext blocks yield identical ciphertext blocks, leaking
//   structure and enabling cut-and-paste/block-shuffling attacks; the static
//   hard-coded key means any captured ciphertext decrypts offline.
// PREVALENCE TODAY: greenfield LOW (libsodium/AES-GCM/authenticated encryption
//   are the defaults; ECB is a code-smell reviewers catch) | legacy/10yr
//   tech-debt HIGH (ECB + DES + fixed keys persist in old payment/PII code).
// EXAMPLE:
//   GET /crypto/encrypt?text=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
//   -> the two identical 16-byte plaintext blocks produce two identical
//      ciphertext blocks (visible as a repeated hex chunk). Round-trip:
//   GET /crypto/decrypt?data=<hex from /encrypt>
// FIX: use an authenticated mode (AES-256-GCM) with a random per-message IV/nonce
//   and a key from a KMS/vault; never ECB, never a static key/IV.
// ===========================================================================
router.get('/encrypt', (req, res) => {
  const text = req.query.text || '';
  try {
    // VULNERABLE: AES-128-ECB (no IV, no authentication) with a static key.
    const cipher = crypto.createCipheriv('aes-128-ecb', AES_KEY, null);
    const encrypted = Buffer.concat([
      cipher.update(text, 'utf8'),
      cipher.final(),
    ]).toString('hex');
    res.json({
      text,
      algorithm: 'aes-128-ecb',
      key: AES_KEY.toString('utf8'),
      data: encrypted,
      note: 'ECB: identical 16-byte plaintext blocks -> identical ciphertext blocks. Static key + no IV.',
    });
  } catch (err) {
    res.status(500).json({ text, error: err.message });
  }
});

router.get('/decrypt', (req, res) => {
  const data = req.query.data || '';
  try {
    // VULNERABLE: matching AES-128-ECB decrypt with the same static key.
    const decipher = crypto.createDecipheriv('aes-128-ecb', AES_KEY, null);
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(data, 'hex')),
      decipher.final(),
    ]).toString('utf8');
    res.json({ data, algorithm: 'aes-128-ecb', text: decrypted });
  } catch (err) {
    res.status(500).json({ data, error: err.message });
  }
});

// ===========================================================================
// PERMUTATION 4 — Insecure randomness for reset tokens (predictable RNG)
// OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
// CWE-338: Use of Cryptographically Weak PRNG (also CWE-330: Insufficiently Random Values)
// EXPLOITATION LIKELIHOOD: HIGH — Math.random() is V8's non-crypto xorshift128+
//   and its internal state is recoverable from a handful of observed outputs;
//   combined with the time-based prefix an attacker predicts other users' reset
//   tokens and takes over accounts (no email access needed).
// PREVALENCE TODAY: greenfield MEDIUM (framework session IDs are usually CSPRNG,
//   but hand-rolled reset/invite/coupon tokens still reach for Math.random) |
//   legacy/10yr tech-debt HIGH (Math.random / java.util.Random tokens abound).
// EXAMPLE:
//   GET /crypto/reset-token?user=alice
//   Observe a few tokens, reconstruct the xorshift128+ state, predict the next
//   token issued for the victim, and reset their password.
// FIX: use a CSPRNG (crypto.randomBytes) for all tokens. See /crypto/reset-token-safe.
// ===========================================================================
router.get('/reset-token', (req, res) => {
  const user = req.query.user || 'guest';
  // VULNERABLE: token built from Date.now() + Math.random() — both predictable.
  const timePart = Date.now().toString(36);
  let randPart = '';
  for (let i = 0; i < 24; i++) {
    randPart += Math.floor(Math.random() * 16).toString(16);
  }
  const token = `${timePart}-${randPart}`;
  res.json({
    user,
    token,
    source: 'Date.now() + Math.random()',
    note: 'Math.random() is a non-crypto PRNG (V8 xorshift128+); state is recoverable -> tokens are predictable.',
  });
});

// ===========================================================================
// SAFE REFERENCE — the correct patterns, shown so the vulnerable/safe pairs can
// be diffed by SAST tooling and learners.
//   * password hashing: scrypt (a slow, memory-hard KDF) with a random per-user salt
//   * tokens: crypto.randomBytes (a CSPRNG), not Math.random
// ===========================================================================
router.get('/hash-safe', (req, res) => {
  const password = req.query.password || '';
  // SAFE: random per-user salt + a deliberately-slow KDF (scrypt).
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 32);
  res.json({
    scheme: 'scrypt(password, random-salt, N=default) — slow, salted KDF',
    salt: salt.toString('hex'),
    hash: derived.toString('hex'),
    note: 'Per-user random salt defeats rainbow tables; scrypt is memory-hard to slow brute force.',
  });
});

router.get('/reset-token-safe', (req, res) => {
  const user = req.query.user || 'guest';
  // SAFE: CSPRNG — 32 unpredictable bytes.
  const token = crypto.randomBytes(32).toString('hex');
  res.json({
    user,
    token,
    source: 'crypto.randomBytes(32) — CSPRNG',
    note: 'Cryptographically secure randomness; not predictable from prior outputs.',
  });
});

module.exports = { base: '/crypto', router };
