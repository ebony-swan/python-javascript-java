# 03 — Cryptographic Failures

**OWASP 2021:** A02 Cryptographic Failures → **OWASP 2025:** A04 Cryptographic Failures
**Primary CWEs:** CWE-327 (broken algorithm), CWE-916 (weak hash), CWE-798/321 (hard-coded key), CWE-338/330 (weak PRNG)

"Cryptographic failures" is less about broken math and more about developers
using the wrong primitive, reusing keys, or reaching for a general-purpose RNG.

Endpoints: `/crypto`.

| # | Endpoint | Flaw | CWE | Exploitation | Prev. G | Prev. L |
|---|----------|------|-----|--------------|:-------:|:-------:|
| 1 | `GET /hash?password=` | unsalted MD5/SHA-1 for passwords | 916/327 | **HIGH** | LOW | HIGH |
| 2 | `GET /token?user=` | hard-coded signing secret | 798/321 | **HIGH** | MEDIUM | HIGH |
| 3 | `GET /encrypt` `GET /decrypt` | static key, no IV, structure-leaking mode | 327/329 | **MEDIUM** | MEDIUM | HIGH |
| 4 | `GET /reset-token?user=` | token from a non-crypto PRNG | 338/330 | **HIGH** | MEDIUM | HIGH |

- **P1 — weak password hashing.** MD5/SHA-1, unsalted (the scheme the seeded
  `users` table actually uses). Rainbow tables and GPU cracking make recovery
  trivial once a hash leaks (e.g. via the SQLi UNION in doc 01). *Prevalence:*
  **LOW** greenfield — Django/Werkzeug/Spring Security/Rails ship bcrypt/argon2 by
  default — but **HIGH** in legacy auth code.
- **P2 — hard-coded secret.** The HMAC key is a literal in the source
  (`hardcoded-hmac-key-do-not-ship-2021`). HMAC-SHA256 is strong, but anyone with
  the repo forges valid tokens. *Prevalence:* **MEDIUM** greenfield (vaults/KMS/
  env-vars are standard, yet secrets still slip into source — see any secret-
  scanning report), **HIGH** legacy.
- **P3 — weak cipher/mode.** A static key with no per-message IV in a
  structure-leaking mode (AES-**ECB** in JS/Java; a static repeating-key XOR in
  Python, since no AES lib is bundled) means identical plaintext blocks produce
  identical ciphertext, and everything is reversible by anyone with the (shared,
  static) key. **MEDIUM** exploitation; **HIGH** legacy prevalence (ECB is the
  classic "it encrypts, ship it" mistake).
- **P4 — insecure randomness.** Reset/session tokens from `random.Random`
  (Mersenne Twister) / `Math.random` / `java.util.Random` are predictable — an
  attacker who observes a few outputs can reconstruct the state and forge future
  tokens → account takeover. **HIGH** exploitation; **MEDIUM** greenfield / **HIGH**
  legacy.

**Fix:** argon2/bcrypt/scrypt for passwords; secrets from a vault/KMS/env, never
source; authenticated encryption (AES-GCM) with a random per-message nonce; a
CSPRNG (`secrets`, `crypto.randomBytes`, `java.security.SecureRandom`) for all
security tokens. See `…reset-token-safe`.
