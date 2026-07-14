"""Cryptographic Failures — OWASP 2021 A02 | OWASP 2025 A04.

Mirrors the header/annotation format of the reference module
(``app/vulns/injection_sql.py``). Each permutation carries a standard header
describing the flaw, its CWE, an exploitation-likelihood rating, real-world
prevalence, an example request, and the corresponding safe pattern.

NOTE ON AVAILABLE LIBRARIES: this environment ships only the Python stdlib
(no ``pyca/cryptography``, no ``pycryptodome``), so the AES/DES-ECB demo the
sister JS/Java apps use is reproduced here with a repeating-key XOR "cipher"
plus a STATIC hard-coded key. It is the same class of bug (CWE-327: use of a
broken/roll-your-own algorithm with a hard-coded key and no IV) and exhibits
the same ECB-style structural leak: identical plaintext blocks map to identical
ciphertext blocks.
"""
import base64
import hashlib
import hmac
import random

import secrets

from flask import Blueprint, request, jsonify

bp = Blueprint("crypto", __name__, url_prefix="/crypto")


# =============================================================================
# PERMUTATION 1 — Weak, unsalted password hashing (MD5 / SHA-1)
# OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
# CWE-916: Use of Password Hash With Insufficient Computational Effort
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
# EXPLOITATION LIKELIHOOD: HIGH — no auth needed to observe the scheme; once a
#   DB dump leaks, unsalted MD5/SHA-1 of common passwords is reversed instantly
#   via free rainbow tables and multi-GB/s GPU cracking. This is exactly the
#   scheme the users table uses (see app/db.py::_md5), so the whole app inherits it.
# PREVALENCE TODAY: greenfield LOW (Django/Werkzeug/Spring Security/Rails all
#   default to bcrypt/scrypt/argon2/pbkdf2 — you have to go out of your way to
#   use MD5) | legacy/10yr tech-debt HIGH (hand-rolled auth from the md5()/sha1()
#   era is still guarding production password stores everywhere).
# EXAMPLE:
#   GET /crypto/hash?password=password1
#   -> md5=7c6a180b36896a0a8c02787eeafb0e4c  (crack: any online rainbow table)
# FIX: use a slow, salted password KDF: hashlib.pbkdf2_hmac / scrypt / argon2,
#   or werkzeug.security.generate_password_hash (see /crypto/hash-safe).
# =============================================================================
@bp.get("/hash")
def hash_password():
    password = request.args.get("password", "")
    # VULNERABLE: fast, unsalted general-purpose digests used as password hashes.
    md5 = hashlib.md5(password.encode()).hexdigest()
    sha1 = hashlib.sha1(password.encode()).hexdigest()
    return jsonify(
        {
            "password": password,
            "md5": md5,
            "sha1": sha1,
            "salted": False,
            "note": "Unsalted MD5/SHA-1 — rainbow-table / brute-force trivial. "
            "Same scheme as the users table (app/db.py).",
        }
    )


# HARD-CODED SIGNING SECRET for PERMUTATION 2. Checked into source control, so
# anyone with read access to this repo can forge valid tokens for any user.
_TOKEN_SECRET = b"hardcoded-hmac-key-do-not-ship-2021"  # VULNERABLE: CWE-798 secret in source


# =============================================================================
# PERMUTATION 2 — Token signed with a HARD-CODED secret
# OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
# CWE-798: Use of Hard-coded Credentials
# CWE-321: Use of Hard-coded Cryptographic Key
# EXPLOITATION LIKELIHOOD: HIGH — HMAC-SHA256 itself is strong, but the key is a
#   literal in the source (see _TOKEN_SECRET above). Anyone with the repo (open
#   source, leaked archive, insider) forges a token for role=admin and skips
#   authentication entirely. Deterministic, no cracking required.
# PREVALENCE TODAY: greenfield MEDIUM (vaults/KMS/env-vars are standard, yet
#   hard-coded keys are still one of the top secret-scanning hits in new repos) |
#   legacy/10yr tech-debt HIGH (config-in-code predates managed secret stores).
# EXAMPLE:
#   GET /crypto/token?user=admin
#   Attacker who has _TOKEN_SECRET recomputes the HMAC over any payload:
#     python -c "import hmac,hashlib,base64;\
#       p=base64.urlsafe_b64encode(b'admin:admin').rstrip(b'=');\
#       print(p.decode()+'.'+hmac.new(b'hardcoded-hmac-key-do-not-ship-2021',p,hashlib.sha256).hexdigest())"
# FIX: load the key from a secret manager / env var, rotate it, and keep it out
#   of source control (see /crypto/token-safe for the shape of a real signer).
# =============================================================================
@bp.get("/token")
def make_token():
    user = request.args.get("user", "guest")
    role = request.args.get("role", "user")
    payload = base64.urlsafe_b64encode(f"{user}:{role}".encode()).rstrip(b"=")
    # VULNERABLE: token integrity depends on a secret hard-coded in the source.
    sig = hmac.new(_TOKEN_SECRET, payload, hashlib.sha256).hexdigest()
    token = payload.decode() + "." + sig
    return jsonify(
        {
            "user": user,
            "role": role,
            "token": token,
            "signing_key_source": "HARD-CODED literal _TOKEN_SECRET in crypto.py",
            "note": "Anyone with the source can forge a token for role=admin.",
        }
    )


# STATIC hard-coded key + no IV for PERMUTATION 3. Same key every request.
_XOR_KEY = b"STATICKEY"  # VULNERABLE: CWE-798 hard-coded key, reused, no IV/nonce


def _xor_cipher(data: bytes) -> bytes:
    # Repeating-key XOR: the "ECB" of roll-your-own crypto. Identical plaintext
    # blocks aligned to the key length produce identical ciphertext -> structure
    # leaks, and a single known-plaintext byte recovers a key byte.
    return bytes(b ^ _XOR_KEY[i % len(_XOR_KEY)] for i, b in enumerate(data))


# =============================================================================
# PERMUTATION 3 — Weak cipher: static key, no IV, structure-leaking mode
# OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
# CWE-329/CWE-798: static/absent IV and a hard-coded reused key
# EXPLOITATION LIKELIHOOD: MEDIUM — the ciphertext is reversible by anyone with
#   the source (static key), and even without it the ECB-style pattern leak +
#   known-plaintext trivially recovers the key. Needs captured ciphertext, so a
#   notch below pre-auth injection, but recovery is deterministic.
# PREVALENCE TODAY: greenfield MEDIUM (modern libs default to AEAD/AES-GCM or
#   libsodium, but "AES" with no mode still silently means ECB in several stacks,
#   e.g. Java's Cipher.getInstance("AES")) | legacy/10yr tech-debt HIGH (ECB and
#   home-grown XOR "encryption" are endemic in older codebases).
# EXAMPLE:
#   GET /crypto/encrypt?text=AAAAAAAAAAAAAAAAAAAA
#     -> hex repeats every len(key) bytes, exposing the plaintext structure.
#   GET /crypto/decrypt?data=<hex from /encrypt>   (round-trips with the static key)
# FIX: use an authenticated cipher with a random per-message nonce from a vetted
#   library (AES-GCM / ChaCha20-Poly1305), key from a KMS (see /crypto/encrypt-safe note).
# =============================================================================
@bp.get("/encrypt")
def encrypt():
    text = request.args.get("text", "")
    # VULNERABLE: broken roll-your-own cipher, static hard-coded key, no IV/nonce.
    ct = _xor_cipher(text.encode())
    hex_ct = ct.hex()
    return jsonify(
        {
            "plaintext": text,
            "ciphertext_hex": hex_ct,
            "key": _XOR_KEY.decode(),
            "mode": "repeating-key XOR (ECB-analogue: no IV, key reused)",
            "note": "Identical plaintext blocks -> identical ciphertext blocks. "
            "Static key in source means anyone can decrypt.",
        }
    )


# =============================================================================
# PERMUTATION 3 (cont.) — matching decrypt for the weak cipher above
# Same CWE-327 flaw; provided so the round-trip can be demonstrated end-to-end.
# EXAMPLE: GET /crypto/decrypt?data=<hex from /crypto/encrypt>
# =============================================================================
@bp.get("/decrypt")
def decrypt():
    data = request.args.get("data", "")
    try:
        # VULNERABLE: decryption needs only the ciphertext + the static in-source key.
        pt = _xor_cipher(bytes.fromhex(data)).decode("utf-8", "replace")
    except ValueError as exc:
        return jsonify({"data": data, "error": str(exc)}), 400
    return jsonify(
        {
            "ciphertext_hex": data,
            "plaintext": pt,
            "key": _XOR_KEY.decode(),
            "note": "Recovered with the hard-coded static key — no secret required.",
        }
    )


# =============================================================================
# PERMUTATION 4 — Predictable reset token from a non-crypto RNG
# OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
# CWE-338: Use of Cryptographically Weak PRNG
# CWE-330: Use of Insufficiently Random Values
# EXPLOITATION LIKELIHOOD: HIGH — the token comes from random.Random (Mersenne
#   Twister) seeded from the PUBLIC username. An attacker who knows the victim's
#   username reproduces the exact reset token offline and takes over the account.
#   No cracking, fully deterministic; that is why this is rated HIGH not MEDIUM.
# PREVALENCE TODAY: greenfield MEDIUM (secrets/CSPRNG guidance is well known, but
#   Math.random()/random.random() for tokens/OTPs/IDs still recurs in new code) |
#   legacy/10yr tech-debt HIGH (predictable seeding was the norm before `secrets`).
# EXAMPLE:
#   GET /crypto/reset-token?user=alice
#   Attacker reproduces it:  python -c "import random,hashlib;\
#     r=random.Random(int(hashlib.md5(b'alice').hexdigest(),16));\
#     print('%032x'%r.getrandbits(128))"
# FIX: use a CSPRNG (secrets.token_urlsafe) and store only a slow hash of the
#   token (see /crypto/reset-token-safe).
# =============================================================================
@bp.get("/reset-token")
def reset_token():
    user = request.args.get("user", "guest")
    # VULNERABLE: seed derived solely from the public username -> fully predictable.
    seed = int(hashlib.md5(user.encode()).hexdigest(), 16)
    rng = random.Random(seed)  # non-cryptographic Mersenne Twister PRNG
    token = "%032x" % rng.getrandbits(128)
    return jsonify(
        {
            "user": user,
            "reset_token": token,
            "seed_source": "int(md5(username)) — public + fixed",
            "rng": "random.Random (Mersenne Twister, NOT a CSPRNG)",
            "note": "Anyone who knows the username reproduces this token -> ATO.",
        }
    )


# =============================================================================
# SAFE REFERENCE — the correct crypto choices for the flaws above.
#   * CSPRNG for the token: secrets.token_urlsafe (os.urandom-backed).
#   * Slow, salted password/token hashing: hashlib.pbkdf2_hmac with a random salt.
# Shown so the vulnerable/safe pair can be diffed by SAST tools and learners.
# =============================================================================
@bp.get("/reset-token-safe")
def reset_token_safe():
    user = request.args.get("user", "guest")
    # SAFE: unpredictable token from a cryptographically secure RNG.
    token = secrets.token_urlsafe(32)
    # SAFE: store only a slow, salted hash of the token (never the token itself).
    salt = secrets.token_bytes(16)
    token_hash = hashlib.pbkdf2_hmac("sha256", token.encode(), salt, 200_000)
    return jsonify(
        {
            "user": user,
            "reset_token": token,  # emailed to the user once; only its hash is stored
            "stored_hash": token_hash.hex(),
            "salt": salt.hex(),
            "rng": "secrets.token_urlsafe (CSPRNG) + pbkdf2_hmac (salted, slow)",
            "note": "Unpredictable and non-reversible — the correct pattern.",
        }
    )
