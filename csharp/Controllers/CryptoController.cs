using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace VulnApp.Controllers;

/// <summary>
/// Cryptographic Failures — OWASP 2021 A02 Cryptographic Failures |
/// OWASP 2025 A04 Cryptographic Failures.
///
/// Mirrors the annotation format and attribute-routed action style of
/// SqlInjectionController. Every handler uses a REAL crypto primitive from
/// System.Security.Cryptography so each weakness is genuinely reproducible when
/// the app runs (crack the hash, forge the token, spot the ECB block echo,
/// regenerate the "random" reset token).
///
/// Identifiers are prefixed "Crypto" so nothing collides with the other C#
/// controllers that share the VulnApp.Controllers namespace.
/// </summary>
[ApiController]
public class CryptoController : ControllerBase
{
    // HARD-CODED SECRETS (the whole point of P2/P3): committed to source, so
    // anyone with the repo/binary owns them. Shown here in the clear on purpose.
    //
    //   P2 HMAC signing key ->  "s3cr3t-hmac-key-2014-do-not-ship"
    //   P3 AES-128 key       ->  "0123456789abcdef"  (16 bytes, ECB, no IV)
    //
    private const string CryptoHmacKey = "s3cr3t-hmac-key-2014-do-not-ship"; // VULNERABLE: hard-coded signing key
    private static readonly byte[] CryptoAesKey = Encoding.UTF8.GetBytes("0123456789abcdef"); // VULNERABLE: static AES-128 key

    // ========================================================================
    // PERMUTATION 1 — WEAK, UNSALTED PASSWORD HASH (MD5 / SHA-1)
    // OWASP 2021 A02 Cryptographic Failures -> OWASP 2025 A04 Cryptographic Failures
    // CWE-916: Use of Password Hash With Insufficient Computational Effort
    // EXPLOITATION LIKELIHOOD: MEDIUM — not a remote sink; it needs the hash
    //   store to leak first (e.g. via the SQLi UNION demo). Once it does, fast
    //   UNSALTED MD5/SHA-1 of human passwords fall to wordlists/rainbow tables in
    //   seconds — and this endpoint uses the EXACT scheme in users.password (Db.Md5),
    //   so md5("password1") here equals alice's stored hash.
    // PREVALENCE TODAY: greenfield LOW (ASP.NET Core Identity hashes with PBKDF2 by
    //   default; devs reach for bcrypt/argon2) | legacy/10yr tech-debt HIGH
    //   (MD5/SHA-1 password columns are all over decade-old schemas and homegrown auth).
    // EXAMPLE: GET /crypto/hash?password=password1
    //          -> md5 == 7c6a180b36896a0a8c02787eeafb0e4c (alice's users.password)
    // FIX: salted adaptive KDF — PBKDF2/bcrypt/scrypt/argon2 (see /crypto/reset-token-safe).
    // ========================================================================
    [HttpGet("/crypto/hash")]
    public IActionResult Hash(string password = "")
    {
        // VULNERABLE: fast, unsalted digests — the same broken scheme users.password uses.
        var md5 = Db.Md5(password);
        var sha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();
        return new JsonResult(new
        {
            password,
            md5,
            sha1,
            salted = false,
            note = "unsalted MD5/SHA-1 — identical to users.password (Db.Md5). Dump the users table and crack offline; md5('password1') matches alice."
        });
    }

    // ========================================================================
    // PERMUTATION 2 — HARD-CODED HMAC SIGNING SECRET (token forgery)
    // OWASP 2021 A02 Cryptographic Failures -> OWASP 2025 A04 Cryptographic Failures
    // CWE-798: Use of Hard-coded Credentials
    // EXPLOITATION LIKELIHOOD: HIGH — the signing key is a string literal in this
    //   source file (see header). Anyone who reads the repo/decompiles the binary
    //   recomputes HMAC-SHA256 over any payload and MINTS a valid token for any
    //   user — set user=admin and you have a deterministic privilege-escalation /
    //   auth bypass. Gated only on obtaining the (committed) key.
    // PREVALENCE TODAY: greenfield MEDIUM (Key Vault / user-secrets / env are the
    //   norm and secret scanners catch some, yet committed JWT/HMAC secrets remain
    //   one of the most common repo leaks) | legacy/10yr tech-debt HIGH (keys baked
    //   into web.config/appSettings and shared across every environment).
    // EXAMPLE: GET /crypto/token?user=admin  -> token verifiable/forgeable with the
    //          hard-coded key; re-sign "admin:<any-ts>" offline to impersonate admin.
    // FIX: load the key from a secret store (Key Vault/env), rotate it, never commit it.
    // ========================================================================
    [HttpGet("/crypto/token")]
    public IActionResult Token(string user = "")
    {
        var payload = $"{user}:{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";
        // VULNERABLE: HMAC keyed with a secret hard-coded in this file.
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(CryptoHmacKey));
        var sig = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)) + "." + Convert.ToBase64String(sig);
        return new JsonResult(new
        {
            user,
            payload,
            token,
            key = CryptoHmacKey,
            note = "signing key is a hard-coded literal — anyone with the source re-signs 'admin:<ts>' and forges an admin token"
        });
    }

    // ========================================================================
    // PERMUTATION 3 — WEAK CIPHER MODE: AES in ECB with a STATIC KEY
    // OWASP 2021 A02 Cryptographic Failures -> OWASP 2025 A04 Cryptographic Failures
    // CWE-327: Use of a Broken or Risky Cryptographic Algorithm
    // EXPLOITATION LIKELIHOOD: MEDIUM — ECB is deterministic and IV-less, so equal
    //   16-byte plaintext blocks yield IDENTICAL ciphertext blocks (the classic
    //   "ECB penguin"): it leaks structure and enables block cut-and-paste / known-
    //   plaintext manipulation without ever recovering the key. And because the key
    //   is also a hard-coded literal, /decrypt trivially reverses everything.
    // PREVALENCE TODAY: greenfield LOW (guidance/libraries default to authenticated
    //   AES-GCM; analyzers flag CipherMode.ECB) | legacy/10yr tech-debt HIGH (ECB is
    //   the "looks like the default" choice in old .NET crypto and unauthenticated
    //   CBC/ECB blobs are everywhere in tech debt).
    // EXAMPLE: GET /crypto/encrypt?text=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    //          -> two identical 16-byte plaintext blocks -> two identical hex blocks.
    //          Round-trip: GET /crypto/decrypt?data=<base64 from encrypt>
    // FIX: authenticated encryption (AES-GCM) with a random per-message nonce and a
    //      key from a KMS/secret store — never ECB, never a static hard-coded key.
    // ========================================================================
    [HttpGet("/crypto/encrypt")]
    public IActionResult Encrypt(string text = "")
    {
        using var aes = Aes.Create();
        aes.Key = CryptoAesKey;
        aes.Mode = CipherMode.ECB;        // VULNERABLE: ECB leaks plaintext block structure (no IV, deterministic)
        aes.Padding = PaddingMode.PKCS7;
        using var enc = aes.CreateEncryptor();
        var pt = Encoding.UTF8.GetBytes(text);
        var ct = enc.TransformFinalBlock(pt, 0, pt.Length);

        // Split into 16-byte blocks so the ECB structure leak is visible: repeated
        // plaintext blocks show up as repeated ciphertext blocks.
        var blocks = new List<string>();
        for (int i = 0; i < ct.Length; i += 16)
            blocks.Add(Convert.ToHexString(ct, i, Math.Min(16, ct.Length - i)).ToLowerInvariant());

        return new JsonResult(new
        {
            text,
            mode = "AES-128-ECB",
            data = Convert.ToBase64String(ct),
            hex = Convert.ToHexString(ct).ToLowerInvariant(),
            blocks,
            note = "ECB: identical plaintext blocks -> identical ciphertext blocks. Key is static/hard-coded, so /decrypt reverses it."
        });
    }

    [HttpGet("/crypto/decrypt")]
    public IActionResult Decrypt(string data = "")
    {
        try
        {
            using var aes = Aes.Create();
            aes.Key = CryptoAesKey;
            aes.Mode = CipherMode.ECB;    // VULNERABLE: same static key + ECB reverses any ciphertext
            aes.Padding = PaddingMode.PKCS7;
            using var dec = aes.CreateDecryptor();
            var ct = Convert.FromBase64String(data);
            var pt = dec.TransformFinalBlock(ct, 0, ct.Length);
            return new JsonResult(new { data, mode = "AES-128-ECB", text = Encoding.UTF8.GetString(pt) });
        }
        catch (Exception e)
        {
            return new JsonResult(new { data, error = e.Message }) { StatusCode = 400 };
        }
    }

    // ========================================================================
    // PERMUTATION 4 — INSECURE RANDOMNESS: reset token from System.Random
    // OWASP 2021 A02 Cryptographic Failures -> OWASP 2025 A04 Cryptographic Failures
    // CWE-338: Use of Cryptographically Weak PRNG
    // EXPLOITATION LIKELIHOOD: HIGH — System.Random is a fast, NON-cryptographic
    //   PRNG. Here it is seeded from the request time (unix seconds), so an attacker
    //   who triggers a reset for a victim and knows roughly WHEN simply enumerates a
    //   handful of second-granular seeds, regenerates the exact token, and takes over
    //   the account. Even the parameterless new Random() is unfit — its stream is
    //   recoverable/predictable and must never guard authentication.
    // PREVALENCE TODAY: greenfield MEDIUM (analyzer CA5394 warns, yet reaching for
    //   Random()/Guid.NewGuid() to mint "temporary" tokens is a very common slip) |
    //   legacy/10yr tech-debt HIGH (pre-CSPRNG token generators are widespread).
    // EXAMPLE: GET /crypto/reset-token?user=alice  -> token is a pure function of a
    //          time-derived seed; brute-force seeds around the request time to
    //          reproduce it and reset alice's password.
    // FIX: RandomNumberGenerator (CSPRNG) for all security tokens (see /crypto/reset-token-safe).
    // ========================================================================
    [HttpGet("/crypto/reset-token")]
    public IActionResult ResetToken(string user = "")
    {
        var seed = (int)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // VULNERABLE: non-cryptographic PRNG with a predictable (time-derived) seed.
        var rng = new Random(seed);
        var bytes = new byte[16];
        rng.NextBytes(bytes);
        var token = Convert.ToHexString(bytes).ToLowerInvariant();
        return new JsonResult(new
        {
            user,
            token,
            seed,
            csprng = false,
            note = "System.Random seeded from unix-seconds — regenerate with new Random(seed) to predict any user's reset token (account takeover)"
        });
    }

    // ========================================================================
    // SAFE REFERENCE — CSPRNG token + salted adaptive KDF. Shown so the
    // vulnerable/safe pair can be diffed by SAST tooling and by learners.
    //   (1) tokens from RandomNumberGenerator (CSPRNG) — unpredictable, no seed;
    //   (2) passwords hashed with PBKDF2 (Rfc2898DeriveBytes) — a SALTED, adaptive
    //       KDF with a random per-user salt and high iteration count (bcrypt/argon2
    //       are equally good) — the fix for P1's unsalted MD5/SHA-1;
    //   (3) contrast this with the hard-coded keys/ECB/System.Random above.
    // ========================================================================
    [HttpGet("/crypto/reset-token-safe")]
    public IActionResult ResetTokenSafe(string user = "", string password = "")
    {
        // CSPRNG token — cryptographically unpredictable, no recoverable seed.
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

        // Salted, adaptive KDF for the password (the safe replacement for P1).
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), salt,
            iterations: 210_000, HashAlgorithmName.SHA256, outputLength: 32);

        return new JsonResult(new
        {
            safe = true,
            user,
            token,
            csprng = true,
            passwordHash = new
            {
                algorithm = "PBKDF2-HMAC-SHA256",
                iterations = 210_000,
                salt = Convert.ToBase64String(salt),
                hash = Convert.ToBase64String(hash),
                salted = true
            },
            note = "RandomNumberGenerator for tokens; salted adaptive KDF (PBKDF2/bcrypt/argon2) for passwords"
        });
    }
}
