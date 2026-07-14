package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

/**
 * Cryptographic Failures — OWASP 2021 A02 | OWASP 2025 A04.
 *
 * Comment/annotation format mirrors {@link SqlInjectionController} (the reference
 * module): every permutation carries a standard header describing the flaw, its
 * CWE, an exploitation-likelihood rating, prevalence, an example request, and the
 * corresponding safe pattern. The dangerous line in each handler is tagged with a
 * "VULNERABLE:" inline comment. The file ends with ONE labelled SAFE handler.
 *
 * NOTE (P2/P3): the secrets below are HARD-CODED literals in source ON PURPOSE.
 *   P2 HMAC signing key : "s3cr3t-hardcoded-signing-key-42"   <-- CWE-798 anti-pattern
 *   P3 AES/ECB key      : "0123456789abcdef" (16 bytes)       <-- CWE-321 anti-pattern
 * Anyone with read access to this source (open repo, decompiled JAR, leaked
 * artifact) can forge P2 tokens and decrypt P3 ciphertext for every user.
 */
@RestController
@RequestMapping("/crypto")
public class CryptoController {

    // Hard-coded secrets — DELIBERATELY unsafe (see class javadoc). Real apps must
    // source these from a secrets manager / KMS / env, never a source literal.
    private static final String HARDCODED_HMAC_KEY = "s3cr3t-hardcoded-signing-key-42"; // CWE-798
    private static final byte[] STATIC_AES_KEY =
            "0123456789abcdef".getBytes(StandardCharsets.UTF_8); // CWE-321, 128-bit, static

    // ========================================================================
    // PERMUTATION 1 — Weak, unsalted password hashing (MD5 + SHA-1)
    // OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
    // CWE-916: Use of Password Hash With Insufficient Computational Effort (also CWE-327)
    // EXPLOITATION LIKELIHOOD: MEDIUM — needs the stored hash first (post-DB-leak),
    //   but MD5/SHA-1 are unsalted and GPU/rainbow-table crackable in seconds, so
    //   any breach = instant plaintext recovery. Mirrors the users.password column.
    // PREVALENCE TODAY: greenfield LOW (Spring Security's DelegatingPasswordEncoder
    //   defaults to bcrypt; argon2/scrypt are the norm) | legacy/10yr tech-debt HIGH
    //   (MD5/SHA-1 password columns are everywhere and painful to migrate in place).
    // EXAMPLE:
    //   GET /crypto/hash?password=password1
    //   -> md5 = 7c6a180b36896a0a8c02787eeafb0e4c  (identical to alice's stored hash)
    // FIX: use an adaptive salted KDF (bcrypt/scrypt/argon2/PBKDF2) — see /crypto/hash-safe.
    // ========================================================================
    @GetMapping("/hash")
    public Map<String, Object> weakHash(@RequestParam(defaultValue = "") String password) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("password", password);
        try {
            // VULNERABLE: fast, unsalted general-purpose digests used for passwords.
            out.put("md5", toHex(MessageDigest.getInstance("MD5")
                    .digest(password.getBytes(StandardCharsets.UTF_8))));
            out.put("sha1", toHex(MessageDigest.getInstance("SHA-1")
                    .digest(password.getBytes(StandardCharsets.UTF_8))));
            out.put("scheme", "MD5/SHA-1, UNSALTED — same scheme as the users table");
            out.put("note", "Rainbow-table / brute-force trivial: reversible in seconds.");
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return out;
    }

    // ========================================================================
    // PERMUTATION 2 — Token signed with a HARD-CODED secret key
    // OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
    // CWE-798: Use of Hard-coded Credentials (also CWE-321 Hard-coded Cryptographic Key)
    // EXPLOITATION LIKELIHOOD: HIGH — the HMAC key is a source literal. Anyone who
    //   reads the repo / decompiles the JAR forges a valid token for ANY user
    //   (e.g. user=admin), pre-auth, deterministically, with no cracking needed.
    // PREVALENCE TODAY: greenfield MEDIUM (vaults/env vars are common, but keys still
    //   get committed and are caught only if secret-scanning/SAST is wired up) |
    //   legacy/10yr tech-debt HIGH (baked-in signing keys are a classic in old code).
    // EXAMPLE:
    //   GET /crypto/token?user=admin
    //   -> attacker with the source recomputes HMAC-SHA256(key, "admin") offline
    //      and mints an admin token; the server accepts its own forgeable signature.
    // FIX: load the key from a KMS/secrets manager, rotate it, and keep it out of source.
    // ========================================================================
    @GetMapping("/token")
    public Map<String, Object> signToken(@RequestParam(defaultValue = "guest") String user) {
        Map<String, Object> out = new LinkedHashMap<>();
        String payload = "user=" + user + ";iat=fixed";
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            // VULNERABLE: signing key is a hard-coded literal shipped in the source.
            mac.init(new SecretKeySpec(HARDCODED_HMAC_KEY.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"));
            String sig = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
            String token = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + sig;
            out.put("payload", payload);
            out.put("token", token);
            out.put("signing_key", HARDCODED_HMAC_KEY); // echoed to show it is knowable
            out.put("note", "Key is in source -> anyone can forge a token for any user.");
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return out;
    }

    // ========================================================================
    // PERMUTATION 3 — Weak cipher/mode: AES/ECB with a STATIC hard-coded key
    // OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
    // CWE-327: Use of a Broken or Risky Cryptographic Algorithm (mode) (also CWE-321)
    // EXPLOITATION LIKELIHOOD: MEDIUM — ECB is deterministic and unauthenticated:
    //   identical 16-byte plaintext blocks yield identical ciphertext blocks
    //   (structure leak, cut-and-paste tampering), and the static key is in source
    //   so anyone can decrypt outright. No random/authenticated IV, no integrity.
    // PREVALENCE TODAY: greenfield MEDIUM (Java's Cipher.getInstance("AES") silently
    //   DEFAULTS to ECB — a famous footgun that still ships) | legacy/10yr tech-debt
    //   HIGH (DES/3DES and AES-ECB with fixed keys are endemic in old systems).
    // EXAMPLE:
    //   GET /crypto/encrypt?text=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA   (32 'A' = two blocks)
    //     -> ciphertext_hex's first two 16-byte blocks are IDENTICAL (structure leak).
    //   GET /crypto/decrypt?data=<base64>   (recovers plaintext with the static key)
    // FIX: use an authenticated cipher with a random nonce (AES-GCM) and a managed key.
    // ========================================================================
    @GetMapping("/encrypt")
    public Map<String, Object> encrypt(@RequestParam(defaultValue = "") String text) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("plaintext", text);
        try {
            // VULNERABLE: ECB mode + static key + no IV. Leaks plaintext structure.
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(STATIC_AES_KEY, "AES"));
            byte[] ct = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
            out.put("algorithm", "AES/ECB/PKCS5Padding (static key, no IV)");
            out.put("ciphertext_b64", Base64.getEncoder().encodeToString(ct));
            out.put("ciphertext_hex", toHex(ct));
            out.put("note", "ECB: identical plaintext blocks -> identical ciphertext blocks.");
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return out;
    }

    @GetMapping("/decrypt")
    public Map<String, Object> decrypt(@RequestParam(defaultValue = "") String data) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ciphertext_b64", data);
        try {
            // VULNERABLE: same static key decrypts anything encrypted by /crypto/encrypt.
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(STATIC_AES_KEY, "AES"));
            byte[] pt = cipher.doFinal(Base64.getDecoder().decode(data));
            out.put("plaintext", new String(pt, StandardCharsets.UTF_8));
            out.put("note", "Recovered with the hard-coded key baked into the source.");
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return out;
    }

    // ========================================================================
    // PERMUTATION 4 — Insecure randomness for a reset token (java.util.Random)
    // OWASP 2021 A02 Cryptographic Failures  ->  OWASP 2025 A04 Cryptographic Failures
    // CWE-338: Use of Cryptographically Weak PRNG (also CWE-330 Insufficient Randomness)
    // EXPLOITATION LIKELIHOOD: HIGH — java.util.Random is a 48-bit LCG seeded from the
    //   clock. An attacker requests a reset for their own account, learns the server
    //   time, brute-forces the narrow seed window, and reproduces the victim's token
    //   -> account takeover, pre-auth. The generator is fully predictable, not secret.
    // PREVALENCE TODAY: greenfield MEDIUM (SecureRandom is well known, yet Random/
    //   Math.random slips into token/OTP/nonce code) | legacy/10yr tech-debt HIGH
    //   (hand-rolled token generators on java.util.Random are a persistent classic).
    // EXAMPLE:
    //   GET /crypto/reset-token?user=alice
    //   -> response echoes the seed; anyone can `new Random(seed).nextBytes(...)`
    //      to regenerate the exact same token and hijack the reset flow.
    // FIX: use SecureRandom (CSPRNG) for all tokens — see /crypto/reset-token-safe.
    // ========================================================================
    @GetMapping("/reset-token")
    public Map<String, Object> resetToken(@RequestParam(defaultValue = "guest") String user) {
        Map<String, Object> out = new LinkedHashMap<>();
        long seed = System.currentTimeMillis();
        // VULNERABLE: non-cryptographic, clock-seeded LCG used for a security token.
        Random weak = new Random(seed);
        byte[] tok = new byte[16];
        weak.nextBytes(tok);
        out.put("user", user);
        out.put("reset_token", toHex(tok));
        out.put("seed", seed);       // echoed to show the token is fully reproducible
        out.put("prng", "java.util.Random (48-bit LCG) — predictable, NOT a CSPRNG");
        out.put("note", "Reproduce: new Random(seed).nextBytes(new byte[16]) -> same token.");
        return out;
    }

    // ========================================================================
    // SAFE REFERENCE — the correct approach for all four permutations.
    //   * Token/salt entropy from a CSPRNG (java.security.SecureRandom).
    //   * Password hashing with a salted, adaptive KDF (PBKDF2-HMAC-SHA256).
    //   * (Encryption should use AES-GCM with a random 96-bit nonce and a managed
    //      key — never ECB, never a source-literal key.)
    // Shown so the vulnerable/safe pair can be diffed by learners and SAST tooling.
    // ========================================================================
    @GetMapping("/reset-token-safe")
    public Map<String, Object> resetTokenSafe(@RequestParam(defaultValue = "guest") String user,
                                              @RequestParam(defaultValue = "") String password) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            // SAFE: cryptographically secure RNG for the unguessable reset token.
            SecureRandom csprng = new SecureRandom();
            byte[] tok = new byte[32];
            csprng.nextBytes(tok);
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tok);

            // SAFE: salted, high-iteration PBKDF2 instead of raw MD5/SHA-1.
            byte[] salt = new byte[16];
            csprng.nextBytes(salt);
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(), salt, 210_000, 256);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] dk = skf.generateSecret(spec).getEncoded();

            out.put("user", user);
            out.put("reset_token", token);
            out.put("prng", "java.security.SecureRandom (CSPRNG) — unpredictable, no seed leak");
            out.put("password_kdf", "PBKDF2WithHmacSHA256, 210000 iters, per-user random salt");
            out.put("salt_b64", Base64.getEncoder().encodeToString(salt));
            out.put("derived_key_hex", toHex(dk));
            out.put("note", "Key/secret material would live in a KMS/secrets manager, not in source.");
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return out;
    }

    // Small hex helper (kept local so this module needs no extra dependencies).
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
