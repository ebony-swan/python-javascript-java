// Cryptographic Failures — OWASP 2021 A02 Cryptographic Failures | OWASP 2025 A04 Cryptographic Failures.
//
// Companion to injection_sql.go: the same annotation format and init()-based
// self-registration are reused here. Every permutation uses a genuinely broken
// cryptographic primitive — unsalted fast hashes, a hard-coded HMAC key, AES in
// ECB mode under a static key, and a non-cryptographic (predictable) RNG — with
// no mitigation, so each demo is really exploitable. Each dangerous sink is
// flagged with a `VULNERABLE:` comment and the file ends with ONE clearly-
// labelled SAFE reference handler (crypto/rand CSPRNG + a note on salted KDFs).
//
// The genuine dangerous sinks for Go here are: crypto/md5 + crypto/sha1 without
// a salt (same scheme as users.password), an hmac key that is a source literal,
// crypto/aes driven block-by-block in ECB mode with a compiled-in key, and
// math/rand (a deterministic PRNG) used to mint security tokens.
package main

import (
	"crypto/aes"
	"crypto/hmac"
	crand "crypto/rand" // CSPRNG — used only by the SAFE handler
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand" // NON-cryptographic PRNG — the P4 footgun
	"net/http"
	"time"
)

func init() {
	register("GET /crypto/hash", "weak hash: unsalted MD5 + SHA-1 (CWE-916)", cryptoHash)
	register("GET /crypto/token", "hard-coded HMAC key: forgeable token (CWE-798)", cryptoToken)
	register("GET /crypto/encrypt", "weak cipher: AES-ECB, static key (CWE-327)", cryptoEncrypt)
	register("GET /crypto/decrypt", "weak cipher: AES-ECB decrypt (static key)", cryptoDecrypt)
	register("GET /crypto/reset-token", "insecure RNG: math/rand token (CWE-338)", cryptoResetToken)
	register("GET /crypto/reset-token-safe", "SAFE: crypto/rand CSPRNG + salted KDF note", cryptoResetTokenSafe)
}

// ============================================================================
// PERMUTATION 1 — Weak password hashing: unsalted, fast MD5 + SHA-1
// OWASP 2021 A02 Cryptographic Failures -> OWASP 2025 A04 Cryptographic Failures
// CWE-916: Use of Password Hash With Insufficient Computational Effort
// EXPLOITATION LIKELIHOOD: HIGH — once a hash leaks (e.g. via the SQLi UNION
//   demo that dumps users.password), unsalted MD5/SHA-1 are recovered almost
//   instantly: precomputed rainbow tables for common values and billions of
//   GPU guesses/sec for the rest. It is offline/post-leak (not a standalone
//   pre-auth break), but recovery of weak-to-moderate passwords is a near
//   certainty, so the confidentiality impact rates HIGH.
// PREVALENCE TODAY: greenfield LOW (Django/Rails/Laravel/Spring Security all
//   default to a salted adaptive KDF — bcrypt/argon2/PBKDF2 — so a new app has to
//   go out of its way to hash with MD5) | legacy/10yr tech-debt HIGH (unsalted
//   MD5/SHA-1 password columns are the archetypal debt; you cannot re-hash without
//   the plaintext, so they survive migration after migration).
// EXAMPLE: GET /crypto/hash?password=password1
//   -> md5=7c6a180b36896a0a8c02787eeafb0e4c  (cracks instantly in any wordlist)
// FIX: hash with a salted adaptive KDF (bcrypt/scrypt/argon2id); never MD5/SHA-1.
// ============================================================================
func cryptoHash(w http.ResponseWriter, r *http.Request) {
	password := r.URL.Query().Get("password")
	if password == "" {
		password = "password1"
	}
	// VULNERABLE: fast, UNSALTED digests — identical to users.password, so a
	// leaked hash is reversed with rainbow tables / GPU brute force.
	md5sum := md5hex(password) // reuses the lab's md5 helper (crypto/md5)
	shaRaw := sha1.Sum([]byte(password))
	sha1sum := hex.EncodeToString(shaRaw[:])
	writeJSON(w, 200, map[string]any{
		"password": password,
		"md5":      md5sum,
		"sha1":     sha1sum,
		"salted":   false,
		"scheme":   "unsalted MD5 (same as users.password)",
		"note":     "no salt + fast hash => rainbow-table / GPU crackable; use bcrypt/argon2id",
	})
}

// ============================================================================
// PERMUTATION 2 — Hard-coded signing secret: token HMAC'd with a source literal
// OWASP 2021 A02 Cryptographic Failures -> OWASP 2025 A04 Cryptographic Failures
// CWE-798: Use of Hard-coded Credentials
// EXPLOITATION LIKELIHOOD: HIGH — the HMAC key is a compiled-in string literal
//   (see cryptoHMACKey below). Anyone who can read the source — public repo,
//   leaked tarball, decompiled binary, or this endpoint's own echo — recomputes a
//   valid signature for ANY user, including admin, and forges an auth token.
//   Deterministic, no tooling, full authentication bypass.
// PREVALENCE TODAY: greenfield MEDIUM (secrets managers / env injection are the
//   norm, yet hard-coded JWT/HMAC secrets still land in commits constantly — it is
//   one of the most common secret-scanner hits) | legacy/10yr tech-debt HIGH
//   (keys embedded in source and config are endemic; rotating a shared signing key
//   invalidates every issued token, so teams leave it in place for years).
// EXAMPLE: GET /crypto/token?user=admin
//   -> returns a token an attacker can also compute offline from the leaked key,
//      minting an admin session without ever knowing admin's password.
// FIX: load the key from a secret manager / env var, rotate it, and never commit
//   it; treat any key that reaches source control as compromised.
// ============================================================================
//
// VULNERABLE (CWE-798): signing key is a hard-coded literal — the bad key is
// visible right here in the source. Anyone reading the repo forges valid tokens.
var cryptoHMACKey = []byte("s3cr3t-signing-key-do-not-ship-2015") // VULNERABLE: hard-coded secret

func cryptoToken(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		user = "alice"
	}
	// VULNERABLE: token signed with the compiled-in key above; forgeable by anyone
	// who has the source (or this response, which echoes the key for the demo).
	mac := hmac.New(sha1.New, cryptoHMACKey)
	mac.Write([]byte(user))
	sig := mac.Sum(nil)
	token := base64.RawURLEncoding.EncodeToString([]byte(user)) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
	writeJSON(w, 200, map[string]any{
		"user":  user,
		"token": token,
		"alg":   "HMAC-SHA1",
		"key":   string(cryptoHMACKey), // hard-coded in source — shown to prove forgeability
		"note":  "key is a source-code literal; re-sign user=admin with the same key to forge an admin token",
	})
}

// ============================================================================
// PERMUTATION 3 — Weak cipher mode: AES in ECB under a static hard-coded key
// OWASP 2021 A02 Cryptographic Failures -> OWASP 2025 A04 Cryptographic Failures
// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// EXPLOITATION LIKELIHOOD: HIGH — two compounding flaws. (1) ECB encrypts every
//   16-byte block independently, so identical plaintext blocks yield identical
//   ciphertext blocks: structure leaks and blocks can be cut/pasted/rearranged
//   without the key. (2) The key is a compiled-in literal, so anyone with the
//   source (or the matching /crypto/decrypt route) simply decrypts everything.
//   No IV, no authentication (no MAC) => ciphertexts are also malleable.
// PREVALENCE TODAY: greenfield LOW (modern crypto libraries steer you to AEAD —
//   AES-GCM / ChaCha20-Poly1305 — with a random nonce, and linters flag ECB and
//   static keys) | legacy/10yr tech-debt HIGH (ECB is the historical "just call
//   AES" default because it needs no IV, and a hard-coded key beside it is common
//   in old code that had to encrypt without any key-management story).
// EXAMPLE: GET /crypto/encrypt?text=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
//   -> the two identical 16-byte input blocks encrypt to the SAME ciphertext
//      block (see "blocks" in the response) — the ECB tell. Feed the hex to
//      GET /crypto/decrypt?data=... to recover the plaintext with no key knowledge.
// FIX: use an authenticated mode with a random nonce (crypto/cipher AES-GCM) and a
//   key from a KMS/secret store — never ECB, never a static compiled-in key.
// ============================================================================
//
// VULNERABLE (CWE-798 alongside CWE-327): the AES key is a static source literal.
var cryptoAESKey = []byte("static-demo-key!") // 16 bytes = AES-128; VULNERABLE: hard-coded

// cryptoPKCS7Pad pads data to a whole number of blocks (PKCS#7).
func cryptoPKCS7Pad(data []byte, blockSize int) []byte {
	n := blockSize - (len(data) % blockSize)
	pad := make([]byte, n)
	for i := range pad {
		pad[i] = byte(n)
	}
	return append(data, pad...)
}

// cryptoPKCS7Unpad removes PKCS#7 padding, rejecting malformed input.
func cryptoPKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("data is not a whole number of blocks")
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize || n > len(data) {
		return nil, fmt.Errorf("invalid PKCS#7 padding")
	}
	return data[:len(data)-n], nil
}

// cryptoECBEncrypt encrypts plaintext with AES in ECB mode under the static key.
func cryptoECBEncrypt(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(cryptoAESKey)
	if err != nil {
		return nil, err
	}
	padded := cryptoPKCS7Pad(plain, aes.BlockSize)
	out := make([]byte, len(padded))
	// VULNERABLE: ECB — each block encrypted independently with no IV/chaining, so
	// equal plaintext blocks produce equal ciphertext blocks (structure leak).
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return out, nil
}

// cryptoECBDecrypt reverses cryptoECBEncrypt (matching /crypto/decrypt).
func cryptoECBDecrypt(ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(cryptoAESKey)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the AES block size")
	}
	out := make([]byte, len(ct))
	// VULNERABLE: ECB decrypt, block by block, static key — no authenticity check.
	for i := 0; i < len(ct); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], ct[i:i+aes.BlockSize])
	}
	return cryptoPKCS7Unpad(out, aes.BlockSize)
}

func cryptoEncrypt(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("text")
	if text == "" {
		// Default shows the ECB tell: 32 'A's = two identical 16-byte blocks.
		text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	ct, err := cryptoECBEncrypt([]byte(text))
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// Split ciphertext into per-block hex to make the ECB structure leak visible:
	// repeated plaintext blocks show up as repeated ciphertext blocks here.
	blocks := []string{}
	for i := 0; i < len(ct); i += aes.BlockSize {
		blocks = append(blocks, hex.EncodeToString(ct[i:i+aes.BlockSize]))
	}
	ctHex := hex.EncodeToString(ct)
	writeJSON(w, 200, map[string]any{
		"mode":           "AES-128-ECB",
		"key":            string(cryptoAESKey), // static, compiled-in — echoed to prove the point
		"plaintext":      text,
		"ciphertext_hex": ctHex,
		"blocks":         blocks,
		"note":           "identical plaintext blocks -> identical ciphertext blocks (ECB tell); no IV, no MAC",
		"decrypt":        "/crypto/decrypt?data=" + ctHex,
	})
}

func cryptoDecrypt(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	raw, err := hex.DecodeString(data)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "data must be hex: " + err.Error()})
		return
	}
	pt, err := cryptoECBDecrypt(raw)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{
		"mode":           "AES-128-ECB",
		"key":            string(cryptoAESKey),
		"ciphertext_hex": data,
		"plaintext":      string(pt),
		"note":           "recovered with the compiled-in static key — no secret needed beyond the source",
	})
}

// ============================================================================
// PERMUTATION 4 — Insecure randomness: reset token from a non-crypto PRNG
// OWASP 2021 A02 Cryptographic Failures -> OWASP 2025 A04 Cryptographic Failures
// CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
// EXPLOITATION LIKELIHOOD: HIGH — math/rand is a deterministic PRNG, and here it
//   is seeded with time.Now().Unix() (one-second granularity). An attacker who
//   triggers a password reset and knows the request second re-seeds an identical
//   generator and reproduces the token bit-for-bit -> pre-auth account takeover.
//   Deterministic, no victim interaction, only a coarse timestamp needed.
// PREVALENCE TODAY: greenfield MEDIUM (crypto/rand is well documented, but math/
//   rand is the tempting default for anything "random" and Go's two same-named
//   rand packages are a notorious footgun for tokens/OTPs/IDs) | legacy/10yr
//   tech-debt HIGH (time-seeded PRNG tokens for sessions, resets and coupons are a
//   classic finding in older code).
// EXAMPLE: GET /crypto/reset-token?user=admin
//   -> reset_token + the exact seed are returned; re-seeding math/rand with that
//      Unix second regenerates the same token, so the reset link is forgeable.
// FIX: mint tokens from a CSPRNG (crypto/rand) — see /crypto/reset-token-safe.
// ============================================================================
func cryptoResetToken(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		user = "alice"
	}
	seed := time.Now().Unix()
	// VULNERABLE: non-cryptographic PRNG seeded with a guessable value (the current
	// second). Given the seed, every byte below is reproducible => predictable token.
	cryptoRng := rand.New(rand.NewSource(seed))
	buf := make([]byte, 16)
	_, _ = cryptoRng.Read(buf)
	token := hex.EncodeToString(buf)
	writeJSON(w, 200, map[string]any{
		"user":        user,
		"reset_token": token,
		"rng":         "math/rand (NOT cryptographic)",
		"seed":        seed,
		"note":        "seeded with time.Now().Unix(); re-seed math/rand with this second to regenerate the token -> account takeover",
	})
}

// ============================================================================
// SAFE REFERENCE — CSPRNG token generation, plus the correct password-storage
// note. Uses crypto/rand (a cryptographically secure, unseedable RNG) to mint an
// unpredictable 256-bit token, and documents that PASSWORDS must be stored with a
// salted adaptive KDF (bcrypt/scrypt/argon2id), never the unsalted MD5/SHA-1 of
// P1. Shown so the vulnerable/safe pair diffs cleanly for SAST tools and learners.
// (bcrypt/argon2 live in golang.org/x/crypto, outside stdlib, so they are noted
// rather than imported here — no new module dependency is added.)
// ============================================================================
func cryptoResetTokenSafe(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		user = "alice"
	}
	buf := make([]byte, 32) // 256 bits
	// SAFE: crypto/rand is a CSPRNG — output is unpredictable and cannot be
	// reproduced from a seed, unlike math/rand.
	if _, err := crand.Read(buf); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	token := hex.EncodeToString(buf)
	writeJSON(w, 200, map[string]any{
		"user":        user,
		"reset_token": token,
		"rng":         "crypto/rand (CSPRNG)",
		"note":        "unpredictable 256-bit token; store PASSWORDS with a salted adaptive KDF (bcrypt/scrypt/argon2id), and encrypt with AES-GCM, never MD5/SHA-1 or ECB",
	})
}
