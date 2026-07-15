// Insecure Deserialization / Software & Data Integrity Failures —
// OWASP 2021 A08 Software and Data Integrity Failures -> OWASP 2025 A08 Software and Data Integrity Failures.
//
// Same annotation format and init()-based self-registration as the reference
// module (injection_sql.go): main.go auto-discovers these routes with no wiring
// changes. Go has no ObjectInputStream / pickle-style "run code on decode"
// primitive, so these demos are deliberately HONEST about impact instead of
// faking a Go RCE:
//   - gob/JSON decode of untrusted bytes gives an attacker CONTROL over which
//     concrete type is instantiated and a resource-exhaustion surface, but NOT
//     arbitrary code execution (CWE-502);
//   - a user-controlled text/template evaluated as "config" is genuine template
//     injection whose blast radius equals whatever fields/methods the data
//     context exposes — here it reaches arbitrary file read (CWE-94 / CWE-1336);
//   - decoding-and-trusting an UNSIGNED serialized token is a textbook A08
//     data-integrity failure: forge admin with one curl (CWE-345 / CWE-502).
//
// Every dangerous sink is flagged with a `VULNERABLE:` comment; the genuine
// stdlib sinks (encoding/gob, text/template.Parse+Execute, unauthenticated
// json.Unmarshal) are used UNSANITIZED so the demos are really exploitable. The
// file ends with ONE clearly-labelled SAFE handler (integrity-verified HMAC +
// fixed-struct parse with DisallowUnknownFields).
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	destemplate "text/template" // NO sandbox: methods/fields on the data context are reachable
)

func init() {
	register("POST /deserialization/native", "Insecure deserialization: gob decode of untrusted bytes into an interface (attacker-chosen type)", desNative)
	register("POST /deserialization/template", "SSTI: user-controlled text/template run as config (arbitrary file read via context method)", desTemplate)
	register("POST /deserialization/decode", "Integrity failure: decodes and TRUSTS an unsigned serialized token (forge admin)", desDecode)
	register("POST /deserialization/decode-safe", "SAFE: HMAC-verified token + fixed-struct parse (DisallowUnknownFields)", desDecodeSafe)

	// gob can only (de)serialize interface values whose concrete types are
	// registered. Registering these "gadget" types is exactly what makes them
	// reachable from an untrusted stream in PERMUTATION 1.
	gob.Register(desGreeting{})
	gob.Register(desAdminGrant{})
}

// desGadget is an interface field carried inside the wire envelope. Because the
// envelope is gob-decoded from untrusted bytes, the CLIENT decides which
// registered concrete type lands in this field server-side.
type desGadget interface{ desKind() string }

// desGreeting is the benign, "expected" payload type.
type desGreeting struct{ Name string }

func (desGreeting) desKind() string { return "greeting" }

// desAdminGrant is an INTERNAL, privileged type the public API never intended a
// caller to submit — yet gob will happily instantiate it from the stream.
type desAdminGrant struct {
	Grant bool
	Role  string
}

func (desAdminGrant) desKind() string { return "admin-grant" }

// desEnvelope is the top-level structure decoded from the untrusted stream.
type desEnvelope struct {
	Action  string
	Payload desGadget
}

// desGobExample gob-encodes an envelope and base64s it, so the handler can hand
// out ready-to-replay payloads (a binary gob stream is otherwise awkward to
// hand-craft with curl).
func desGobExample(env desEnvelope) string {
	var buf bytes.Buffer
	_ = gob.NewEncoder(&buf).Encode(env)
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// ============================================================================
// PERMUTATION 1 — native binary deserialization (encoding/gob) of untrusted input
// OWASP 2021 A08 Software and Data Integrity Failures -> OWASP 2025 A08 Software and Data Integrity Failures
// CWE-502: Deserialization of Untrusted Data
// EXPLOITATION LIKELIHOOD: MEDIUM — HONEST: Go's gob does NOT invoke methods or
//   constructors on decode, so there is no pickle/ObjectInputStream-style RCE.
//   The genuine harm is (a) TYPE CONFUSION — the attacker picks which registered
//   concrete type is instantiated, smuggling the internal privileged
//   desAdminGrant into a field meant for desGreeting — and (b) resource
//   exhaustion, since a crafted stream can declare huge slice/map lengths and
//   drive the decoder to allocate. Impactful but not arbitrary code execution.
// PREVALENCE TODAY: greenfield LOW (gob is used almost exclusively between
//   trusted Go services; decoding gob straight from an HTTP client is unusual and
//   an easy code-review flag) | legacy/10yr tech-debt MEDIUM (RPC/cache/session
//   layers that gob-encode blobs and later decode them from a client-reachable
//   channel, plus gob.Register'd interface graphs no one audits for gadget types).
// EXAMPLE:
//   # 1) get a ready-made malicious payload:
//   curl -s -X POST localhost:8081/deserialization/native      # -> example_admin_grant_b64
//   # 2) replay it — the server instantiates the privileged desAdminGrant gadget:
//   curl -X POST localhost:8081/deserialization/native -d 'data=<example_admin_grant_b64>'
//   -> {"admin_granted": true, "role": "admin", "payload_type": "main.desAdminGrant"}
// FIX: never gob-decode data crossing a trust boundary. Use a self-describing
//   format parsed into a FIXED struct, avoid interface{}/gob.Register for wire
//   types, and bound input size / nesting (see /deserialization/decode-safe).
// ============================================================================
func desNative(w http.ResponseWriter, r *http.Request) {
	data := strings.TrimSpace(r.FormValue("data"))
	if data == "" {
		writeJSON(w, 200, map[string]any{
			"usage":                   "POST data=<base64 gob of a desEnvelope>",
			"note":                    "Go gob does not run code on decode; the risk is attacker-controlled TYPE instantiation + resource exhaustion (CWE-502).",
			"example_benign_b64":      desGobExample(desEnvelope{Action: "greet", Payload: desGreeting{Name: "alice"}}),
			"example_admin_grant_b64": desGobExample(desEnvelope{Action: "grant", Payload: desAdminGrant{Grant: true, Role: "admin"}}),
		})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "base64: " + err.Error()})
		return
	}
	var env desEnvelope
	// VULNERABLE: gob-decoding untrusted bytes into an interface field lets the
	// client choose which registered concrete type the server instantiates.
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&env); err != nil {
		writeJSON(w, 400, map[string]any{"error": "gob: " + err.Error()})
		return
	}
	resp := map[string]any{
		"action":        env.Action,
		"payload_type":  fmt.Sprintf("%T", env.Payload),
		"admin_granted": false,
	}
	switch g := env.Payload.(type) {
	case desGreeting:
		resp["message"] = "hello " + g.Name
	case desAdminGrant:
		// Type confusion: an internal privileged type reached the server purely
		// because the untrusted stream selected it.
		resp["admin_granted"] = g.Grant
		resp["role"] = g.Role
		resp["effect"] = "server instantiated the privileged desAdminGrant gadget straight from untrusted bytes"
	}
	writeJSON(w, 200, resp)
}

// ============================================================================
// PERMUTATION 2 — config-as-code: user-controlled text/template evaluated
// OWASP 2021 A08 Software and Data Integrity Failures -> OWASP 2025 A08 Software and Data Integrity Failures
// CWE-94: Improper Control of Generation of Code ('Code Injection') / CWE-1336 SSTI
// EXPLOITATION LIKELIHOOD: HIGH — a template compiled from request input can read
//   any exported FIELD ({{.Secret}} exfiltrates the config key) and call any
//   METHOD on the data context. Here the context exposes .ReadFile, so
//   {{.ReadFile "data/secret.txt"}} yields arbitrary local file read with a single
//   curl. HONEST nuance: text/template itself only reaches what the context
//   exposes — no exposed side-effecting method means no RCE — but real "config
//   template" contexts routinely expose helpers, so the ceiling is high.
// PREVALENCE TODAY: greenfield LOW-MEDIUM (devs know not to Parse user input, yet
//   "let users template their notification/report/config" features keep
//   reintroducing it, and text/template is picked over html/template for non-HTML
//   output) | legacy/10yr tech-debt MEDIUM-HIGH (admin panels that render
//   user-editable email/report/config templates against a fat context object).
// EXAMPLE:
//   curl -X POST localhost:8081/deserialization/template --data-urlencode 'tpl={{.Secret}}'
//   curl -X POST localhost:8081/deserialization/template --data-urlencode 'tpl={{.ReadFile "data/secret.txt"}}'
//   -> renders the file contents (GO_TRAVERSAL_OK secret) back in the response.
// FIX: never Parse untrusted template text. If users must template, use a data
//   context with NO methods and only whitelisted primitive fields, or a logic-less
//   format (json/plain interpolation) — do not hand attacker text to a template engine.
// ============================================================================

// desTplContext is the "config" data context. It exposes a secret field and a
// file-reading method — exactly the fat context that turns SSTI into file read.
type desTplContext struct {
	Service string
	Secret  string
}

// ReadFile is reachable as {{.ReadFile "path"}} from any executed template.
func (desTplContext) ReadFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "read-error: " + err.Error()
	}
	return string(b)
}

func desTemplate(w http.ResponseWriter, r *http.Request) {
	src := r.FormValue("tpl")
	if src == "" {
		src = "service={{.Service}}  (try {{.Secret}} or {{.ReadFile \"data/secret.txt\"}})"
	}
	ctx := desTplContext{Service: "vulnapp", Secret: "s3cr3t-config-signing-key"}
	// VULNERABLE: a template is compiled from untrusted request input. Its actions
	// (field access, method calls) run against the ctx object with no sandbox.
	t, err := destemplate.New("config").Parse(src)
	if err != nil {
		writeJSON(w, 400, map[string]any{"template": src, "error": err.Error()})
		return
	}
	var out bytes.Buffer
	if err := t.Execute(&out, ctx); err != nil {
		writeJSON(w, 400, map[string]any{"template": src, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"template": src, "rendered": out.String()})
}

// ============================================================================
// PERMUTATION 3 — trusting an UNSIGNED serialized token (data-integrity failure)
// OWASP 2021 A08 Software and Data Integrity Failures -> OWASP 2025 A08 Software and Data Integrity Failures
// CWE-345: Insufficient Verification of Data Authenticity (with CWE-502)
// EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic, zero tooling. The
//   token is a base64 JSON blob whose `role` field is decoded and trusted with NO
//   signature/HMAC verification, so anyone forges {"role":"admin"} and is admin.
//   This is the canonical A08 "trust deserialized data" failure. (json.Unmarshal
//   into interface{} also makes the check type-confusable, e.g. numeric vs string.)
// PREVALENCE TODAY: greenfield MEDIUM (mature JWT libs verify by default, but
//   hand-rolled base64-JSON session cookies, `alg:none` acceptance, and "just
//   store the user object in the cookie" shortcuts still ship) | legacy/10yr
//   tech-debt HIGH (home-grown signed-cookie/session-blob schemes that either skip
//   the MAC or verify it wrong are extremely common in older codebases).
// EXAMPLE:
//   curl -X POST localhost:8081/deserialization/decode \
//     -d 'token=eyJ1c2VyIjoiYXR0YWNrZXIiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9'
//   (that base64 is {"user":"attacker","role":"admin","exp":9999999999})
//   -> {"is_admin": true, "access": "ADMIN PANEL GRANTED"}
// FIX: verify a server-side HMAC/signature over the payload BEFORE trusting it, and
//   parse into a fixed struct (see /deserialization/decode-safe).
// ============================================================================

// desToken is the token shape shared by the vulnerable and safe handlers.
type desToken struct {
	User string `json:"user"`
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
}

func desDecode(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimSpace(r.FormValue("token"))
	if tok == "" {
		forged := base64.StdEncoding.EncodeToString([]byte(`{"user":"attacker","role":"admin","exp":9999999999}`))
		writeJSON(w, 200, map[string]any{
			"usage":                      "POST token=<base64 of a JSON {user,role,exp}>",
			"note":                       "the token is trusted with NO signature check — forge any role (CWE-345/CWE-502).",
			"example_forged_admin_token": forged,
		})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(tok)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "base64: " + err.Error()})
		return
	}
	var t desToken
	// VULNERABLE: the serialized token is decoded and its role trusted as
	// authoritative with no integrity/authenticity verification whatsoever.
	if err := json.Unmarshal(raw, &t); err != nil {
		writeJSON(w, 400, map[string]any{"error": "json: " + err.Error()})
		return
	}
	admin := t.Role == "admin"
	access := "user area"
	if admin {
		access = "ADMIN PANEL GRANTED"
	}
	writeJSON(w, 200, map[string]any{"decoded": t, "is_admin": admin, "access": access})
}

// desHMACKey is the server-side secret that never leaves the process — the token
// carries only the payload and its MAC, never the key.
var desHMACKey = []byte("go-vulnapp-server-side-hmac-key")

// desSign returns the hex HMAC-SHA1 of payload under the server key.
func desSign(payload []byte) string {
	m := hmac.New(sha1.New, desHMACKey)
	m.Write(payload)
	return hex.EncodeToString(m.Sum(nil))
}

// ============================================================================
// SAFE REFERENCE — integrity-verified token + fixed-struct parse.
// Contrast with PERMUTATION 3: the token is "<base64(json)>.<hex hmac>". The MAC
// is recomputed with the server key and compared in CONSTANT time BEFORE the
// payload is trusted, so a forged/tampered token is rejected. The payload is then
// parsed into a FIXED struct with DisallowUnknownFields, so no surprise fields
// smuggle in. POST with no token to mint a valid example to test acceptance.
// ============================================================================
func desDecodeSafe(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimSpace(r.FormValue("token"))
	if tok == "" {
		payload := []byte(`{"user":"alice","role":"user","exp":9999999999}`)
		b64 := base64.StdEncoding.EncodeToString(payload)
		writeJSON(w, 200, map[string]any{
			"usage":         "POST token=<base64(json)>.<hex hmac-sha1>",
			"valid_example": b64 + "." + desSign(payload),
			"note":          "tamper with the payload and the signature check rejects it.",
		})
		return
	}
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		writeJSON(w, 400, map[string]any{"error": "expected <base64(json)>.<hex hmac>"})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "base64: " + err.Error()})
		return
	}
	// SAFE: verify authenticity FIRST with a constant-time HMAC compare; reject
	// anything that was not signed by this server.
	if !hmac.Equal([]byte(desSign(raw)), []byte(parts[1])) {
		writeJSON(w, 401, map[string]any{"error": "bad signature — token rejected (integrity check failed)"})
		return
	}
	// SAFE: parse the verified payload into a FIXED struct and reject unknown fields.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var t desToken
	if err := dec.Decode(&t); err != nil {
		writeJSON(w, 400, map[string]any{"error": "json: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"decoded": t, "is_admin": t.Role == "admin", "verified": true})
}
