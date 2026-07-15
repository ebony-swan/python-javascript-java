// Cross-Site Scripting (XSS) — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
//
// Companion to injection_sql.go: the same annotation format and init()-based
// self-registration are reused here. Every permutation writes an untrusted value
// into an HTML sink WITHOUT output encoding, so the browser parses the attacker's
// markup as code. Each dangerous sink is flagged with a `VULNERABLE:` comment and
// the file ends with ONE clearly-labelled SAFE reference handler.
//
// The genuine dangerous sink for Go here is emitting untrusted input into an HTML
// response via string concatenation / text/template (server side) or into
// `innerHTML` (client side) instead of using html/template's auto-escaping.
package main

import (
	htmltemplate "html/template" // context-aware auto-escaping (the SAFE renderer)
	"net/http"
	"strconv"
	"sync"
	texttemplate "text/template" // NO HTML escaping — the P4 footgun
)

func init() {
	register("GET /injection/xss/hello", "XSS: reflected, unescaped HTML body", xssHello)
	register("POST /injection/xss/comment", "XSS: store a comment (stored)", xssComment)
	register("GET /injection/xss/comments", "XSS: render stored comments unescaped", xssComments)
	register("GET /injection/xss/dom", "XSS: DOM-based via location.hash -> innerHTML", xssDom)
	register("GET /injection/xss/profile", "XSS: text/template (no auto-escaping)", xssProfile)
	register("GET /injection/xss/hello-safe", "SAFE: html/template auto-escaping", xssHelloSafe)
}

// xssWriteHTML sends a text/html response body (unique helper to avoid clashing
// with other modules in this single-package namespace).
func xssWriteHTML(w http.ResponseWriter, html string) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(html))
}

// ============================================================================
// PERMUTATION 1 — Reflected XSS: untrusted query param echoed into the HTML body
// OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
// CWE-79: Improper Neutralization of Input During Web Page Generation ('XSS')
// EXPLOITATION LIKELIHOOD: HIGH — reflected, deterministic and pre-auth; the only
//   friction is social-engineering the victim into opening the crafted link.
// PREVALENCE TODAY: greenfield LOW-MEDIUM (Go's html/template auto-escapes, but
//   plenty of handlers still fmt.Fprintf/concatenate HTML strings or ship
//   JSON->SPA data that gets rendered raw) | legacy/10yr tech-debt HIGH
//   (string-built HTML responses with no output encoding are the old default).
// EXAMPLE:
//   GET /injection/xss/hello?name=<script>alert(1)</script>
// FIX: render through html/template so output is entity-encoded (see /hello-safe).
// ============================================================================
func xssHello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "world"
	}
	// VULNERABLE: user input concatenated straight into the HTML body, unescaped.
	html := `<!doctype html><html><head><meta charset="utf-8"><title>Hello</title></head>` +
		`<body><h1>Hello, ` + name + `!</h1>` +
		`<p>Your <code>name</code> parameter was reflected verbatim into this page.</p>` +
		`</body></html>`
	xssWriteHTML(w, html)
}

// ============================================================================
// PERMUTATION 2 — Stored XSS: comment persisted unescaped, replayed to viewers
// OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
// CWE-79: Improper Neutralization of Input During Web Page Generation ('XSS')
// EXPLOITATION LIKELIHOOD: HIGH — the payload persists server-side and fires in
//   EVERY viewer's browser (admins included) with no per-victim link or targeting;
//   a single POST is enough. In-process slice works because the server is long-lived.
// PREVALENCE TODAY: greenfield LOW-MEDIUM (auto-escaping templates neutralize most
//   stored values, but rich-text / markdown / "allow some HTML" fields and
//   template.HTML() casts reintroduce it) | legacy/10yr tech-debt HIGH
//   (unencoded persist-then-render, sometimes of data stored years ago).
// EXAMPLE:
//   curl -X POST localhost:8081/injection/xss/comment \
//        -d 'text=<script>alert(document.cookie)</script>'
//   then open  GET /injection/xss/comments   # payload runs for every visitor
// FIX: entity-encode each comment at render time (html/template auto-escaping).
// ============================================================================
var (
	xssMu    sync.Mutex
	xssStore []string // in-process store — NOT sanitized on the way in or out.
)

func xssComment(w http.ResponseWriter, r *http.Request) {
	text := r.FormValue("text") // reads POST form body or ?text= query
	// VULNERABLE: attacker-controlled markup stored verbatim (no encoding).
	xssMu.Lock()
	xssStore = append(xssStore, text)
	n := len(xssStore)
	xssMu.Unlock()
	writeJSON(w, 200, map[string]any{"stored": text, "count": n, "view": "/injection/xss/comments"})
}

func xssComments(w http.ResponseWriter, r *http.Request) {
	xssMu.Lock()
	items := ""
	for _, c := range xssStore {
		// VULNERABLE: each stored comment concatenated into the page unescaped, so
		// a single malicious comment runs in every visitor's browser.
		items += "<li>" + c + "</li>"
	}
	n := len(xssStore)
	xssMu.Unlock()
	html := `<!doctype html><html><head><meta charset="utf-8"><title>Comments</title></head>` +
		`<body><h1>Comments (` + strconv.Itoa(n) + `)</h1><ul>` + items + `</ul></body></html>`
	xssWriteHTML(w, html)
}

// ============================================================================
// PERMUTATION 3 — DOM-based XSS: client JS copies location.hash into innerHTML
// OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
// CWE-79: Improper Neutralization of Input During Web Page Generation ('XSS')
// EXPLOITATION LIKELIHOOD: MEDIUM-HIGH — the bug is entirely client-side; a victim
//   must open a crafted #fragment link, and the fragment never leaves the browser,
//   so server-side logging/WAFs are blind to the payload. (innerHTML won't run a
//   bare <script>, but img/svg onerror handlers fire, so it's a real sink.)
// PREVALENCE TODAY: greenfield MEDIUM (framework text-binding is safe, yet
//   innerHTML / dangerouslySetInnerHTML sinks fed from location/URL still ship) |
//   legacy/10yr tech-debt HIGH (jQuery .html(location.hash), document.write and
//   hand-rolled hash routers are everywhere in old front-ends).
// EXAMPLE:
//   GET /injection/xss/dom#<img src=x onerror=alert(1)>
// FIX: use textContent/.innerText, or sanitize via a Trusted Types policy — never
//   assign untrusted data to innerHTML.
// ============================================================================
func xssDom(w http.ResponseWriter, r *http.Request) {
	// The SERVER returns a STATIC page — the payload after `#` never reaches it.
	// The flaw lives entirely in the inline client script below.
	html := `<!doctype html><html><head><meta charset="utf-8"><title>DOM XSS</title></head>
<body><h1>DOM XSS demo</h1>
<p>Put a payload after the <code>#</code>, e.g. <code>#&lt;img src=x onerror=alert(1)&gt;</code></p>
<div id="out">(reads location.hash)</div>
<script>
  var payload = decodeURIComponent(location.hash.slice(1));
  // VULNERABLE (client-side sink): URL fragment written straight into innerHTML.
  document.getElementById('out').innerHTML = payload;
</script>
</body></html>`
	xssWriteHTML(w, html)
}

// ============================================================================
// PERMUTATION 4 — XSS via disabled escaping: rendered with text/template
// OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
// CWE-79: Improper Neutralization of Input During Web Page Generation ('XSS')
// EXPLOITATION LIKELIHOOD: HIGH — reflected and deterministic. text/template does
//   NO contextual auto-escaping, so {{.Name}} is emitted raw; picking text/template
//   (or importing the wrong "template" package) is a classic Go footgun. NOTE: this
//   is XSS only — text/template does not evaluate expressions on the data value, so
//   unlike Jinja/Twig there is no SSTI->RCE escalation here. Be honest: no RCE.
// PREVALENCE TODAY: greenfield MEDIUM (html/template is the safe default, but
//   text/template legitimately builds email/reports/config and gets reused for HTML;
//   gosec/CodeQL flag it) | legacy/10yr tech-debt MEDIUM-HIGH (old handlers that
//   render HTML through text/template or template.HTML() casts).
// EXAMPLE:
//   GET /injection/xss/profile?name=<script>alert(1)</script>
// FIX: render HTML with html/template (contextual auto-escaping) — see /hello-safe.
// ============================================================================
var xssProfileTmpl = texttemplate.Must(texttemplate.New("profile").Parse(
	`<!doctype html><html><head><meta charset="utf-8"><title>Profile</title></head>` +
		`<body><h1>Profile of {{.Name}}</h1>` +
		`<p>Rendered with <code>text/template</code>, which does NO contextual ` +
		`auto-escaping (html/template would have entity-encoded this).</p>` +
		`</body></html>`))

func xssProfile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "guest"
	}
	w.Header().Set("Content-Type", "text/html")
	// VULNERABLE: text/template emits {{.Name}} raw — no HTML escaping at all.
	_ = xssProfileTmpl.Execute(w, map[string]string{"Name": name})
}

// ============================================================================
// SAFE REFERENCE — render untrusted output through html/template. Its contextual
// auto-escaping entity-encodes < > & " ' and adapts per output context, so the
// same payload stays inert in BOTH the element body and the quoted attribute
// below. Shown so the vulnerable/safe pair diffs cleanly for SAST and learners.
// ============================================================================
var xssSafeTmpl = htmltemplate.Must(htmltemplate.New("hello-safe").Parse(
	`<!doctype html><html><head><meta charset="utf-8"><title>Hello (safe)</title></head>` +
		`<body><h1>Hello, {{.Name}}!</h1>` +
		`<form><label>Name: <input name="name" value="{{.Name}}"></label></form>` +
		`<p>(escaped output — the payload is inert in body and attribute contexts)</p>` +
		`</body></html>`))

func xssHelloSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "world"
	}
	w.Header().Set("Content-Type", "text/html")
	// SAFE: html/template auto-escapes {{.Name}} contextually before it hits HTML.
	_ = xssSafeTmpl.Execute(w, map[string]string{"Name": name})
}
