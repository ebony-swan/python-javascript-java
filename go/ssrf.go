// Server-Side Request Forgery (SSRF) —
// OWASP 2021 A10 Server-Side Request Forgery -> folded into OWASP 2025 A01 Broken Access Control.
//
// The server is tricked into making HTTP requests to attacker-chosen targets:
// internal-only services, the cloud metadata endpoint
// (http://169.254.169.254/latest/meta-data/), admin panels bound to loopback,
// etc. Mirrors the annotation format and init()-based registration used by the
// SQL-injection reference module.
package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func init() {
	register("GET /ssrf/fetch", "SSRF: fetch user-supplied URL, no allow-list (full-read)", ssrfFetch)
	register("POST /ssrf/webhook", "SSRF: blind/internal callback to user-supplied URL", ssrfWebhook)
	register("GET /ssrf/preview", "SSRF: naive localhost/127.0.0.1 blocklist (bypassable)", ssrfPreview)
	register("GET /ssrf/fetch-safe", "SAFE: scheme+host allow-list, block private/link-local", ssrfFetchSafe)
}

// ssrfClient is the short-timeout client shared by the vulnerable handlers so
// the demo never hangs when a target is unreachable. Note the deliberate lack
// of any dialer control that would block internal/link-local addresses.
var ssrfClient = &http.Client{Timeout: 3 * time.Second}

// ssrfSnippet reads at most n bytes of a response body — enough to prove the
// server reached (and read) an internal resource, which is what makes a
// "full-read" SSRF so much worse than a blind one.
func ssrfSnippet(r io.Reader, n int64) string {
	b, _ := io.ReadAll(io.LimitReader(r, n))
	return string(b)
}

// ============================================================================
// PERMUTATION 1 — fetch a user-supplied URL with no allow-list (full-read SSRF)
// OWASP 2021 A10 Server-Side Request Forgery -> folded into OWASP 2025 A01 Broken Access Control
// CWE-918: Server-Side Request Forgery (SSRF)
// EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic, no tooling; the raw
//   URL is fetched and the response BODY is returned, so the attacker reads
//   internal services and (in cloud/IMDSv1) steals metadata credentials.
// PREVALENCE TODAY: greenfield MEDIUM (no framework/ORM equivalent makes URL
//   fetching safe-by-default — every "import from URL"/image-proxy/PDF/preview
//   feature is hand-rolled; awareness + IMDSv2 + egress rules cut impact) |
//   legacy/10yr tech-debt HIGH (URL-fetch features accreted, flat networks,
//   IMDSv1 still enabled).
// EXAMPLE: GET /ssrf/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
//   Self-contained proof: GET /ssrf/fetch?url=http://127.0.0.1:8081/injection/sql/notes
// FIX: allow-list scheme+host, resolve the host and reject private/link-local
//   IPs, pin the validated IP into the dialer (see /ssrf/fetch-safe).
// ============================================================================
func ssrfFetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// VULNERABLE: the server issues a GET to a fully attacker-controlled URL.
	resp, err := ssrfClient.Get(target)
	if err != nil {
		writeJSON(w, 502, map[string]any{"url": target, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	writeJSON(w, 200, map[string]any{
		"url":     target,
		"status":  resp.StatusCode,
		"snippet": ssrfSnippet(resp.Body, 1024),
	})
}

// ============================================================================
// PERMUTATION 2 — blind/internal SSRF via a user-supplied webhook/callback URL
// OWASP 2021 A10 Server-Side Request Forgery -> folded into OWASP 2025 A01 Broken Access Control
// CWE-918: Server-Side Request Forgery (SSRF)
// EXPLOITATION LIKELIHOOD: MEDIUM — blind (the response body is NOT returned),
//   yet the callback still reaches internal-only hosts: fire mutating internal
//   endpoints, port-scan the LAN via connect/timeout differences, and hit the
//   metadata service (http://169.254.169.254/latest/meta-data/). No auth here.
// PREVALENCE TODAY: greenfield HIGH (webhooks/callbacks are ubiquitous and
//   still shipped without egress allow-lists even in new code) | legacy/10yr
//   tech-debt HIGH (integration callbacks everywhere, none SSRF-guarded).
// EXAMPLE: curl -X POST localhost:8081/ssrf/webhook -d 'url=http://169.254.169.254/latest/meta-data/'
//   or JSON: curl -X POST -H 'Content-Type: application/json' \
//            localhost:8081/ssrf/webhook -d '{"url":"http://127.0.0.1:8081/crypto/hash"}'
// FIX: allow-list callback hosts, resolve+block private ranges, send through an
//   egress proxy that cannot route to RFC1918/link-local (see /ssrf/fetch-safe).
// ============================================================================
func ssrfWebhook(w http.ResponseWriter, r *http.Request) {
	var target string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			URL string `json:"url"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		target = body.URL
	} else {
		target = r.FormValue("url")
	}
	// VULNERABLE: server POSTs to an attacker-supplied callback with no filtering.
	resp, err := ssrfClient.Post(target, "application/json", strings.NewReader(`{"event":"ping"}`))
	if err != nil {
		writeJSON(w, 502, map[string]any{"callback": target, "delivered": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	// Blind by design: we return only that the callback was reachable and its
	// status code — never the body — mirroring a real fire-and-forget webhook.
	writeJSON(w, 200, map[string]any{
		"callback":  target,
		"delivered": true,
		"status":    resp.StatusCode,
		"note":      "response body intentionally not returned (blind SSRF)",
	})
}

// ============================================================================
// PERMUTATION 3 — SSRF behind a naive, bypassable substring blocklist
// OWASP 2021 A10 Server-Side Request Forgery -> folded into OWASP 2025 A01 Broken Access Control
// CWE-918: Server-Side Request Forgery (SSRF)
// EXPLOITATION LIKELIHOOD: HIGH — the blocklist only rejects the substrings
//   "localhost"/"127.0.0.1", which does not constrain the resolved address; a
//   loopback/metadata target that spells its host differently sails through and
//   the body is returned (full-read again).
// PREVALENCE TODAY: greenfield MEDIUM (the reflex to blocklist "localhost" is
//   common; SAST/review sometimes catch it) | legacy/10yr tech-debt HIGH
//   (blocklists bolted on after a pentest, never covering IPv6/DNS/alt-encodings).
// EXAMPLE (both connect to loopback over IPv4, no substring match):
//     GET /ssrf/preview?url=http://0.0.0.0:8081/injection/sql/notes   (kernel routes 0.0.0.0 -> localhost)
//     GET /ssrf/preview?url=http://LOCALHOST:8081/injection/sql/notes (case defeats a case-sensitive Contains)
//   More blocklist bypasses (host resolves to loopback without the substring):
//     http://[::1]:8081/...               (IPv6 loopback — where an IPv6 stack is enabled)
//     http://127-0-0-1.nip.io             (nip.io dashed form — DNS -> 127.0.0.1)
//     http://0177.0.0.1  http://2130706433  (octal / decimal — glibc inet_aton;
//       these DO work in PHP/curl/C#/cgo but NOT Go's pure-Go resolver, which
//       rejects the literals and falls through to a failing DNS lookup)
//   The literal http://127.0.0.1.nip.io is BLOCKED here because it still
//   contains the "127.0.0.1" substring — which is exactly why substring
//   blocklists are the wrong control.
// FIX: never blocklist strings; allow-list host, resolve, reject private/
//   link-local IPs, and pin the resolved IP (see /ssrf/fetch-safe).
// ============================================================================
func ssrfPreview(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// Naive, easily bypassed denylist (substring match only).
	if strings.Contains(target, "localhost") || strings.Contains(target, "127.0.0.1") {
		writeJSON(w, 400, map[string]any{"url": target, "error": "blocked: internal address"})
		return
	}
	// VULNERABLE: the substring check does not constrain the address actually
	// dialed, so [::1]/octal/decimal/DNS forms of loopback are still fetched.
	resp, err := ssrfClient.Get(target)
	if err != nil {
		writeJSON(w, 502, map[string]any{"url": target, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	writeJSON(w, 200, map[string]any{
		"url":     target,
		"status":  resp.StatusCode,
		"snippet": ssrfSnippet(resp.Body, 1024),
	})
}

// ============================================================================
// SAFE REFERENCE — allow-list scheme + host, then resolve and reject any
// private/link-local address before (and after) connecting. Shown so the
// vulnerable/safe pair can be diffed by SAST tooling and learners.
//
// Layers of defence:
//  1. scheme allow-list (http/https only — no file://, gopher://, dict:// ...)
//  2. host allow-list (exact hostnames the feature is meant to reach)
//  3. resolve every A/AAAA record and reject loopback/private/link-local:
//       127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
//       169.254.0.0/16 (+ ::1, fc00::/7, fe80::/10) via net.IP helpers
//  4. disable redirects (a 302 to http://169.254.169.254/ would re-open SSRF)
//  5. pin the validated IP into the dialer so DNS rebinding can't swap the
//     address between the check and the connect (TOCTOU).
// ============================================================================
func ssrfFetchSafe(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	u, err := url.Parse(raw)
	if err != nil {
		writeJSON(w, 400, map[string]any{"url": raw, "error": "unparseable url"})
		return
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		writeJSON(w, 400, map[string]any{"url": raw, "error": "scheme not allowed"})
		return
	}
	allowedHosts := map[string]bool{"example.com": true, "api.example.com": true}
	host := strings.ToLower(u.Hostname())
	if !allowedHosts[host] {
		writeJSON(w, 403, map[string]any{"url": raw, "error": "host not on allow-list"})
		return
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		writeJSON(w, 502, map[string]any{"url": raw, "error": "resolution failed"})
		return
	}
	for _, ip := range ips {
		if ssrfIsInternal(ip) {
			writeJSON(w, 403, map[string]any{"url": raw, "resolved": ip.String(), "error": "resolves to internal address"})
			return
		}
	}
	// Pin the first validated IP so a rebind can't change the target underneath us.
	pinned := ips[0].String()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	safeClient := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // do not follow redirects
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			// Always dial the pre-validated I:port regardless of the URL host.
			Proxy: nil,
		},
	}
	req, _ := http.NewRequest("GET", raw, nil)
	req.URL.Host = net.JoinHostPort(pinned, port)
	req.Host = host // preserve virtual-host routing
	resp, err := safeClient.Do(req)
	if err != nil {
		writeJSON(w, 502, map[string]any{"url": raw, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	writeJSON(w, 200, map[string]any{
		"url":      raw,
		"resolved": pinned,
		"status":   resp.StatusCode,
		"snippet":  ssrfSnippet(resp.Body, 1024),
	})
}

// ssrfIsInternal reports whether an IP is loopback, private (RFC1918 / ULA),
// link-local (169.254.0.0/16, fe80::/10), or unspecified — the ranges an
// outbound-fetch feature must never reach.
func ssrfIsInternal(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}
