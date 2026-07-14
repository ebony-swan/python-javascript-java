package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Server-Side Request Forgery (SSRF) —
 * OWASP 2021 A10 Server-Side Request Forgery  ->  folded into
 * OWASP 2025 A01 Broken Access Control.
 *
 * Mirrors the comment/annotation format of {@link SqlInjectionController}: each
 * permutation carries a standard header describing the flaw, its CWE, an
 * exploitation-likelihood rating, greenfield-vs-legacy prevalence, an example
 * payload, and the corresponding safe pattern. Every dangerous sink is a real,
 * exploitable {@link HttpURLConnection} that the SERVER opens to a
 * user-controlled URL — nothing is stubbed. Timeouts are short (~3s) so the
 * demo never hangs, and {@code HttpURLConnection} follows 3xx redirects by
 * default, which matters for the P3 redirect bypass.
 *
 * PRIMARY CWE: CWE-918 Server-Side Request Forgery (SSRF).
 */
@RestController
@RequestMapping("/ssrf")
public class SsrfController {

    private static final int TIMEOUT_MS = 3000;

    // ========================================================================
    // PERMUTATION 1 — Unrestricted server-side fetch (no allow-list)
    // OWASP 2021 A10 Server-Side Request Forgery  ->  folded into OWASP 2025 A01 Broken Access Control
    // CWE-918: Server-Side Request Forgery (SSRF)
    // EXPLOITATION LIKELIHOOD: HIGH — reachable pre-auth, deterministic, no
    //   tooling required. The server opens a GET to whatever URL the attacker
    //   supplies and returns status + body, so it doubles as an internal proxy:
    //   read cloud metadata (169.254.169.254), hit admin-only internal services,
    //   or use file:// / gopher:// depending on the client stack.
    // PREVALENCE TODAY: greenfield MEDIUM (URL-fetch features — link previews,
    //   image proxies, PDF/HTML renderers, import-from-URL — are ubiquitous and
    //   NO mainstream framework blocks SSRF by default; egress controls + IMDSv2
    //   are what save modern shops, not the code) | legacy/10yr tech-debt HIGH
    //   (hand-rolled fetchers with zero egress validation are everywhere).
    // EXAMPLE:
    //   curl 'http://localhost:8080/ssrf/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    //   curl 'http://localhost:8080/ssrf/fetch?url=http://127.0.0.1:8080/ssrf'
    // FIX: allow-list scheme + host and block private/link-local ranges after
    //   DNS resolution (see /ssrf/fetch-safe).
    // ========================================================================
    @GetMapping("/fetch")
    public Map<String, Object> fetch(@RequestParam(defaultValue = "http://example.com") String url) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("permutation", "unrestricted-fetch");
        // VULNERABLE: user-supplied URL fetched by the server with no allow-list / egress check.
        out.putAll(httpGet(url));
        return out;
    }

    // ========================================================================
    // PERMUTATION 2 — Blind / internal SSRF via a user-supplied webhook URL
    // OWASP 2021 A10 Server-Side Request Forgery  ->  folded into OWASP 2025 A01 Broken Access Control
    // CWE-918: Server-Side Request Forgery (SSRF)
    // EXPLOITATION LIKELIHOOD: HIGH — "register a callback/webhook and we'll POST
    //   to it" is a first-class feature, so the request is attacker-controlled by
    //   design. Even when the body is not returned (truly blind), timing / status
    //   codes turn the server into an internal PORT SCANNER, and pointing it at
    //   http://169.254.169.254/latest/meta-data/ steals cloud instance credentials.
    // PREVALENCE TODAY: greenfield MEDIUM (webhooks/callbacks are standard SaaS
    //   plumbing; SSRF-aware teams validate the destination, but many ship it raw
    //   because "it's just an outbound call") | legacy/10yr tech-debt HIGH
    //   (integration/notification subsystems that fire arbitrary stored URLs).
    // EXAMPLE:
    //   curl -X POST http://localhost:8080/ssrf/webhook -H 'Content-Type: application/json' \
    //        -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
    //   curl -X POST http://localhost:8080/ssrf/webhook -H 'Content-Type: application/json' \
    //        -d '{"url":"http://127.0.0.1:22"}'   # internal port probe via status/timing
    // FIX: resolve the host and reject private/link-local targets; pin an
    //   allow-list of destinations (see /ssrf/fetch-safe).
    // ========================================================================
    @PostMapping("/webhook")
    public Map<String, Object> webhook(@RequestBody(required = false) Map<String, Object> body) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("permutation", "blind-webhook");
        Object raw = body == null ? null : body.getOrDefault("url", body.get("callback"));
        String url = raw == null ? "" : raw.toString();
        // VULNERABLE: server fires a request at an attacker-chosen callback URL with no destination check.
        out.putAll(httpGet(url));
        return out;
    }

    // ========================================================================
    // PERMUTATION 3 — Naive substring blocklist (trivially bypassable)
    // OWASP 2021 A10 Server-Side Request Forgery  ->  folded into OWASP 2025 A01 Broken Access Control
    // CWE-918: Server-Side Request Forgery (SSRF)
    // EXPLOITATION LIKELIHOOD: HIGH — the only control is a case-sensitive
    //   substring check for "localhost" / "127.0.0.1", which does not understand
    //   URL parsing, alternate IP encodings, DNS, IPv6, or redirects. Every one of
    //   the following reaches loopback/internal despite the filter:
    //     http://127.0.0.1.nip.io/     (DNS name that resolves to 127.0.0.1)
    //     http://0177.0.0.1/           (octal 0177 = 127)
    //     http://2130706433/           (decimal form of 127.0.0.1)
    //     http://[::1]/                (IPv6 loopback — no "127.0.0.1" substring)
    //     http://169.254.169.254/...   (metadata IP was never on the blocklist)
    //     an external URL that 302-redirects to http://127.0.0.1/ (follow-redirect)
    // PREVALENCE TODAY: greenfield LOW (a reviewed modern shop reaches for a
    //   vetted SSRF library / egress proxy, not a string blocklist; SAST flags
    //   deny-list URL checks) | legacy/10yr tech-debt HIGH (hand-rolled
    //   "block localhost" string checks are a classic band-aid that ships and stays).
    // EXAMPLE:
    //   curl 'http://localhost:8080/ssrf/preview?url=http://127.0.0.1.nip.io:8080/ssrf'
    //   curl 'http://localhost:8080/ssrf/preview?url=http://2130706433:8080/ssrf'
    //   curl 'http://localhost:8080/ssrf/preview?url=http://169.254.169.254/latest/meta-data/'
    // FIX: do NOT deny-list strings — resolve the host to IP(s) and allow only
    //   public destinations on an allow-list of schemes/hosts (see /ssrf/fetch-safe).
    // ========================================================================
    @GetMapping("/preview")
    public Map<String, Object> preview(@RequestParam(defaultValue = "http://example.com") String url) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("permutation", "naive-blocklist");
        // Broken control: a raw substring blocklist that ignores octal/decimal/IPv6/DNS/redirects.
        if (url.contains("localhost") || url.contains("127.0.0.1")) {
            out.put("blocked", true);
            out.put("reason", "url contains 'localhost' or '127.0.0.1'");
            out.put("requested_url", url);
            return out;
        }
        // VULNERABLE: passes the blocklist yet still reaches loopback/internal via encoding/DNS/redirect.
        out.putAll(httpGet(url));
        return out;
    }

    // ========================================================================
    // SAFE REFERENCE — scheme + host allow-list AND private/link-local block.
    // Shown so the vulnerable/safe pair can be diffed by SAST tooling and learners.
    //
    // Three independent controls make this safe:
    //   1) the scheme must be http/https (no file:, gopher:, ftp:, dict:, ...);
    //   2) the host must be on an explicit allow-list of destinations;
    //   3) EVERY resolved IP for that host is checked and rejected if it falls in
    //      loopback 127.0.0.0/8, private 10/8 · 172.16/12 · 192.168/16, or
    //      link-local 169.254/16 — closing the DNS-rebinding / alternate-encoding
    //      holes that P3's string blocklist leaves open. Only after all three
    //      pass is the request actually issued.
    // ========================================================================
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");
    private static final Set<String> ALLOWED_HOSTS = Set.of("example.com", "www.example.com", "api.github.com");

    @GetMapping("/fetch-safe")
    public Map<String, Object> fetchSafe(@RequestParam(defaultValue = "http://example.com") String url) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("permutation", "safe-allowlist");
        out.put("requested_url", url);
        try {
            URL parsed = new URL(url);
            String scheme = parsed.getProtocol() == null ? "" : parsed.getProtocol().toLowerCase();
            String host = parsed.getHost() == null ? "" : parsed.getHost().toLowerCase();
            if (!ALLOWED_SCHEMES.contains(scheme)) {
                out.put("rejected", "scheme not in allow-list " + ALLOWED_SCHEMES);
                return out;
            }
            if (!ALLOWED_HOSTS.contains(host)) {
                out.put("rejected", "host not in allow-list " + ALLOWED_HOSTS);
                return out;
            }
            for (InetAddress addr : InetAddress.getAllByName(host)) {
                if (addr.isLoopbackAddress() || addr.isAnyLocalAddress()
                        || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
                    // SAFE: refuse any host that resolves into a private/link-local range.
                    out.put("rejected", "host resolves to a private/link-local address: " + addr.getHostAddress());
                    return out;
                }
            }
            // SAFE: scheme, host, and every resolved IP all passed validation before the fetch.
            out.putAll(httpGet(url));
        } catch (Exception e) {
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }

    /**
     * Opens a real server-side GET to {@code urlStr} with short connect/read
     * timeouts and returns the status line plus a bounded body snippet. On any
     * failure it returns the exact URL that was requested together with the error
     * (as the reference modules echo the built command/query), so blind/internal
     * probes still surface a useful signal. {@code HttpURLConnection} follows 3xx
     * redirects by default — deliberately left on for the P3 redirect bypass.
     */
    private Map<String, Object> httpGet(String urlStr) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("requested_url", urlStr);
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestMethod("GET");
            int status = conn.getResponseCode();
            out.put("status", status);
            out.put("final_url", conn.getURL().toString());
            InputStream in = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
            String bodySnippet = "";
            if (in != null) {
                byte[] raw = in.readAllBytes();
                in.close();
                String body = new String(raw, StandardCharsets.UTF_8);
                bodySnippet = body.length() > 500 ? body.substring(0, 500) : body;
            }
            out.put("body_snippet", bodySnippet);
        } catch (Exception e) {
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
        return out;
    }
}
