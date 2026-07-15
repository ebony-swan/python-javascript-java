using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace VulnApp.Controllers;

/// <summary>
/// Server-Side Request Forgery (SSRF) —
/// OWASP 2021 A10 Server-Side Request Forgery -> folded into OWASP 2025 A01 Broken Access Control.
///
/// Mirrors the annotation format and attribute-routed action style of
/// SqlInjectionController. Every handler drives a REAL HttpClient request against
/// a user-controlled URL, so the forgery is genuinely exploitable when the app
/// runs. The canonical high-impact target is the cloud metadata service at
/// http://169.254.169.254/latest/meta-data/ (IMDSv1 hands out IAM credentials with
/// no auth); a target that works even inside this sandbox is the app's OWN internal
/// admin endpoint, e.g. http://127.0.0.1:5001/access/admin/users — the server can
/// be coerced into requesting internal resources the client could never reach.
///
/// There is no "safe by default" framework for SSRF: fetching a URL is the intended
/// feature (webhooks, link previews, image proxies, PDF/HTML importers, "import from
/// URL"). Safety comes from validating the RESOLVED destination, not the string.
/// All fetches use a ~3s timeout so the demo never hangs.
/// </summary>
[ApiController]
public class SsrfController : ControllerBase
{
    // How long any outbound request may take before we give up (keeps the demo snappy).
    private static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(3);

    // ========================================================================
    // PERMUTATION 1 — direct fetch of a fully user-controlled URL (no allow-list)
    // OWASP 2021 A10 Server-Side Request Forgery -> folded into OWASP 2025 A01 Broken Access Control
    // CWE-918: Server-Side Request Forgery (SSRF)
    // EXPLOITATION LIKELIHOOD: HIGH — unauthenticated GET, zero tooling; the server
    //   dials any scheme/host/IP the caller names. Trivially reaches internal-only
    //   services and cloud metadata; ultimate impact is env-dependent (IMDSv1 vs v2,
    //   what internal endpoints exist) but reaching the sink is deterministic.
    // PREVALENCE TODAY: greenfield MEDIUM (nothing makes "fetch a URL" safe by
    //   default; SSRF-aware wrappers, egress allow-lists and IMDSv2 are spreading but
    //   opt-in) | legacy/10yr tech-debt HIGH (link-preview / image-proxy / import-URL
    //   features that pass raw user input straight to an HTTP client).
    // EXAMPLE: GET /ssrf/fetch?url=http://127.0.0.1:5001/access/admin/users
    //          -> SSRFs the app into requesting its own internal admin dump;
    //          real-world: url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    // FIX: allow-list scheme+host, resolve DNS and reject private/link-local IPs,
    //   disable redirects (see /ssrf/fetch-safe).
    // ========================================================================
    [HttpGet("/ssrf/fetch")]
    public async Task<IActionResult> Fetch(string url = "")
    {
        // VULNERABLE: HttpClient issues a GET to a fully user-controlled URL with
        // no scheme/host allow-list and no destination-IP validation.
        var (status, snippet, error) = await FetchSnippet(url);
        return new JsonResult(new
        {
            url,
            status,
            snippet,
            error,
            note = "the server, not the client, made this request — internal hosts and 169.254.169.254 are reachable"
        });
    }

    // ========================================================================
    // PERMUTATION 2 — blind SSRF via a user-supplied webhook / callback URL
    // OWASP 2021 A10 Server-Side Request Forgery -> folded into OWASP 2025 A01 Broken Access Control
    // CWE-918: Server-Side Request Forgery (SSRF)
    // EXPLOITATION LIKELIHOOD: HIGH — user-registered callback/webhook URLs are a
    //   first-class product feature, so the sink is exposed by design. Blind (the
    //   HTTP response is not shown to the caller) which lowers confirmability, but it
    //   still fires at internal services and http://169.254.169.254/latest/meta-data/;
    //   delivery-status/timing is a usable side channel and metadata exfil is severe.
    // PREVALENCE TODAY: greenfield MEDIUM (mature products validate webhook targets
    //   and pin egress, but many ship the feature with none of that) | legacy/10yr
    //   tech-debt HIGH (webhook/notification callers bolted on with no egress controls).
    // EXAMPLE: curl -X POST localhost:5001/ssrf/webhook -d 'url=http://169.254.169.254/latest/meta-data/'
    //          internal pivot: -d 'url=http://127.0.0.1:5001/access/admin/users'
    //          (JSON also accepted: -H 'Content-Type: application/json' -d '{"url":"..."}')
    // FIX: validate the callback destination (allow-list + resolved-IP block) before
    //   sending, and treat delivery status as sensitive (see /ssrf/fetch-safe).
    // ========================================================================
    [HttpPost("/ssrf/webhook")]
    public async Task<IActionResult> Webhook()
    {
        var url = await ReadUrlFromBody();
        if (string.IsNullOrWhiteSpace(url))
            return new JsonResult(new { error = "supply a webhook url via form field 'url'/'callback' or JSON {\"url\":...}" }) { StatusCode = 400 };

        // VULNERABLE: the caller-supplied callback URL is requested with no
        // validation. Blind SSRF — we deliberately do NOT return the response body,
        // only whether delivery connected, mirroring a real webhook sender.
        var (status, _, error) = await FetchSnippet(url);
        return new JsonResult(new
        {
            url,
            delivered = status > 0,
            status,
            error,
            note = "blind: the callback body is not returned; the request still reached the target (internal/metadata included)"
        });
    }

    // ========================================================================
    // PERMUTATION 3 — SSRF behind a NAIVE, bypassable substring blocklist
    // OWASP 2021 A10 Server-Side Request Forgery -> folded into OWASP 2025 A01 Broken Access Control
    // CWE-918: Server-Side Request Forgery (SSRF)
    // EXPLOITATION LIKELIHOOD: HIGH — the only defense is a substring check for
    //   'localhost'/'127.0.0.1', which is trivially bypassed. Deterministic and
    //   pre-auth; the block message even tells the attacker what to route around.
    // PREVALENCE TODAY: greenfield MEDIUM (teams that "add SSRF protection" reach for
    //   string/regex blocklists — a known-broken approach that still passes review) |
    //   legacy/10yr tech-debt HIGH (hand-rolled deny-lists on the raw URL string).
    // EXAMPLE: GET /ssrf/preview?url=http://127.0.0.1        -> blocked
    //          bypasses that all still hit loopback / link-local:
    //            http://127.0.0.1.nip.io   (DNS name resolving to 127.0.0.1)
    //            http://0177.0.0.1         (octal-encoded 127.0.0.1)
    //            http://2130706433         (decimal-encoded 127.0.0.1)
    //            http://[::1]              (IPv6 loopback — string never contains 127.0.0.1)
    // FIX: never blocklist the URL string; parse it, resolve DNS, and block the
    //   destination IP against private/link-local ranges (see /ssrf/fetch-safe).
    // ========================================================================
    [HttpGet("/ssrf/preview")]
    public async Task<IActionResult> Preview(string url = "")
    {
        // Naive, substring-only blocklist — the classic broken SSRF "defense".
        if (url.Contains("localhost") || url.Contains("127.0.0.1"))
            return new JsonResult(new { url, blocked = true, error = "blocked: local address not allowed" }) { StatusCode = 400 };

        // VULNERABLE: past the substring check, the raw URL is fetched — octal/decimal
        // IPs, DNS names like *.nip.io, and IPv6 [::1] all reach loopback/link-local.
        var (status, snippet, error) = await FetchSnippet(url);
        return new JsonResult(new
        {
            url,
            blocked = false,
            status,
            snippet,
            error,
            note = "substring blocklist bypassed via alternate host encodings (octal/decimal/nip.io/[::1])"
        });
    }

    // ========================================================================
    // SAFE REFERENCE — allow-list scheme+host AND block the resolved destination IP.
    // Shown so the vulnerable/safe pair can be diffed by SAST tooling and learners.
    //   (1) require an absolute http/https URL;
    //   (2) allow-list the host (reg-name), rejecting everything else;
    //   (3) resolve DNS and reject if ANY resolved address is loopback/private/
    //       link-local (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1, fc00::/7)
    //       — this defeats decimal/octal/nip.io tricks and DNS-rebinding;
    //   (4) disable auto-redirects so a 30x cannot bounce us to an internal target.
    // ========================================================================
    [HttpGet("/ssrf/fetch-safe")]
    public async Task<IActionResult> FetchSafe(string url = "")
    {
        // Fixed allow-list of destinations this feature is actually permitted to reach.
        var allowedHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "example.com", "www.example.com", "api.github.com"
        };

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return new JsonResult(new { safe = true, url, error = "invalid absolute URL" }) { StatusCode = 400 };

        // SAFE (1)+(2): scheme + host allow-list.
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            return new JsonResult(new { safe = true, url, error = "scheme not allowed (http/https only)" }) { StatusCode = 400 };
        if (!allowedHosts.Contains(uri.Host))
            return new JsonResult(new { safe = true, url, error = $"host '{uri.Host}' is not on the allow-list" }) { StatusCode = 400 };

        // SAFE (3): resolve and reject any private/link-local destination address.
        IPAddress[] addrs;
        try { addrs = await Dns.GetHostAddressesAsync(uri.Host); }
        catch (Exception e) { return new JsonResult(new { safe = true, url, error = "dns resolution failed: " + e.Message }) { StatusCode = 400 }; }

        foreach (var ip in addrs)
            if (IsPrivateOrLinkLocal(ip))
                return new JsonResult(new { safe = true, url, error = $"resolved to blocked address {ip}" }) { StatusCode = 400 };

        // SAFE (4): no auto-redirect (a 30x could otherwise point at an internal host).
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = FetchTimeout };
        try
        {
            var resp = await client.GetAsync(uri);
            var body = await resp.Content.ReadAsStringAsync();
            return new JsonResult(new { safe = true, url, status = (int)resp.StatusCode, snippet = Snippet(body) });
        }
        catch (Exception e)
        {
            return new JsonResult(new { safe = true, url, error = e.Message }) { StatusCode = 502 };
        }
    }

    // --- helpers -------------------------------------------------------------

    // The dangerous sink shared by P1/P2/P3: fetch a user-controlled URL and return
    // (status, body-snippet, error). Auto-redirects follow by default (another SSRF
    // vector). Returns status 0 on transport/timeout failure.
    private static async Task<(int Status, string Snippet, string Error)> FetchSnippet(string url)
    {
        using var client = new HttpClient { Timeout = FetchTimeout };
        try
        {
            var resp = await client.GetAsync(url); // VULNERABLE: request issued to an unvalidated, user-controlled URL
            var body = await resp.Content.ReadAsStringAsync();
            return ((int)resp.StatusCode, Snippet(body), null);
        }
        catch (Exception e)
        {
            return (0, null, e.Message);
        }
    }

    private static string Snippet(string body)
    {
        if (string.IsNullOrEmpty(body)) return body;
        return body.Length > 512 ? body.Substring(0, 512) : body;
    }

    // Pull the target URL out of a form body ('url' or 'callback') or a JSON body.
    private async Task<string> ReadUrlFromBody()
    {
        if (Request.HasFormContentType)
        {
            var f = await Request.ReadFormAsync();
            var u = f["url"].ToString();
            if (!string.IsNullOrEmpty(u)) return u;
            var cb = f["callback"].ToString();
            if (!string.IsNullOrEmpty(cb)) return cb;
        }

        using var reader = new StreamReader(Request.Body);
        var raw = await reader.ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(raw)) return "";
        try
        {
            var obj = JObject.Parse(raw);
            var u = (string)obj["url"] ?? (string)obj["callback"];
            if (!string.IsNullOrEmpty(u)) return u;
        }
        catch { /* not JSON — fall through and treat the raw body as the URL */ }
        return raw.Trim();
    }

    // True for loopback / private / link-local (incl. cloud-metadata 169.254.0.0/16)
    // addresses that a URL-fetching feature must never be allowed to reach.
    private static bool IsPrivateOrLinkLocal(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true; // 127.0.0.0/8, ::1

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 0) return true;                                  // 0.0.0.0/8
            if (b[0] == 10) return true;                                 // 10.0.0.0/8
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;    // 172.16.0.0/12
            if (b[0] == 192 && b[1] == 168) return true;                 // 192.168.0.0/16
            if (b[0] == 169 && b[1] == 254) return true;                 // 169.254.0.0/16 (link-local + metadata)
            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return true;   // fe80::/10, fec0::/10
            var b = ip.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC) return true;                      // fc00::/7 unique-local
            return false;
        }

        return false;
    }
}
