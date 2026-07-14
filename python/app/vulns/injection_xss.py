"""Cross-Site Scripting (XSS) — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.

Companion to :mod:`app.vulns.injection_sql`; the same header/annotation format is
reused here. Every permutation echoes the untrusted value straight into an HTML
sink with no output encoding, so a browser parses the attacker's markup as code.
The reflected/stored/DOM/template-context variants below each carry a standard
header (flaw, CWE, exploitation likelihood, prevalence, example payload, fix) and
end with ONE clearly-labelled SAFE reference handler that escapes its output.
"""
from flask import Blueprint, request, jsonify, render_template_string
from markupsafe import escape

bp = Blueprint("injection_xss", __name__, url_prefix="/injection/xss")


# =============================================================================
# PERMUTATION 1 — Reflected XSS (untrusted query param echoed into the page)
# OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
# CWE-79: Improper Neutralization of Input During Web Page Generation ('XSS')
# EXPLOITATION LIKELIHOOD: HIGH — reflected pre-auth and deterministic; only
#   friction is social engineering the victim into opening the crafted link.
# PREVALENCE TODAY: greenfield MEDIUM (React/Jinja2/Angular auto-escape by
#   default, but raw string responses, dangerouslySetInnerHTML and non-HTML
#   contexts keep reintroducing it) | legacy/10yr tech-debt HIGH (server-side
#   string-concatenated HTML with no encoding is the default old pattern).
# EXAMPLE:
#   GET /injection/xss/hello?name=<script>alert(1)</script>
# FIX: HTML-entity-encode on output (markupsafe.escape) — see /hello-safe.
# =============================================================================
@bp.get("/hello")
def hello():
    name = request.args.get("name", "World")
    # VULNERABLE: raw request value concatenated into the HTML response body.
    return (
        "<!doctype html><html><body>"
        f"<h1>Hello, {name}!</h1>"
        "<p>(reflected without escaping)</p>"
        "</body></html>"
    )


# =============================================================================
# PERMUTATION 2 — Stored XSS (persisted comment rendered unescaped for everyone)
# OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
# CWE-79: Improper Neutralization of Input During Web Page Generation ('XSS')
# EXPLOITATION LIKELIHOOD: HIGH — the payload persists and fires against every
#   viewer (including admins) with no per-victim link; a single POST is enough.
# PREVALENCE TODAY: greenfield MEDIUM (auto-escaping helps, but rich-text /
#   markdown / "allow some HTML" fields and API->SPA rendering still bite) |
#   legacy/10yr tech-debt HIGH (unencoded persistence + render is the norm).
# EXAMPLE:
#   curl -d 'text=<script>alert(document.cookie)</script>' \
#        http://127.0.0.1:5000/injection/xss/comment
#   then open  GET /injection/xss/comments
# FIX: escape each comment when rendering (markupsafe.escape / template autoescape).
# =============================================================================
_COMMENTS = []  # module-level in-memory store; NOT sanitized on the way in.


@bp.post("/comment")
def add_comment():
    text = request.form.get("text")
    if text is None:
        text = (request.get_json(silent=True) or {}).get("text", "")
    # VULNERABLE: attacker-controlled markup stored verbatim (no encoding).
    _COMMENTS.append(text)
    return jsonify({"stored": text, "count": len(_COMMENTS)})


@bp.get("/comments")
def list_comments():
    # VULNERABLE: every stored comment interpolated into HTML without escaping.
    items = "".join(f"<li>{c}</li>" for c in _COMMENTS)
    return (
        "<!doctype html><html><body><h2>Comments</h2>"
        f"<ul>{items}</ul>"
        "</body></html>"
    )


# =============================================================================
# PERMUTATION 3 — DOM-based XSS (client-side sink; server never sees the payload)
# OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
# CWE-79: Improper Neutralization of Input During Web Page Generation ('XSS')
# EXPLOITATION LIKELIHOOD: MEDIUM — deterministic once the victim opens the link,
#   but the payload lives in the URL fragment (never sent to the server), so
#   server-side WAF/logging can't see or block it; needs victim interaction.
# PREVALENCE TODAY: greenfield MEDIUM (frameworks discourage direct innerHTML,
#   yet SPA glue code, third-party widgets and hash-router state still assign
#   tainted data to innerHTML) | legacy/10yr tech-debt HIGH (jQuery-era
#   $(el).html(location.hash) patterns are everywhere in old front-ends).
# EXAMPLE:
#   GET /injection/xss/dom#<img src=x onerror=alert(1)>
#   (innerHTML won't run raw <script>, but img/svg onerror handlers do fire)
# FIX: use textContent / .innerText, or sanitize with a trusted-types policy.
# =============================================================================
@bp.get("/dom")
def dom():
    # Server returns a STATIC page; the flaw is entirely in the client-side JS
    # below. VULNERABLE: location.hash is written straight into innerHTML.
    return """<!doctype html>
<html><body>
<h2>DOM XSS demo</h2>
<p>Payload goes in the URL fragment, e.g. <code>#&lt;img src=x onerror=alert(1)&gt;</code></p>
<div id="out"></div>
<script>
  // VULNERABLE: untrusted location.hash assigned to innerHTML on the client.
  var payload = decodeURIComponent(location.hash.slice(1));
  document.getElementById('out').innerHTML = payload;
</script>
</body></html>"""


# =============================================================================
# PERMUTATION 4 — XSS via disabled escaping: user input rendered AS a Jinja
#                 template (render_template_string) -> reflected XSS + SSTI
# OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
# CWE-79: Improper Neutralization of Input During Web Page Generation ('XSS')
# ALSO CWE-1336: Improper Neutralization of Special Elements Used in a Template
#   Engine (Server-Side Template Injection). Because the value is concatenated
#   into the template SOURCE, literal markup is emitted raw (autoescaping only
#   guards {{ }} expression output, not template text) AND {{ }} is evaluated —
#   name={{7*7}} renders 49, and Jinja SSTI escalates to RCE.
# EXPLOITATION LIKELIHOOD: HIGH — reflected + deterministic, and the SSTI angle
#   turns a "cosmetic" XSS into remote code execution on the server.
# PREVALENCE TODAY: greenfield LOW (SAST/Bandit flag render_template_string on
#   tainted input; passing user data as a template is a known anti-pattern) |
#   legacy/10yr tech-debt MEDIUM-HIGH (hand-rolled email/report/CMS features
#   that build template source from user data are still in production).
# EXAMPLE:
#   GET /injection/xss/profile?name=<script>alert(1)</script>   (reflected XSS)
#   GET /injection/xss/profile?name={{7*7}}                      (SSTI -> 49)
# FIX: never build template SOURCE from input; pass it as a bound variable to a
#   fixed template so autoescaping applies (render_template(..., name=name)).
# =============================================================================
@bp.get("/profile")
def profile():
    name = request.args.get("name", "World")
    # VULNERABLE: untrusted input concatenated into Jinja template source, then
    # rendered — output is unescaped (XSS) and the input is evaluated (SSTI).
    template = f"<!doctype html><html><body><h1>Profile of {name}</h1></body></html>"
    return render_template_string(template)


# =============================================================================
# SAFE REFERENCE — HTML-entity-encode untrusted output before rendering.
# markupsafe.escape turns  <script>  into  &lt;script&gt;  so the browser shows
# the text instead of executing it. Shown so the vulnerable/safe pair can be
# diffed by SAST tools and learners.
# =============================================================================
@bp.get("/hello-safe")
def hello_safe():
    name = request.args.get("name", "World")
    safe_name = escape(name)  # SAFE: entity-encodes < > & " ' on output.
    return (
        "<!doctype html><html><body>"
        f"<h1>Hello, {safe_name}!</h1>"
        "<p>(escaped output — payload is inert)</p>"
        "</body></html>"
    )
