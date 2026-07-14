package com.example.vulnapp.vulns;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Cross-Site Scripting (XSS) — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
 *
 * Same comment/annotation format as {@link SqlInjectionController}: each
 * permutation carries a standard header describing the flaw, its CWE, an
 * exploitation-likelihood rating, prevalence today, an example payload, and the
 * corresponding safe pattern.
 *
 * NOTE: this class is a @Controller (not @RestController) because PERMUTATION 4
 * renders a Thymeleaf view; the JSON/HTML-string handlers therefore carry an
 * explicit @ResponseBody. Auto-discovered by component scan — no wiring changes.
 */
@Controller
@RequestMapping("/injection/xss")
public class XssController {

    // Module-level in-memory store for the stored-XSS demo (PERMUTATION 2).
    // A singleton controller bean makes this a process-wide comment list.
    private static final List<String> COMMENTS = Collections.synchronizedList(new ArrayList<>());

    // ========================================================================
    // PERMUTATION 1 — Reflected XSS via HTML string concatenation
    // OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
    // CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
    // EXPLOITATION LIKELIHOOD: HIGH — deterministic script execution; only caveat
    //   is social engineering (victim must open the attacker-crafted link).
    // PREVALENCE TODAY: greenfield LOW (React/Angular/Vue and Thymeleaf auto-escape
    //   by default, so raw HTML string-building is rare) | legacy/10yr tech-debt HIGH
    //   (JSP/servlet out.print, PHP echo, and hand-rolled HTML concatenation persist).
    // EXAMPLE: GET /injection/xss/hello?name=<script>alert(1)</script>
    // FIX: HTML-entity-encode before output (see /injection/xss/hello-safe).
    // ========================================================================
    @GetMapping(value = "/hello", produces = "text/html")
    @ResponseBody
    public String hello(@RequestParam(defaultValue = "World") String name) {
        // VULNERABLE: request parameter concatenated straight into the HTML body, unescaped.
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Hello</title></head>"
             + "<body><h1>Hello, " + name + "!</h1>"
             + "<p>Reflected value: " + name + "</p></body></html>";
    }

    // ========================================================================
    // PERMUTATION 2 — Stored XSS (persisted comment rendered unescaped)
    // OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
    // CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
    // EXPLOITATION LIKELIHOOD: HIGH — payload persists server-side and fires for
    //   EVERY viewer (including admins) with no per-victim social engineering.
    // PREVALENCE TODAY: greenfield MEDIUM (auto-escaping helps, but innerHTML /
    //   dangerouslySetInnerHTML / markdown & rich-text renderers reopen the sink)
    //   | legacy/10yr tech-debt HIGH (unescaped template output on stored fields).
    // EXAMPLE:
    //   curl -X POST 'http://127.0.0.1:8080/injection/xss/comment' \
    //        --data-urlencode 'text=<script>alert(document.cookie)</script>'
    //   then open  GET /injection/xss/comments  as any user.
    // FIX: encode on output (or sanitize allowed HTML with a library like OWASP Java HTML Sanitizer).
    // ========================================================================
    @PostMapping("/comment")
    @ResponseBody
    public Map<String, Object> addComment(@RequestParam(defaultValue = "") String text) {
        // VULNERABLE: raw comment text stored verbatim, no sanitization or encoding.
        COMMENTS.add(text);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("stored", text);
        out.put("count", COMMENTS.size());
        out.put("view", "/injection/xss/comments");
        return out;
    }

    @GetMapping(value = "/comments", produces = "text/html")
    @ResponseBody
    public String comments() {
        StringBuilder items = new StringBuilder();
        synchronized (COMMENTS) {
            for (String c : COMMENTS) {
                // VULNERABLE: stored comment written into the page unescaped on every view.
                items.append("<li class=\"comment\">").append(c).append("</li>");
            }
        }
        if (items.length() == 0) {
            items.append("<li><em>No comments yet — POST one to /injection/xss/comment</em></li>");
        }
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Comments</title></head>"
             + "<body><h1>Comments (" + COMMENTS.size() + ")</h1><ul>" + items + "</ul></body></html>";
    }

    // ========================================================================
    // PERMUTATION 3 — DOM-based XSS (client-side sink, server never sees payload)
    // OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
    // CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
    // EXPLOITATION LIKELIHOOD: MEDIUM — reliable via <img onerror> gadgets and
    //   invisible to server-side WAFs (the #fragment is never sent to the server),
    //   but injected <script> tags won't run through innerHTML and it needs a link click.
    // PREVALENCE TODAY: greenfield MEDIUM (SPAs push logic client-side; innerHTML /
    //   dangerouslySetInnerHTML sinks recur despite framework guidance) | legacy/10yr
    //   tech-debt HIGH (jQuery `.html()` and location.hash handling are everywhere).
    // EXAMPLE: GET /injection/xss/dom#<img src=x onerror=alert(1)>
    // FIX: use textContent / safe DOM APIs, or sanitize (e.g. DOMPurify) before innerHTML.
    // ========================================================================
    @GetMapping(value = "/dom", produces = "text/html")
    @ResponseBody
    public String dom() {
        // Server returns a STATIC page; the untrusted data (location.hash) is read and
        // written to innerHTML entirely in the browser — the flaw lives client-side.
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>DOM XSS</title></head>"
             + "<body><h1>DOM-based XSS</h1>"
             + "<p>Put a payload in the URL fragment, e.g. <code>#&lt;img src=x onerror=alert(1)&gt;</code></p>"
             + "<div id=\"out\"></div>"
             + "<script>"
             + "var raw = location.hash.substring(1);"
             + "try { raw = decodeURIComponent(raw); } catch (e) {}"
             // VULNERABLE (client-side sink): fragment value assigned to innerHTML with no sanitization.
             + "document.getElementById('out').innerHTML = raw;"
             + "</script></body></html>";
    }

    // ========================================================================
    // PERMUTATION 4 — XSS via Thymeleaf th:utext (auto-escaping disabled)
    // OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
    // CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
    // EXPLOITATION LIKELIHOOD: HIGH — th:utext emits the model value raw, so a
    //   reflected <script> executes deterministically; only needs a link click.
    // PREVALENCE TODAY: greenfield LOW (Thymeleaf escapes by default via th:text;
    //   th:utext is an explicit, reviewable opt-out) | legacy/10yr tech-debt MEDIUM
    //   (th:utext left on rich-text fields, or JSP <c:out escapeXml="false"> / raw ${}).
    // EXAMPLE: GET /injection/xss/profile?name=<script>alert(1)</script>
    // FIX: use th:text (escaped) — see the SAFE reference below.
    // NOTE: th:utext ("unescaped text") deliberately disables Thymeleaf's default
    //   HTML-entity escaping — the whole point of the tag, and the whole bug here.
    // ========================================================================
    @GetMapping("/profile")
    public String profile(@RequestParam(defaultValue = "World") String name, Model model) {
        // VULNERABLE: value handed to a template that outputs it via th:utext (unescaped).
        model.addAttribute("name", name);
        return "xss_profile"; // resolves to templates/xss_profile.html
    }

    // ========================================================================
    // SAFE REFERENCE — HTML-entity-encode untrusted input before output.
    // Shown so the vulnerable/safe pair can be diffed by SAST tooling and learners.
    // (Server-side templates should prefer Thymeleaf th:text, which does this for you.)
    // ========================================================================
    @GetMapping(value = "/hello-safe", produces = "text/html")
    @ResponseBody
    public String helloSafe(@RequestParam(defaultValue = "World") String name) {
        String safe = htmlEncode(name);
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Hello (safe)</title></head>"
             + "<body><h1>Hello, " + safe + "!</h1>"
             + "<p>Reflected value: " + safe + "</p></body></html>";
    }

    private static String htmlEncode(String s) {
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }
}
