using Microsoft.AspNetCore.Mvc;

namespace VulnApp.Controllers;

/// <summary>
/// Broken Access Control — OWASP 2021 A01 | OWASP 2025 A01.
///
/// Mirrors the annotation format and attribute-routed action style of
/// SqlInjectionController. Every handler exposes a distinct access-control flaw:
/// object-level (IDOR), function-level (missing authZ), property-level (mass
/// assignment) and client-trusted role decisions. Access control is app logic —
/// no framework makes it "safe by default", which is why this category sits at
/// #1 in both the 2021 and 2025 OWASP Top 10.
/// </summary>
[ApiController]
public class AccessControlController : ControllerBase
{
    // ========================================================================
    // PERMUTATION 1 — Insecure Direct Object Reference (IDOR)
    // OWASP 2021 A01 Broken Access Control -> OWASP 2025 A01 Broken Access Control
    // CWE-639: Authorization Bypass Through User-Controlled Key
    // EXPLOITATION LIKELIHOOD: HIGH — just increment the id; no tooling, fully
    //   deterministic, and it leaks other users' PRIVATE notes (ids 2 and 4).
    // PREVALENCE TODAY: greenfield MEDIUM (ORMs fetch by id but nothing enforces
    //   per-object ownership — teams must remember the check every time) |
    //   legacy/10yr tech-debt HIGH (object-level authZ retrofitted, if at all).
    // EXAMPLE: GET /access/note?id=2   -> alice's private "Bank PIN reminder"
    //          GET /access/note?id=4   -> admin's private "Ops runbook"
    // FIX: scope the lookup to the caller / verify ownership (see /access/note-safe).
    // ========================================================================
    [HttpGet("/access/note")]
    public IActionResult Note(int id = 0)
    {
        // VULNERABLE: note fetched by raw id with no ownership or private-flag check.
        var sql = "SELECT id, owner, title, body, private FROM notes WHERE id=@id";
        var rows = Db.Query(sql, ("@id", id));
        return new JsonResult(new { query = sql, id, note = rows.Count > 0 ? rows[0] : null });
    }

    // ========================================================================
    // PERMUTATION 2 — Missing function-level authorization
    // OWASP 2021 A01 Broken Access Control -> OWASP 2025 A01 Broken Access Control
    // CWE-862: Missing Authorization
    // EXPLOITATION LIKELIHOOD: CRITICAL — an unauthenticated GET to an admin-only
    //   endpoint dumps every user's MD5 password hash, email and SSN. Trivial to
    //   hit, no auth, no tooling, catastrophic impact.
    // PREVALENCE TODAY: greenfield MEDIUM (frameworks ship [Authorize] but it is
    //   opt-in — endpoints default to allow, so a forgotten attribute exposes
    //   them) | legacy/10yr tech-debt HIGH (admin routes behind "hidden" URLs).
    // EXAMPLE: GET /access/admin/users   (no session, no role, no token)
    // FIX: require authentication + an admin role check ([Authorize(Roles=...)]).
    // ========================================================================
    [HttpGet("/access/admin/users")]
    public IActionResult AdminUsers()
    {
        // VULNERABLE: admin-only data returned with no authentication or role check.
        var users = Db.Query("SELECT id, username, password, email, role, ssn FROM users");
        return new JsonResult(new { count = users.Count, users });
    }

    // ========================================================================
    // PERMUTATION 3 — Mass assignment / privilege escalation
    // OWASP 2021 A01 Broken Access Control -> OWASP 2025 A01 Broken Access Control
    // CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
    // EXPLOITATION LIKELIHOOD: HIGH — a normal user posts an extra role=admin
    //   field to a self-service profile update and is silently promoted. Post-auth
    //   but deterministic, no tooling, and the payoff is full privilege escalation.
    // PREVALENCE TODAY: greenfield MEDIUM (DTOs/[Bind] help, but auto model-binding
    //   still over-binds sensitive props when devs bind straight to entities) |
    //   legacy/10yr tech-debt HIGH (classic Rails-mass-assignment-era pattern).
    // EXAMPLE: curl -d 'username=alice&email=a@x.com&role=admin' /access/profile
    // FIX: bind an allow-list of user-editable fields only; never accept role
    //   from the request body (privilege fields are set server-side).
    // ========================================================================
    [HttpPost("/access/profile")]
    public IActionResult UpdateProfile()
    {
        var form = Request.Form;
        var username = form["username"].ToString();

        // VULNERABLE: EVERY field present in the body is persisted — including
        // "role" — with no allow-list, so the client controls its own privilege.
        var editable = new[] { "email", "ssn", "password", "role" };
        var sets = new List<string>();
        var ps = new List<(string, object)> { ("@u", username) };
        int i = 0;
        foreach (var col in editable)
        {
            if (form.ContainsKey(col))
            {
                var p = "@p" + i++;
                sets.Add($"{col}={p}");
                ps.Add((p, form[col].ToString()));
            }
        }

        if (sets.Count == 0)
            return new JsonResult(new { error = "no updatable fields supplied" }) { StatusCode = 400 };

        var sql = $"UPDATE users SET {string.Join(", ", sets)} WHERE username=@u";
        Db.Query(sql, ps.ToArray()); // executes the UPDATE (reader over a non-query still runs it)

        var updated = Db.Query("SELECT id, username, email, role, ssn FROM users WHERE username=@u",
            ("@u", username));
        return new JsonResult(new { query = sql, updated = updated.Count > 0 ? updated[0] : null });
    }

    // ========================================================================
    // PERMUTATION 4 — Client-controlled authorization decision
    // OWASP 2021 A01 Broken Access Control -> OWASP 2025 A01 Broken Access Control
    // CWE-602: Client-Side Enforcement of Server-Side Security
    // EXPLOITATION LIKELIHOOD: HIGH — the server trusts a client-supplied role
    //   (X-Role header or ?role=). Set one header and you are admin; no tooling,
    //   no auth, deterministic, exposes admin-only data.
    // PREVALENCE TODAY: greenfield LOW (role comes from a server-validated
    //   session/JWT claim; trusting a raw request header is an obvious smell that
    //   review/SAST flag) | legacy/10yr tech-debt MEDIUM (proxy/gateway trust
    //   headers like X-Forwarded-User honoured directly by downstream apps).
    // EXAMPLE: curl -H 'X-Role: admin' /access/dashboard
    //          GET /access/dashboard?role=admin
    // FIX: derive the role from an authenticated, server-side session/token —
    //   never from a request header or query parameter the client controls.
    // ========================================================================
    [HttpGet("/access/dashboard")]
    public IActionResult Dashboard(string role = "")
    {
        var headerRole = Request.Headers["X-Role"].ToString();
        var effectiveRole = !string.IsNullOrEmpty(headerRole) ? headerRole : role;

        // VULNERABLE: authorization decision made from a client-controlled value.
        if (effectiveRole == "admin")
        {
            var users = Db.Query("SELECT id, username, email, role, ssn FROM users");
            return new JsonResult(new
            {
                role = effectiveRole,
                admin = true,
                secret = "prod db password: hunter2",
                users
            });
        }

        return new JsonResult(new { role = effectiveRole, admin = false, message = "standard user dashboard" });
    }

    // ========================================================================
    // SAFE REFERENCE — server-side ownership + private-flag check.
    // The current user is simulated via ?current= (defaults to alice); a private
    // note is only returned when the caller owns it. Diff against PERMUTATION 1.
    // ========================================================================
    [HttpGet("/access/note-safe")]
    public IActionResult NoteSafe(int id = 0, string current = "alice")
    {
        var rows = Db.Query("SELECT id, owner, title, body, private FROM notes WHERE id=@id", ("@id", id));
        if (rows.Count == 0)
            return new JsonResult(new { id, note = (object)null });

        var note = rows[0];
        var isPrivate = Convert.ToInt64(note["private"]) == 1;
        var owner = note["owner"]?.ToString();

        // SAFE: enforce object-level authorization before returning private data.
        if (isPrivate && owner != current)
            return new JsonResult(new { id, current, error = "forbidden — you do not own this note" }) { StatusCode = 403 };

        return new JsonResult(new { id, current, note });
    }
}
