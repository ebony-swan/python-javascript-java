package com.example.vulnapp.vulns;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Broken Access Control — OWASP 2021 A01 | OWASP 2025 A01.
 *
 * Mirrors the comment/annotation format of {@link SqlInjectionController}: each
 * permutation carries a standard header describing the flaw, its CWE, an
 * exploitation-likelihood rating, greenfield-vs-legacy prevalence, an example
 * request, and the corresponding safe pattern. Every dangerous sink is a real,
 * exploitable authorization gap — the queries themselves are parameterized so
 * the ONLY defect on show is the missing/broken access-control check, not SQLi.
 *
 * PRIMARY CWEs: CWE-639 Authorization Bypass Through User-Controlled Key,
 * CWE-862 Missing Authorization, CWE-915 Improperly Controlled Modification of
 * Dynamically-Determined Object Attributes (mass assignment), CWE-602
 * Client-Side Enforcement of Server-Side Security.
 */
@RestController
@RequestMapping("/access")
public class AccessControlController {

    private final JdbcTemplate jdbc;

    public AccessControlController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // ========================================================================
    // PERMUTATION 1 — IDOR: fetch any note by id, no ownership check
    // OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
    // CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
    // EXPLOITATION LIKELIHOOD: HIGH — a single sequential integer is the only
    //   "key"; an attacker just increments ?id= to walk every row, reading other
    //   users' PRIVATE notes (ids 2 and 4) with zero tooling and full reliability.
    // PREVALENCE TODAY: greenfield MEDIUM (frameworks/ORMs never auto-enforce
    //   object-level ownership — it is app-specific logic — but modern teams add
    //   policy/authz layers, use unguessable UUIDs, and catch it in review) |
    //   legacy/10yr tech-debt HIGH (sequential auto-increment ids everywhere and
    //   scattered hand-rolled checks that get forgotten on new endpoints).
    // EXAMPLE:
    //   GET /access/note?id=2   -> alice's private "Bank PIN reminder"
    //   GET /access/note?id=4   -> admin's private "Ops runbook" (db password)
    // FIX: scope the lookup to the authenticated principal and enforce the
    //   private flag server-side (see /access/note-safe).
    // ========================================================================
    @GetMapping("/note")
    public Map<String, Object> note(@RequestParam(defaultValue = "1") int id) {
        String sql = "SELECT id, owner, title, body, private FROM notes WHERE id = ?";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("query", sql + "   -- id=" + id + " (no ownership/private check)");
        // VULNERABLE: returns the row for ANY id with no ownership/private check.
        List<Map<String, Object>> rows = jdbc.queryForList(sql, id);
        out.put("note", rows.isEmpty() ? null : rows.get(0));
        return out;
    }

    // ========================================================================
    // PERMUTATION 2 — Missing function-level authorization on an admin dump
    // OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
    // CWE-862: Missing Authorization
    // EXPLOITATION LIKELIHOOD: HIGH — the endpoint performs NO authentication or
    //   role check, so an anonymous GET dumps every user's password hash, email
    //   and SSN. Pre-auth, deterministic, one request.
    // PREVALENCE TODAY: greenfield MEDIUM (Spring Security-style default-deny helps,
    //   but "admin" routes get shipped before the authz rule is written, and
    //   internal/microservice endpoints are often left wide open behind a gateway) |
    //   legacy/10yr tech-debt HIGH (authz enforced ad hoc per-handler, so any newly
    //   added admin action silently inherits no protection).
    // EXAMPLE:
    //   GET /access/admin/users   -> id, username, MD5 password, email, role, ssn
    // FIX: require authentication AND an explicit role/permission check (ideally
    //   centrally, default-deny) before serving admin-only data.
    // ========================================================================
    @GetMapping("/admin/users")
    public Map<String, Object> adminUsers() {
        String sql = "SELECT id, username, password, email, role, ssn FROM users";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("query", sql + "   -- served with NO auth/role gate");
        // VULNERABLE: admin-only data returned with no authentication/role check.
        out.put("users", jdbc.queryForList(sql));
        return out;
    }

    // ========================================================================
    // PERMUTATION 3 — Mass assignment: every body field bound to a column
    // OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
    // CWE-915: Improperly Controlled Modification of Dynamically-Determined
    //   Object Attributes (a.k.a. mass assignment / autobinding)
    // EXPLOITATION LIKELIHOOD: HIGH — the handler binds EVERY field present in the
    //   JSON body to a user column, so a normal user simply adds "role":"admin"
    //   to a profile update and escalates to admin. Post-auth but trivial and
    //   fully reliable (the GitHub 2012 "become any org member" bug pattern).
    // PREVALENCE TODAY: greenfield MEDIUM (DTOs and allow-listed binding — Rails
    //   strong params, explicit request records — are common, yet binding straight
    //   to entities and permissive JSON/GraphQL patch APIs keep reintroducing it) |
    //   legacy/10yr tech-debt HIGH (frameworks auto-populate domain objects from
    //   the whole request; sensitive fields like role/isAdmin are never excluded).
    // EXAMPLE:
    //   curl -XPOST /access/profile -H 'Content-Type: application/json' \
    //        -d '{"username":"alice","email":"a@x.com","role":"admin"}'
    // FIX: bind only an explicit allow-list of user-editable fields; never let the
    //   request set privilege columns like role (see updateProfileSafe below).
    // ========================================================================
    @PostMapping("/profile")
    public Map<String, Object> updateProfile(@RequestBody Map<String, Object> body) {
        String username = String.valueOf(body.get("username"));
        List<String> setClauses = new ArrayList<>();
        List<Object> params = new ArrayList<>();
        for (Map.Entry<String, Object> e : body.entrySet()) {
            if ("username".equalsIgnoreCase(e.getKey())) {
                continue; // the key identifying the row, not an updatable field
            }
            // VULNERABLE: EVERY field in the body becomes a column update —
            // including 'role', so the client can escalate itself to admin.
            setClauses.add(e.getKey() + " = ?");
            params.add(e.getValue());
        }
        String sql = "UPDATE users SET " + String.join(", ", setClauses) + " WHERE username = ?";
        params.add(username);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("query", sql + "   -- fields bound: " + setClauses);
        jdbc.update(sql, params.toArray());
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, username, email, role, ssn FROM users WHERE username = ?", username);
        out.put("updated", rows.isEmpty() ? null : rows.get(0));
        return out;
    }

    // ========================================================================
    // PERMUTATION 4 — Client-controlled authorization (trusted role from client)
    // OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
    // CWE-602: Client-Side Enforcement of Server-Side Security
    // EXPLOITATION LIKELIHOOD: HIGH — the admin decision is read straight from a
    //   CLIENT-supplied value (X-Role header or ?role= param) and trusted, so the
    //   caller names their own privilege level in a single request.
    // PREVALENCE TODAY: greenfield MEDIUM (SPA/JWT auth discourages it, yet
    //   microservice meshes routinely trust internal "X-User-Role"/"X-User-Id"
    //   headers stamped by a gateway — anyone who reaches the service directly
    //   forges them) | legacy/10yr tech-debt HIGH (role kept in a hidden form
    //   field / editable cookie / query param and believed on the server).
    // EXAMPLE:
    //   curl -H 'X-Role: admin' /access/dashboard
    //   GET /access/dashboard?role=admin
    // FIX: derive the role from the authenticated server-side session/token, never
    //   from a request header or parameter the client controls.
    // ========================================================================
    @GetMapping("/dashboard")
    public Map<String, Object> dashboard(
            @RequestHeader(value = "X-Role", required = false) String roleHeader,
            @RequestParam(required = false) String role) {
        // VULNERABLE: privilege decided from a client-supplied header/param.
        String effectiveRole = roleHeader != null ? roleHeader
                : (role != null ? role : "user");
        boolean isAdmin = "admin".equalsIgnoreCase(effectiveRole);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("trustedRoleFrom", roleHeader != null ? "X-Role header" : "?role= param / default");
        out.put("effectiveRole", effectiveRole);
        out.put("isAdmin", isAdmin);
        if (isAdmin) {
            out.put("adminData", jdbc.queryForList(
                    "SELECT username, role, ssn FROM users"));
        } else {
            out.put("message", "regular user dashboard — pass X-Role: admin to unlock admin data");
        }
        return out;
    }

    // ========================================================================
    // SAFE REFERENCE — server-side ownership/role check for the IDOR in P1.
    // The "current user" is simulated via ?current= (defaults to 'alice'); a note
    // is returned ONLY when it is public or owned by the current user. Shown so
    // the vulnerable/safe pair can be diffed by SAST tooling and learners.
    // ========================================================================
    @GetMapping("/note-safe")
    public Map<String, Object> noteSafe(@RequestParam(defaultValue = "1") int id,
                                        @RequestParam(defaultValue = "alice") String current) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, owner, title, body, private FROM notes WHERE id = ?", id);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("currentUser", current);
        if (rows.isEmpty()) {
            out.put("note", null);
            return out;
        }
        Map<String, Object> row = rows.get(0);
        boolean isPublic = ((Number) row.get("PRIVATE")).intValue() == 0;
        boolean isOwner = current.equals(row.get("OWNER"));
        // SAFE: enforce the ownership/visibility policy on the server before returning.
        if (isPublic || isOwner) {
            out.put("note", row);
        } else {
            out.put("note", null);
            out.put("error", "403 forbidden — note " + id + " is private and not owned by " + current);
        }
        return out;
    }
}
