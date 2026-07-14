package com.example.vulnapp.vulns;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * SQL Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
 *
 * Reference module: the comment/annotation format used here is mirrored by
 * every other vulnerability controller in this app. Each permutation carries a
 * standard header describing the flaw, its CWE, an exploitation-likelihood
 * rating, an example payload, and the corresponding safe pattern.
 */
@RestController
@RequestMapping("/injection/sql")
public class SqlInjectionController {

    private final JdbcTemplate jdbc;

    public SqlInjectionController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // ========================================================================
    // PERMUTATION 1 — SQL injection via string concatenation (auth bypass)
    // OWASP 2021: A03 Injection      OWASP 2025: A05 Injection
    // CWE-89: Improper Neutralization of Special Elements used in an SQL Command
    // EXPLOITATION LIKELIHOOD: HIGH
    //   Reachable pre-authentication, deterministic, no tooling required.
    //   The textbook  ' OR '1'='1  / username=admin'--  payloads bypass login.
    // PREVALENCE TODAY: greenfield LOW-MED (modern ORMs parameterize by default;
    //   recurs in raw SQL and AI-generated snippets) | legacy/10yr tech-debt HIGH.
    // EXAMPLE:
    //   GET /injection/sql/login?username=admin'--&password=whatever
    //   GET /injection/sql/login?username=x' OR '1'='1&password=x
    // FIX: parameterize (see /injection/sql/login-safe).
    // ========================================================================
    @GetMapping("/login")
    public Map<String, Object> login(@RequestParam(defaultValue = "") String username,
                                     @RequestParam(defaultValue = "") String password) {
        // VULNERABLE: user input concatenated straight into the SQL string.
        String sql = "SELECT id, username, role FROM users "
                + "WHERE username = '" + username + "' AND password = '" + password + "'";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("query", sql);
        try {
            List<Map<String, Object>> rows = jdbc.queryForList(sql);
            out.put("authenticated", !rows.isEmpty());
            out.put("as", rows.isEmpty() ? null : rows.get(0));
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return out;
    }

    // ========================================================================
    // PERMUTATION 2 — SQL injection via String.format (UNION data theft)
    // OWASP 2021: A03 Injection      OWASP 2025: A05 Injection
    // CWE-89
    // EXPLOITATION LIKELIHOOD: HIGH
    //   A UNION SELECT reads arbitrary columns/tables (e.g. dump password
    //   hashes and SSNs from the users table) through a search box.
    // PREVALENCE TODAY: greenfield MEDIUM (raw SQL persists in search/reporting/
    //   analytics paths) | legacy/10yr tech-debt HIGH.
    // EXAMPLE:
    //   GET /injection/sql/search?q=zzz' UNION SELECT username, password, ssn FROM users--
    // FIX: parameterize the WHERE clause.
    // ========================================================================
    @GetMapping("/search")
    public Map<String, Object> search(@RequestParam(defaultValue = "") String q) {
        // VULNERABLE: String.format interpolation of untrusted input into SQL.
        String sql = String.format(
                "SELECT title, body, owner FROM notes WHERE body LIKE '%%%s%%'", q);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("query", sql);
        try {
            out.put("results", jdbc.queryForList(sql));
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return out;
    }

    // ========================================================================
    // PERMUTATION 3 — SQL injection via a dynamic ORDER BY clause
    // OWASP 2021: A03 Injection      OWASP 2025: A05 Injection
    // CWE-89
    // EXPLOITATION LIKELIHOOD: MEDIUM
    //   Column/keyword positions cannot be bound as parameters, so developers
    //   often concatenate sort fields. Exploitable for blind boolean/error-based
    //   extraction; needs more skill than a UNION.
    // PREVALENCE TODAY: greenfield MED-HIGH (SQL identifiers/sort columns cannot be
    //   bound, so concatenated ORDER BY stays common in modern ORM apps) | legacy HIGH.
    // EXAMPLE:
    //   GET /injection/sql/notes?sort=body--
    //   GET /injection/sql/notes?sort=(SELECT CASE WHEN 1=1 THEN id ELSE owner END)
    // FIX: allow-list sortable column names.
    // ========================================================================
    @GetMapping("/notes")
    public Map<String, Object> notesSorted(@RequestParam(defaultValue = "id") String sort) {
        // VULNERABLE: sort field concatenated into ORDER BY.
        String sql = "SELECT id, owner, title FROM notes ORDER BY " + sort;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("query", sql);
        try {
            out.put("results", jdbc.queryForList(sql));
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return out;
    }

    // ========================================================================
    // SAFE REFERENCE — parameterized query. Shown so the vulnerable/safe pair
    // can be diffed by SAST tooling and learners.
    // ========================================================================
    @GetMapping("/login-safe")
    public Map<String, Object> loginSafe(@RequestParam(defaultValue = "") String username,
                                         @RequestParam(defaultValue = "") String password) {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, username, role FROM users WHERE username = ? AND password = ?",
                username, password);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("authenticated", !rows.isEmpty());
        out.put("as", rows.isEmpty() ? null : rows.get(0));
        return out;
    }
}
