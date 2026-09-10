using Microsoft.AspNetCore.Mvc;

namespace VulnApp.Controllers;

/// <summary>
/// SQL Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
///
/// Reference controller for the C# app: mirror this annotation format and the
/// attribute-routed action style in every other C# vulnerability controller.
/// </summary>
[ApiController]
public class SqlInjectionController : ControllerBase
{
    // ========================================================================
    // PERMUTATION 1 — SQL injection via string interpolation (auth bypass)
    // OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
    // CWE-89: Improper Neutralization of Special Elements used in an SQL Command
    // EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic, no tooling; the
    //   textbook  admin'--  /  ' OR '1'='1  payloads bypass the login.
    // PREVALENCE TODAY: greenfield LOW (EF Core parameterizes by default) |
    //   legacy/10yr tech-debt HIGH (hand-built ADO.NET/string SQL is common).
    // EXAMPLE: GET /injection/sql/login?username=admin'--&password=x
    // FIX: use parameters (see /injection/sql/login-safe).
    // ========================================================================
    [HttpGet("/injection/sql/login")]
    public IActionResult Login(string username = "", string password = "")
    {
        var sql = "SELECT id, username, role FROM users WHERE username=@u AND password=@p";
        try
        {
            var rows = Db.Query(sql, ("@u", username), ("@p", password));
            return new JsonResult(new { query = sql, authenticated = rows.Count > 0, @as = rows.Count > 0 ? rows[0] : null });
        }
        catch (Exception e)
        {
            return new JsonResult(new { query = sql, error = e.Message }) { StatusCode = 500 };
        }
    }

    // ========================================================================
    // PERMUTATION 2 — SQL injection via interpolation (UNION data theft)
    // OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
    // CWE-89
    // EXPLOITATION LIKELIHOOD: HIGH — a UNION SELECT dumps password hashes and
    //   SSNs from the users table through a notes search box.
    // PREVALENCE TODAY: greenfield MEDIUM (raw SQL persists in reporting) |
    //   legacy/10yr tech-debt HIGH.
    // EXAMPLE: GET /injection/sql/search?q=zzz' UNION SELECT username, password, ssn FROM users--
    // FIX: parameterize the WHERE clause.
    // ========================================================================
    [HttpGet("/injection/sql/search")]
    public IActionResult Search(string q = "")
    {
        // VULNERABLE: interpolated LIKE clause.
        var sql = $"SELECT title, body, owner FROM notes WHERE body LIKE '%{q}%'";
        try
        {
            return new JsonResult(new { query = sql, results = Db.Query(sql) });
        }
        catch (Exception e)
        {
            return new JsonResult(new { query = sql, error = e.Message }) { StatusCode = 500 };
        }
    }

    // ========================================================================
    // PERMUTATION 3 — SQL injection via a dynamic ORDER BY clause
    // OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
    // CWE-89
    // EXPLOITATION LIKELIHOOD: MEDIUM — identifiers can't be parameterized, so a
    //   concatenated sort field enables blind boolean/error-based extraction.
    // PREVALENCE TODAY: greenfield MED-HIGH (ORDER BY columns can't be bound) |
    //   legacy HIGH.
    // EXAMPLE: GET /injection/sql/notes?sort=body--
    // FIX: allow-list sortable column names.
    // ========================================================================
    [HttpGet("/injection/sql/notes")]
    public IActionResult Notes(string sort = "id")
    {
        // VULNERABLE: sort field concatenated into ORDER BY.
        var sql = $"SELECT id, owner, title FROM notes ORDER BY {sort}";
        try
        {
            return new JsonResult(new { query = sql, results = Db.Query(sql) });
        }
        catch (Exception e)
        {
            return new JsonResult(new { query = sql, error = e.Message }) { StatusCode = 500 };
        }
    }

    // ========================================================================
    // SAFE REFERENCE — parameterized query. Shown so the vulnerable/safe pair
    // can be diffed by SAST tooling and learners.
    // ========================================================================
    [HttpGet("/injection/sql/login-safe")]
    public IActionResult LoginSafe(string username = "", string password = "")
    {
        var rows = Db.Query("SELECT id, username, role FROM users WHERE username=@u AND password=@p",
            ("@u", username), ("@p", password));
        return new JsonResult(new { authenticated = rows.Count > 0, @as = rows.Count > 0 ? rows[0] : null });
    }
}
