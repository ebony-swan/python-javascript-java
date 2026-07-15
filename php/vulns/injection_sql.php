<?php
/**
 * SQL Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
 *
 * Reference module for the PHP app: mirror this annotation format and the
 * route() registration in every other PHP vulnerability module.
 */

// ============================================================================
// PERMUTATION 1 — SQL injection via string interpolation (auth bypass)
// OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
// EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic, no tooling; the
//   textbook  admin'--  /  ' OR '1'='1  payloads bypass the login.
// PREVALENCE TODAY: greenfield MEDIUM (PDO offers prepares, but string SQL is
//   still idiomatic in lots of PHP) | legacy/10yr tech-debt HIGH (mysql_query /
//   concatenated SQL is the archetypal old-PHP bug).
// EXAMPLE: GET /injection/sql/login?username=admin'--&password=x
// FIX: use prepared statements with bound parameters (see /injection/sql/login-safe).
// ============================================================================
route('GET', '/injection/sql/login', function () {
    $u = $_GET['username'] ?? '';
    $p = $_GET['password'] ?? '';
    // VULNERABLE: user input interpolated straight into the SQL string.
    $sql = "SELECT id, username, role FROM users WHERE username='$u' AND password='$p'";
    try {
        $rows = get_db()->query($sql)->fetchAll(PDO::FETCH_ASSOC);
        json_response(['query' => $sql, 'authenticated' => count($rows) > 0, 'as' => $rows[0] ?? null]);
    } catch (Throwable $e) {
        json_response(['query' => $sql, 'error' => $e->getMessage()], 500);
    }
}, 'SQLi: auth bypass via string interpolation');

// ============================================================================
// PERMUTATION 2 — SQL injection via interpolation (UNION data theft)
// OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
// CWE-89
// EXPLOITATION LIKELIHOOD: HIGH — a UNION SELECT dumps password hashes and SSNs
//   from the users table through a notes search box.
// PREVALENCE TODAY: greenfield MEDIUM (raw SQL persists in search/reporting) |
//   legacy/10yr tech-debt HIGH.
// EXAMPLE: GET /injection/sql/search?q=zzz' UNION SELECT username, password, ssn FROM users--
// FIX: parameterize the WHERE clause.
// ============================================================================
route('GET', '/injection/sql/search', function () {
    $q = $_GET['q'] ?? '';
    // VULNERABLE: interpolated LIKE clause.
    $sql = "SELECT title, body, owner FROM notes WHERE body LIKE '%$q%'";
    try {
        $rows = get_db()->query($sql)->fetchAll(PDO::FETCH_ASSOC);
        json_response(['query' => $sql, 'results' => $rows]);
    } catch (Throwable $e) {
        json_response(['query' => $sql, 'error' => $e->getMessage()], 500);
    }
}, 'SQLi: UNION data theft');

// ============================================================================
// PERMUTATION 3 — SQL injection via a dynamic ORDER BY clause
// OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
// CWE-89
// EXPLOITATION LIKELIHOOD: MEDIUM — identifiers can't be bound, so a
//   concatenated sort field enables blind boolean/error-based extraction.
// PREVALENCE TODAY: greenfield MED-HIGH (ORDER BY columns can't be parameterized
//   so concatenation stays common even in modern code) | legacy HIGH.
// EXAMPLE: GET /injection/sql/notes?sort=body--
// FIX: allow-list sortable column names.
// ============================================================================
route('GET', '/injection/sql/notes', function () {
    $sort = $_GET['sort'] ?? 'id';
    // VULNERABLE: sort field concatenated into ORDER BY.
    $sql = "SELECT id, owner, title FROM notes ORDER BY $sort";
    try {
        $rows = get_db()->query($sql)->fetchAll(PDO::FETCH_ASSOC);
        json_response(['query' => $sql, 'results' => $rows]);
    } catch (Throwable $e) {
        json_response(['query' => $sql, 'error' => $e->getMessage()], 500);
    }
}, 'SQLi: dynamic ORDER BY');

// ============================================================================
// SAFE REFERENCE — prepared statement with bound parameters. Shown so the
// vulnerable/safe pair can be diffed by SAST tooling and learners.
// ============================================================================
route('GET', '/injection/sql/login-safe', function () {
    $u = $_GET['username'] ?? '';
    $p = $_GET['password'] ?? '';
    $stmt = get_db()->prepare('SELECT id, username, role FROM users WHERE username=? AND password=?');
    $stmt->execute([$u, $p]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    json_response(['authenticated' => count($rows) > 0, 'as' => $rows[0] ?? null]);
}, 'SAFE: prepared statement');
