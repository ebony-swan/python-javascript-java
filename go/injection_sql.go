// SQL Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
//
// Reference module for the Go app: mirror this annotation format and the
// init()-based registration in every other Go vulnerability module.
package main

import (
	"fmt"
	"net/http"
)

func init() {
	register("GET /injection/sql/login", "SQLi: auth bypass via string concat", sqlLogin)
	register("GET /injection/sql/search", "SQLi: UNION data theft", sqlSearch)
	register("GET /injection/sql/notes", "SQLi: dynamic ORDER BY", sqlNotes)
	register("GET /injection/sql/login-safe", "SAFE: parameterized query", sqlLoginSafe)
}

// ============================================================================
// PERMUTATION 1 — SQL injection via string concatenation (auth bypass)
// OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
// EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic, no tooling; the
//   textbook  admin'--  /  ' OR '1'='1  payloads bypass the login.
// PREVALENCE TODAY: greenfield LOW-MED (database/sql encourages placeholders;
//   recurs when devs fmt.Sprintf queries) | legacy/10yr tech-debt HIGH.
// EXAMPLE: GET /injection/sql/login?username=admin'--&password=x
// FIX: use parameter placeholders (see /injection/sql/login-safe).
// ============================================================================
func sqlLogin(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("username")
	p := r.URL.Query().Get("password")
	// VULNERABLE: user input concatenated straight into the SQL string.
	q := fmt.Sprintf("SELECT id, username, role FROM users WHERE username='%s' AND password='%s'", u, p)
	rows, err := db.Query(q)
	if err != nil {
		writeJSON(w, 500, map[string]any{"query": q, "error": err.Error()})
		return
	}
	defer rows.Close()
	list, err := queryToMaps(rows)
	if err != nil {
		writeJSON(w, 500, map[string]any{"query": q, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"query": q, "authenticated": len(list) > 0, "as": first(list)})
}

// ============================================================================
// PERMUTATION 2 — SQL injection via fmt.Sprintf (UNION data theft)
// OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
// CWE-89
// EXPLOITATION LIKELIHOOD: HIGH — a UNION SELECT dumps password hashes and SSNs
//   from the users table through a notes search box.
// PREVALENCE TODAY: greenfield MEDIUM (raw SQL persists in search/reporting) |
//   legacy/10yr tech-debt HIGH.
// EXAMPLE: GET /injection/sql/search?q=zzz' UNION SELECT username, password, ssn FROM users--
// FIX: parameterize the WHERE clause.
// ============================================================================
func sqlSearch(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q")
	// VULNERABLE: interpolated LIKE clause.
	q := fmt.Sprintf("SELECT title, body, owner FROM notes WHERE body LIKE '%%%s%%'", term)
	rows, err := db.Query(q)
	if err != nil {
		writeJSON(w, 500, map[string]any{"query": q, "error": err.Error()})
		return
	}
	defer rows.Close()
	list, err := queryToMaps(rows)
	if err != nil {
		writeJSON(w, 500, map[string]any{"query": q, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"query": q, "results": list})
}

// ============================================================================
// PERMUTATION 3 — SQL injection via a dynamic ORDER BY clause
// OWASP 2021 A03 Injection      OWASP 2025 A05 Injection
// CWE-89
// EXPLOITATION LIKELIHOOD: MEDIUM — identifiers can't be placeholders, so a
//   concatenated sort field enables blind boolean/error-based extraction.
// PREVALENCE TODAY: greenfield MED-HIGH (ORDER BY columns can't be bound, so
//   concatenation stays common even in modern code) | legacy HIGH.
// EXAMPLE: GET /injection/sql/notes?sort=body--
// FIX: allow-list sortable column names.
// ============================================================================
func sqlNotes(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")
	if sort == "" {
		sort = "id"
	}
	// VULNERABLE: sort field concatenated into ORDER BY.
	q := fmt.Sprintf("SELECT id, owner, title FROM notes ORDER BY %s", sort)
	rows, err := db.Query(q)
	if err != nil {
		writeJSON(w, 500, map[string]any{"query": q, "error": err.Error()})
		return
	}
	defer rows.Close()
	list, _ := queryToMaps(rows)
	writeJSON(w, 200, map[string]any{"query": q, "results": list})
}

// ============================================================================
// SAFE REFERENCE — parameterized query. Shown so the vulnerable/safe pair can
// be diffed by SAST tooling and learners.
// ============================================================================
func sqlLoginSafe(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("username")
	p := r.URL.Query().Get("password")
	rows, err := db.Query("SELECT id, username, role FROM users WHERE username=? AND password=?", u, p)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()
	list, _ := queryToMaps(rows)
	writeJSON(w, 200, map[string]any{"authenticated": len(list) > 0, "as": first(list)})
}
