// Broken Access Control — OWASP 2021 A01 Broken Access Control | OWASP 2025 A01 Broken Access Control.
//
// Permutations: IDOR (CWE-639), missing function-level authorization (CWE-862),
// mass assignment (CWE-915) and client-controlled authorization (CWE-602).
// Mirrors the annotation format and init()-based self-registration of
// injection_sql.go — main.go auto-discovers these with no wiring changes.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func init() {
	register("GET /access/note", "IDOR: note by id, no ownership/private check", accessNote)
	register("GET /access/admin/users", "Missing function-level authz: dump all users", accessAdminUsers)
	register("POST /access/profile", "Mass assignment: role settable from request body", accessProfile)
	register("GET /access/dashboard", "Client-controlled authz via X-Role header/param", accessDashboard)
	register("GET /access/note-safe", "SAFE: server-side ownership/role check", accessNoteSafe)
}

// ============================================================================
// PERMUTATION 1 — Insecure Direct Object Reference (IDOR)
// OWASP 2021 A01 Broken Access Control -> OWASP 2025 A01 Broken Access Control
// CWE-639: Authorization Bypass Through User-Controlled Key
// EXPLOITATION LIKELIHOOD: HIGH — a single client-controlled integer selects the
//   record; no tooling, fully deterministic, enumerate ids to harvest every
//   private note. Object-level authz is the top real-world API weakness.
// PREVALENCE TODAY: greenfield MEDIUM (frameworks/ORMs give NO automatic
//   per-object ownership checks — the dev must remember to add them, and IDOR
//   still tops the OWASP API list) | legacy/10yr tech-debt HIGH (CRUD-by-id
//   handlers written before object-level authorization was a habit).
// EXAMPLE: GET /access/note?id=4   -> returns admin's private "Ops runbook"
//          GET /access/note?id=2   -> returns alice's private "Bank PIN reminder"
// FIX: after fetching, verify the row's owner == current principal (or public);
//   see /access/note-safe.
// ============================================================================
func accessNote(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	q := "SELECT id, owner, title, body, private FROM notes WHERE id=?"
	// VULNERABLE: the row is returned to anyone who names its id — no check that
	// the note is public or belongs to the caller, so private ids 2 and 4 leak.
	rows, err := db.Query(q, id)
	if err != nil {
		writeJSON(w, 500, map[string]any{"query": q, "id": id, "error": err.Error()})
		return
	}
	defer rows.Close()
	list, err := queryToMaps(rows)
	if err != nil {
		writeJSON(w, 500, map[string]any{"query": q, "id": id, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"query": q, "id": id, "note": first(list)})
}

// ============================================================================
// PERMUTATION 2 — Missing function-level authorization
// OWASP 2021 A01 Broken Access Control -> OWASP 2025 A01 Broken Access Control
// CWE-862: Missing Authorization
// EXPLOITATION LIKELIHOOD: CRITICAL — an admin-only endpoint that is neither
//   authenticated nor role-gated; one unauthenticated GET dumps every username,
//   MD5 password hash, email and SSN. Pre-auth, deterministic, mass impact.
// PREVALENCE TODAY: greenfield LOW-MEDIUM (route middleware/guards enforce roles,
//   but a forgotten/internal endpoint slips past review) | legacy/10yr tech-debt
//   HIGH (admin panels "protected" only by an unguessable path — security by
//   obscurity — are common tech debt).
// EXAMPLE: curl http://127.0.0.1:8081/access/admin/users
// FIX: require an authenticated session AND role=admin before serving; enforce
//   it in shared middleware, not per-handler.
// ============================================================================
func accessAdminUsers(w http.ResponseWriter, r *http.Request) {
	q := "SELECT id, username, password, email, role, ssn FROM users"
	// VULNERABLE: no authentication and no role check guard this admin function,
	// so it discloses password hashes and SSNs to any anonymous caller.
	rows, err := db.Query(q)
	if err != nil {
		writeJSON(w, 500, map[string]any{"query": q, "error": err.Error()})
		return
	}
	defer rows.Close()
	list, _ := queryToMaps(rows)
	writeJSON(w, 200, map[string]any{"query": q, "note": "admin-only endpoint served without any auth check", "users": list})
}

// ============================================================================
// PERMUTATION 3 — Mass assignment / over-posting
// OWASP 2021 A01 Broken Access Control -> OWASP 2025 A01 Broken Access Control
// CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
// EXPLOITATION LIKELIHOOD: HIGH — a normal "edit my profile" call that also binds
//   the privileged `role` field: add one JSON key and self-escalate to admin.
//   Post-auth but trivial, deterministic, and yields full privilege escalation.
// PREVALENCE TODAY: greenfield MEDIUM (auto-binding ORMs — Rails/Sequelize/Spring
//   — still map unexpected fields unless the dev uses DTOs/strong-params/
//   allow-lists) | legacy/10yr tech-debt HIGH (bind-the-whole-form patterns
//   predate the DTO discipline).
// EXAMPLE: curl -X POST http://127.0.0.1:8081/access/profile \
//            -H 'Content-Type: application/json' \
//            -d '{"username":"alice","email":"a@x.com","role":"admin"}'
// FIX: bind only an explicit allow-list of user-editable fields (username,email);
//   never let `role` come from the request body.
// ============================================================================
func accessProfile(w http.ResponseWriter, r *http.Request) {
	// Collect every field the client posted (JSON body or form-encoded).
	body := map[string]string{}
	if strings.Contains(r.Header.Get("Content-Type"), "json") {
		tmp := map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&tmp)
		for k, v := range tmp {
			body[k] = fmt.Sprint(v)
		}
	} else {
		_ = r.ParseForm()
		for k := range r.Form {
			body[k] = r.Form.Get(k)
		}
	}

	username := body["username"]
	if username == "" {
		writeJSON(w, 400, map[string]any{"error": "username required"})
		return
	}

	// VULNERABLE: every posted field is bound to the user row, INCLUDING role and
	// other privileged columns — there is no per-field authorization, so a normal
	// user posting role=admin escalates their own privileges.
	bindable := map[string]bool{"email": true, "role": true, "ssn": true, "password": true}
	sets := []string{}
	args := []any{}
	applied := []string{}
	for k, v := range body {
		if k == "username" || !bindable[k] {
			continue
		}
		sets = append(sets, k+"=?") // column name is from the fixed allow-list above (no SQLi)
		args = append(args, v)
		applied = append(applied, k)
	}

	q := "UPDATE users SET " + strings.Join(sets, ", ") + " WHERE username=?"
	if len(sets) > 0 {
		args = append(args, username)
		if _, err := db.Exec(q, args...); err != nil {
			writeJSON(w, 500, map[string]any{"query": q, "error": err.Error()})
			return
		}
	}

	rows, err := db.Query("SELECT id, username, email, role, ssn FROM users WHERE username=?", username)
	if err != nil {
		writeJSON(w, 500, map[string]any{"query": q, "error": err.Error()})
		return
	}
	defer rows.Close()
	list, _ := queryToMaps(rows)
	writeJSON(w, 200, map[string]any{"query": q, "bound_fields": applied, "updated": first(list)})
}

// ============================================================================
// PERMUTATION 4 — Client-controlled authorization decision
// OWASP 2021 A01 Broken Access Control -> OWASP 2025 A01 Broken Access Control
// CWE-602: Client-Side Enforcement of Server-Side Security
// EXPLOITATION LIKELIHOOD: HIGH — the server trusts an attacker-set "X-Role"
//   header (or ?role=) as the authorization state; sending X-Role: admin unlocks
//   admin data. One curl flag, deterministic, no auth to defeat.
// PREVALENCE TODAY: greenfield LOW (roles come from a signed session/JWT claim
//   validated server-side, not a raw header) | legacy/10yr tech-debt MEDIUM
//   (apps behind a reverse proxy that trust X-Forwarded-*/X-Role headers a
//   client can still spoof if they reach the origin directly).
// EXAMPLE: curl -H 'X-Role: admin' http://127.0.0.1:8081/access/dashboard
//          curl 'http://127.0.0.1:8081/access/dashboard?role=admin'
// FIX: derive the role from the authenticated server-side session, never from a
//   client-supplied header or query parameter.
// ============================================================================
func accessDashboard(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	if role == "" {
		role = r.URL.Query().Get("role")
	}
	// VULNERABLE: the authorization decision is made from a client-controlled
	// value, so the client simply asserts its own privilege level.
	if role == "admin" {
		rows, err := db.Query("SELECT id, username, email, role, ssn FROM users")
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		defer rows.Close()
		list, _ := queryToMaps(rows)
		writeJSON(w, 200, map[string]any{"role_claimed": role, "admin": true, "secret_dashboard": "prod db password: hunter2", "users": list})
		return
	}
	writeJSON(w, 200, map[string]any{"role_claimed": role, "admin": false, "dashboard": "welcome — standard user view"})
}

// ============================================================================
// SAFE REFERENCE — server-side ownership/role check. Simulates the current user
// via ?current= (defaulting to alice) and only returns a note that is public or
// owned by that principal, returning 403 otherwise. Diff against accessNote to
// see the missing authorization gate.
// ============================================================================
func accessNoteSafe(w http.ResponseWriter, r *http.Request) {
	current := r.URL.Query().Get("current")
	if current == "" {
		current = "alice" // stand-in for the authenticated session principal
	}
	id := r.URL.Query().Get("id")

	rows, err := db.Query("SELECT id, owner, title, body, private FROM notes WHERE id=?", id)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()
	list, _ := queryToMaps(rows)
	if len(list) == 0 {
		writeJSON(w, 404, map[string]any{"error": "not found", "id": id})
		return
	}
	row := list[0]

	private := false
	switch v := row["private"].(type) {
	case int64:
		private = v != 0
	case int:
		private = v != 0
	case bool:
		private = v
	}
	owner, _ := row["owner"].(string)

	// SAFE: enforce object-level authorization on the server before disclosing.
	if private && owner != current {
		writeJSON(w, 403, map[string]any{"error": "forbidden", "id": id, "current": current})
		return
	}
	writeJSON(w, 200, map[string]any{"current": current, "note": row})
}
