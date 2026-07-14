"""Broken Access Control — OWASP 2021 A01  ->  OWASP 2025 A01.

Access-control flaws are *authorization* bugs: the request is understood, often
even authenticated, but the server fails to check whether *this* caller may act
on *this* object or reach *this* function. Unlike injection, no framework or ORM
fixes them for you — object- and function-level authorization is application
logic that must be written (and reviewed) by hand.

The comment/annotation format here mirrors the reference module
``app/vulns/injection_sql.py``: each permutation carries a standard header with
its CWE, an exploitation-likelihood rating, prevalence notes, an example
request, and the corresponding safe pattern.
"""
from flask import Blueprint, request, jsonify

from app.db import get_db

bp = Blueprint("access_control", __name__, url_prefix="/access")


# =============================================================================
# PERMUTATION 1 — IDOR: read any note by id, no ownership check
# OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
# CWE-639: Authorization Bypass Through User-Controlled Key
# EXPLOITATION LIKELIHOOD: HIGH — a single integer parameter selects the object;
#   ids are sequential so an attacker just enumerates 1,2,3,… to walk every
#   record, private ones included. No auth, no tooling, fully deterministic.
# PREVALENCE TODAY: greenfield HIGH (ORMs/frameworks are safe-by-default against
#   SQLi but provide NO object-level ownership check — `Note.get(id)` happily
#   returns anyone's row) | legacy/10yr tech-debt HIGH (raw id->row lookups with
#   authorization "handled elsewhere" are endemic).
# EXAMPLE:
#   GET /access/note?id=2   -> alice's private "Bank PIN reminder"
#   GET /access/note?id=4   -> admin's private "Ops runbook" (prod db password)
# FIX: scope every lookup to the caller — WHERE id=? AND (private=0 OR owner=?)
#      — and verify ownership before returning (see /access/note-safe).
# =============================================================================
@bp.get("/note")
def note():
    note_id = request.args.get("id", "")
    db = get_db()
    # VULNERABLE: the note is fetched and returned for ANY id with no check that
    # the caller owns it or that it is public — the private flag is ignored.
    row = db.execute(
        "SELECT id, owner, title, body, private FROM notes WHERE id = ?",
        (note_id,),
    ).fetchone()
    if row is None:
        return jsonify({"id": note_id, "note": None})
    return jsonify({"id": note_id, "note": dict(row)})


# =============================================================================
# PERMUTATION 2 — Missing function-level authorization on an admin endpoint
# OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
# CWE-862: Missing Authorization
# EXPLOITATION LIKELIHOOD: HIGH — the "admin" URL has zero authentication or
#   role gate; anyone who knows (or guesses) the path dumps every user's md5
#   password hash, email and SSN. Pre-auth, one request, catastrophic impact.
# PREVALENCE TODAY: greenfield MEDIUM (auth middleware/decorators are standard,
#   but newly-added admin/internal/debug routes routinely ship without the guard
#   — "protected by being unlinked") | legacy/10yr tech-debt HIGH (authorization
#   scattered across handlers by hand, trivially forgotten on new endpoints).
# EXAMPLE:
#   curl http://127.0.0.1:5000/access/admin/users
#     -> [{username:admin, password:<md5>, ssn:999-99-9999, role:admin}, …]
# FIX: require authentication AND an explicit role check (deny-by-default) on
#      every privileged route, enforced by middleware — never by obscurity.
# =============================================================================
@bp.get("/admin/users")
def admin_users():
    db = get_db()
    # VULNERABLE: privileged data returned with no authentication or role check.
    rows = [
        dict(r)
        for r in db.execute(
            "SELECT id, username, password, email, role, ssn FROM users"
        ).fetchall()
    ]
    return jsonify({"note": "no auth/role check performed", "users": rows})


# =============================================================================
# PERMUTATION 3 — Mass assignment / privilege escalation
# OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
# CWE-915: Improperly Controlled Modification of Dynamically-Determined Object
#          Attributes (Mass Assignment / autobinding)
# EXPLOITATION LIKELIHOOD: HIGH — the handler writes EVERY field in the request
#   body to the user's row, so a normal user smuggles an extra `role` key and
#   promotes themselves to admin. One authenticated POST, no special tooling.
# PREVALENCE TODAY: greenfield MEDIUM (explicit DTOs/serializers with an allow-
#   list of fields help, but "spread req.body into the model" and frameworks
#   that auto-bind request params to entities keep it alive) | legacy/10yr
#   tech-debt HIGH (whole-object updates from the form/body are the default).
# EXAMPLE:
#   curl -X POST -H 'Content-Type: application/json' \
#     -d '{"username":"alice","email":"a@x.com","role":"admin"}' \
#     http://127.0.0.1:5000/access/profile      -> alice.role becomes "admin"
# FIX: bind only a fixed allow-list of user-editable columns (username, email);
#      never let a privileged column like `role` be set from the request body.
# =============================================================================
@bp.post("/profile")
def profile():
    data = request.get_json(silent=True)
    if data is None:
        data = request.form.to_dict()
    data = data or {}
    username = data.get("username", "")
    # VULNERABLE: every key present in the body (except the selector) is written
    # straight to the row — including privileged columns such as `role`.
    updates = {col: val for col, val in data.items() if col != "username"}
    set_clause = ", ".join(f"{col} = ?" for col in updates)
    sql = f"UPDATE users SET {set_clause} WHERE username = ?"
    params = list(updates.values()) + [username]
    db = get_db()
    try:
        db.execute(sql, params)
        db.commit()
    except Exception as exc:
        return jsonify({"query": sql, "error": str(exc)}), 500
    row = db.execute(
        "SELECT id, username, email, role, ssn FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    return jsonify({"query": sql, "updated": dict(row) if row else None})


# =============================================================================
# PERMUTATION 4 — Client-controlled authorization (trusting a client value)
# OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 Broken Access Control
# CWE-602: Client-Side Enforcement of Server-Side Security
# EXPLOITATION LIKELIHOOD: HIGH — the admin decision is read from an attacker-
#   supplied `X-Role` header (or `?role=` param) and trusted verbatim; sending
#   `X-Role: admin` unlocks admin-only data. Trivial, deterministic, pre-auth.
# PREVALENCE TODAY: greenfield LOW (server-verified session/JWT claims are the
#   safe default; a raw header deciding a role is an obvious review smell) —
#   though microservice "trust the gateway header" designs reintroduce it |
#   legacy/10yr tech-debt HIGH (hand-rolled auth reading a role from a header,
#   cookie value, or hidden form field the client can just rewrite).
# EXAMPLE:
#   curl -H 'X-Role: admin' http://127.0.0.1:5000/access/dashboard
#   GET /access/dashboard?role=admin
# FIX: derive the role from a server-side, cryptographically-verified session or
#      signed token — never from a header/param/cookie the client can set.
# =============================================================================
@bp.get("/dashboard")
def dashboard():
    # VULNERABLE: authorization decided from a value the client fully controls.
    role = request.headers.get("X-Role") or request.args.get("role", "user")
    if role == "admin":
        db = get_db()
        secret = [
            dict(r)
            for r in db.execute(
                "SELECT username, password, ssn FROM users"
            ).fetchall()
        ]
        return jsonify({"role": role, "admin": True, "secret_data": secret})
    return jsonify({"role": role, "admin": False, "data": "public dashboard only"})


# =============================================================================
# SAFE REFERENCE — server-side ownership/visibility enforcement.
# The current user is simulated with ?current= (defaulting to 'alice'); a note
# is only returned when it is public OR owned by that user. Shown so the
# vulnerable/safe pair (this vs PERMUTATION 1) can be diffed by SAST and learners.
# =============================================================================
@bp.get("/note-safe")
def note_safe():
    note_id = request.args.get("id", "")
    current = request.args.get("current", "alice")
    db = get_db()
    row = db.execute(
        "SELECT id, owner, title, body, private FROM notes WHERE id = ?",
        (note_id,),
    ).fetchone()
    if row is None:
        return jsonify({"error": "not found", "id": note_id}), 404
    # SAFE: enforce visibility/ownership on the server before returning anything.
    if row["private"] and row["owner"] != current:
        return jsonify({"error": "forbidden", "id": note_id, "current": current}), 403
    return jsonify({"current": current, "note": dict(row)})
