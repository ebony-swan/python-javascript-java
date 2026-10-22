"""SQL Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.

Reference module: the comment/annotation format used here is mirrored by every
other vulnerability module in this app. Each permutation carries a standard
header describing the flaw, its CWE, an exploitation-likelihood rating, an
example payload, and the corresponding safe pattern.
"""
from flask import Blueprint, request, jsonify

from app.db import get_db

bp = Blueprint("injection_sql", __name__, url_prefix="/injection/sql")


# =============================================================================
# PERMUTATION 1 — SQL injection via string concatenation (auth bypass)
# OWASP 2021: A03 Injection      OWASP 2025: A05 Injection
# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# EXPLOITATION LIKELIHOOD: HIGH
#   Reachable pre-authentication, deterministic, no tooling required. The
#   textbook  ' OR '1'='1  / username=admin'--  payloads bypass login.
# PREVALENCE TODAY: greenfield LOW-MED (modern ORMs parameterize by default;
#   recurs in raw SQL and AI-generated snippets) | legacy/10yr tech-debt HIGH.
# EXAMPLE:
#   GET /injection/sql/login?username=admin'--&password=whatever
#   GET /injection/sql/login?username=x' OR '1'='1&password=x
# FIX: parameterize (see /injection/sql/login-safe).
# =============================================================================
@bp.get("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    db = get_db()
    # VULNERABLE: user input concatenated straight into the SQL string.
    sql = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    try:
        row = db.execute(sql, (username, password)).fetchone()
    except Exception as exc:  # verbose errors also aid the attacker
        return jsonify({"query": sql, "error": str(exc)}), 500
    if row:
        return jsonify({"authenticated": True, "as": dict(row), "query": sql})
    return jsonify({"authenticated": False, "query": sql})


# =============================================================================
# PERMUTATION 2 — SQL injection via f-string interpolation (UNION data theft)
# OWASP 2021: A03 Injection      OWASP 2025: A05 Injection
# CWE-89
# EXPLOITATION LIKELIHOOD: HIGH
#   A UNION SELECT lets an attacker read arbitrary columns/tables (e.g. dump
#   password hashes and SSNs from the users table) through a search box.
# PREVALENCE TODAY: greenfield MEDIUM (raw SQL persists in search/reporting/
#   analytics paths) | legacy/10yr tech-debt HIGH.
# EXAMPLE:
#   GET /injection/sql/search?q=zzz' UNION SELECT username, password, ssn FROM users--
# FIX: parameterize the WHERE clause.
# =============================================================================
@bp.get("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    # VULNERABLE: f-string interpolation of untrusted input into SQL.
    sql = f"SELECT title, body, owner FROM notes WHERE body LIKE '%{q}%'"
    try:
        rows = [dict(r) for r in db.execute(sql).fetchall()]
    except Exception as exc:
        return jsonify({"query": sql, "error": str(exc)}), 500
    return jsonify({"query": sql, "results": rows})


# =============================================================================
# PERMUTATION 3 — SQL injection via a dynamic ORDER BY clause
# OWASP 2021: A03 Injection      OWASP 2025: A05 Injection
# CWE-89
# EXPLOITATION LIKELIHOOD: MEDIUM
#   Column/keyword positions cannot be bound as parameters, so developers often
#   concatenate sort fields. Exploitable for blind boolean/error-based
#   extraction and ordering oracles; needs more skill than a UNION.
# PREVALENCE TODAY: greenfield MED-HIGH (SQL identifiers/sort columns cannot be
#   bound, so concatenated ORDER BY stays common in modern ORM apps) | legacy HIGH.
# EXAMPLE:
#   GET /injection/sql/notes?sort=body--          (breaks/oracles the query)
#   GET /injection/sql/notes?sort=(CASE WHEN (SELECT 1)=1 THEN title ELSE body END)
# FIX: allow-list sortable column names (see safe pattern below).
# =============================================================================
@bp.get("/notes")
def notes_sorted():
    sort = request.args.get("sort", "id")
    db = get_db()
    # VULNERABLE: sort field concatenated into ORDER BY.
    sql = f"SELECT id, owner, title FROM notes ORDER BY {sort}"
    try:
        rows = [dict(r) for r in db.execute(sql).fetchall()]
    except Exception as exc:
        return jsonify({"query": sql, "error": str(exc)}), 500
    return jsonify({"query": sql, "results": rows})


# =============================================================================
# SAFE REFERENCE — parameterized query + allow-listed identifier.
# Shown so the vulnerable/safe pair can be diffed by SAST tools and learners.
# =============================================================================
@bp.get("/login-safe")
def login_safe():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    db = get_db()
    row = db.execute(
        "SELECT id, username, role FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    return jsonify({"authenticated": bool(row), "as": dict(row) if row else None})
