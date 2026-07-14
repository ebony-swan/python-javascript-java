"""SQLite helper + deterministic seed data.

The database is dropped and re-seeded on every startup so the demo always
behaves the same. Modules use :func:`get_db` to obtain a connection.
"""
import hashlib
import os
import sqlite3

from flask import g

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "vulnapp.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")


def _md5(value: str) -> str:
    # VULNERABILITY (Cryptographic Failures): MD5, unsalted, for passwords.
    return hashlib.md5(value.encode()).hexdigest()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH) as fh:
        con.executescript(fh.read())

    users = [
        ("alice", _md5("password1"), "alice@example.com", "user", "111-11-1111"),
        ("bob", _md5("bobs-dog-2019"), "bob@example.com", "user", "222-22-2222"),
        ("admin", _md5("admin123"), "admin@example.com", "admin", "999-99-9999"),
    ]
    con.executemany(
        "INSERT INTO users (username, password, email, role, ssn) VALUES (?, ?, ?, ?, ?)",
        users,
    )

    notes = [
        ("alice", "Shopping list", "milk, eggs, bread", 0),
        ("alice", "Bank PIN reminder", "PIN is 4821 (do not share)", 1),
        ("bob", "Public note", "hello world", 0),
        ("admin", "Ops runbook", "prod db password: hunter2", 1),
    ]
    con.executemany(
        "INSERT INTO notes (owner, title, body, private) VALUES (?, ?, ?, ?)",
        notes,
    )
    con.commit()
    con.close()


def init_app(app):
    app.teardown_appcontext(close_db)
    init_db()
