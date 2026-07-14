-- Shared demo schema. Mirrors the JavaScript and Java apps so the docs can
-- cross-reference the same tables/data across all three languages.

DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT    NOT NULL,
    password TEXT    NOT NULL,   -- stored as an unsalted MD5 hash (see crypto demo)
    email    TEXT,
    role     TEXT    NOT NULL DEFAULT 'user',
    ssn      TEXT                 -- "sensitive" field used by IDOR / crypto demos
);

DROP TABLE IF EXISTS notes;
CREATE TABLE notes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    owner   TEXT    NOT NULL,
    title   TEXT,
    body    TEXT,                 -- rendered unescaped by the stored-XSS demo
    private INTEGER NOT NULL DEFAULT 0
);
