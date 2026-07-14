/**
 * SQLite helper + deterministic seed data, mirroring the Python and Java apps.
 *
 * Uses Node's built-in `node:sqlite` (stable-ish, requires Node >= 22.5) so the
 * SQL-injection demos run against a real engine with no native build step.
 */
'use strict';

const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');

let db;

function md5(value) {
  // VULNERABILITY (Cryptographic Failures): MD5, unsalted, for passwords.
  return crypto.createHash('md5').update(value).digest('hex');
}

function initDb() {
  db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE users (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      password TEXT NOT NULL,   -- unsalted MD5 hash (see crypto demo)
      email    TEXT,
      role     TEXT NOT NULL DEFAULT 'user',
      ssn      TEXT             -- "sensitive" field used by IDOR / crypto demos
    );
    CREATE TABLE notes (
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      owner   TEXT NOT NULL,
      title   TEXT,
      body    TEXT,             -- rendered unescaped by the stored-XSS demo
      private INTEGER NOT NULL DEFAULT 0
    );
  `);

  const insUser = db.prepare(
    'INSERT INTO users (username, password, email, role, ssn) VALUES (?, ?, ?, ?, ?)'
  );
  insUser.run('alice', md5('password1'), 'alice@example.com', 'user', '111-11-1111');
  insUser.run('bob', md5('bobs-dog-2019'), 'bob@example.com', 'user', '222-22-2222');
  insUser.run('admin', md5('admin123'), 'admin@example.com', 'admin', '999-99-9999');

  const insNote = db.prepare(
    'INSERT INTO notes (owner, title, body, private) VALUES (?, ?, ?, ?)'
  );
  insNote.run('alice', 'Shopping list', 'milk, eggs, bread', 0);
  insNote.run('alice', 'Bank PIN reminder', 'PIN is 4821 (do not share)', 1);
  insNote.run('bob', 'Public note', 'hello world', 0);
  insNote.run('admin', 'Ops runbook', 'prod db password: hunter2', 1);

  return db;
}

function getDb() {
  if (!db) initDb();
  return db;
}

module.exports = { initDb, getDb, md5 };
