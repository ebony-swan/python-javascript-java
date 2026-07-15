package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"log"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo)
)

var db *sql.DB

// md5hex is the (deliberately weak) password hash used across the lab.
func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// initDB creates and seeds a shared in-memory SQLite database. Same schema and
// seed data as the Python/JS/Java apps so the docs cross-reference cleanly:
// users alice/bob (role user) + admin (role admin); notes id=2 and id=4 private.
func initDB() {
	var err error
	db, err = sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(1) // keep the shared in-memory database alive for the process
	must(`CREATE TABLE users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		password TEXT NOT NULL,      -- unsalted MD5 hash (see crypto demo)
		email TEXT,
		role TEXT NOT NULL DEFAULT 'user',
		ssn TEXT)`)
	must(`CREATE TABLE notes(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		owner TEXT NOT NULL,
		title TEXT,
		body TEXT,                   -- rendered unescaped by the stored-XSS demo
		private INTEGER NOT NULL DEFAULT 0)`)
	if _, err := db.Exec(`INSERT INTO users(username,password,email,role,ssn) VALUES
		('alice',?,'alice@example.com','user','111-11-1111'),
		('bob',?,'bob@example.com','user','222-22-2222'),
		('admin',?,'admin@example.com','admin','999-99-9999')`,
		md5hex("password1"), md5hex("bobs-dog-2019"), md5hex("admin123")); err != nil {
		log.Fatal(err)
	}
	must(`INSERT INTO notes(owner,title,body,private) VALUES
		('alice','Shopping list','milk, eggs, bread',0),
		('alice','Bank PIN reminder','PIN is 4821 (do not share)',1),
		('bob','Public note','hello world',0),
		('admin','Ops runbook','prod db password: hunter2',1)`)
}

func must(q string) {
	if _, err := db.Exec(q); err != nil {
		log.Fatal(err)
	}
}
