<?php
// Shared helpers for the deliberately-vulnerable PHP demo app.
// Vulnerability modules in vulns/ call route() to self-register; index.php
// (the front controller) discovers them, so there is no central wiring to edit.

$ROUTES = [];

function route(string $method, string $path, callable $handler, string $desc = ''): void
{
    global $ROUTES;
    $ROUTES[] = ['method' => $method, 'path' => $path, 'handler' => $handler, 'desc' => $desc];
}

function json_response($data, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

// Shared SQLite connection. File-backed (not in-memory) because PHP's built-in
// server is shared-nothing: a file lets stored data (e.g. the stored-XSS
// comments) persist across requests. Same schema/seed as the other lab apps:
// users alice/bob (user) + admin (admin); notes id=2 and id=4 are private.
function get_db(): PDO
{
    static $db = null;
    if ($db === null) {
        $dir = __DIR__ . '/data';
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        $db = new PDO('sqlite:' . $dir . '/vulnapp.db');
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        seed_db($db);
    }
    return $db;
}

function seed_db(PDO $db): void
{
    $db->exec("CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,      -- unsalted MD5 hash (see crypto demo)
        email TEXT,
        role TEXT NOT NULL DEFAULT 'user',
        ssn TEXT)");
    $db->exec("CREATE TABLE IF NOT EXISTS notes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        title TEXT,
        body TEXT,                   -- rendered unescaped by the stored-XSS demo
        private INTEGER NOT NULL DEFAULT 0)");
    if ((int) $db->query("SELECT COUNT(*) FROM users")->fetchColumn() === 0) {
        $u = $db->prepare("INSERT INTO users(username,password,email,role,ssn) VALUES(?,?,?,?,?)");
        $u->execute(['alice', md5('password1'), 'alice@example.com', 'user', '111-11-1111']);
        $u->execute(['bob', md5('bobs-dog-2019'), 'bob@example.com', 'user', '222-22-2222']);
        $u->execute(['admin', md5('admin123'), 'admin@example.com', 'admin', '999-99-9999']);
        $n = $db->prepare("INSERT INTO notes(owner,title,body,private) VALUES(?,?,?,?)");
        $n->execute(['alice', 'Shopping list', 'milk, eggs, bread', 0]);
        $n->execute(['alice', 'Bank PIN reminder', 'PIN is 4821 (do not share)', 1]);
        $n->execute(['bob', 'Public note', 'hello world', 0]);
        $n->execute(['admin', 'Ops runbook', 'prod db password: hunter2', 1]);
    }
}

function render_index(): void
{
    global $ROUTES;
    $rows = $ROUTES;
    usort($rows, fn($a, $b) => strcmp($a['path'], $b['path']));
    header('Content-Type: text/html');
    echo '<!doctype html><meta charset="utf-8"><title>PHP VulnApp — endpoints</title>';
    echo '<style>body{font-family:system-ui,sans-serif;max-width:64rem;margin:2rem auto;padding:0 1rem}'
        . 'td,th{border:1px solid #ddd;padding:.35rem .6rem;text-align:left}table{border-collapse:collapse;width:100%}'
        . 'code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}'
        . '.warn{background:#fff3cd;border:1px solid #ffe69c;padding:.6rem 1rem;border-radius:6px}</style>';
    echo '<p class="warn">⚠️ Intentionally vulnerable demo app — for security education only.</p>';
    echo '<h1>PHP VulnApp</h1><p>Deliberately vulnerable PHP app demonstrating OWASP Top 10 '
        . 'code-level issues with multiple permutations per category.</p>';
    echo '<table><thead><tr><th>Method</th><th>Path</th><th>Demonstrates</th></tr></thead><tbody>';
    foreach ($rows as $r) {
        echo '<tr><td>' . $r['method'] . '</td><td><code>' . htmlspecialchars($r['path'])
            . '</code></td><td>' . htmlspecialchars($r['desc']) . '</td></tr>';
    }
    echo '</tbody></table>';
}
