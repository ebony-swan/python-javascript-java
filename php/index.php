<?php
// Front controller for the deliberately-vulnerable PHP demo app.
//
//   cd php && php -S 127.0.0.1:8082 index.php     # http://127.0.0.1:8082/
//
// WARNING: intentional security vulnerabilities — never expose to an untrusted
// network.

require __DIR__ . '/lib.php';

// Auto-discover vulnerability modules: each file in vulns/ calls route().
foreach (glob(__DIR__ . '/vulns/*.php') as $module) {
    require $module;
}

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path === '/' || $path === '') {
    render_index();
    return true;
}

foreach ($ROUTES as $r) {
    if ($r['method'] === $method && $r['path'] === $path) {
        ($r['handler'])();
        return true;
    }
}

http_response_code(404);
header('Content-Type: application/json');
echo json_encode(['error' => 'not found', 'method' => $method, 'path' => $path]);
return true;
