/**
 * Deliberately-vulnerable Express demo app.
 *
 *   npm install
 *   npm start           # http://127.0.0.1:3000/
 *
 * Vulnerability modules live in ./routes and are auto-mounted: any file that
 * exports `{ base, router }` is wired up automatically. One file per OWASP
 * category; multiple annotated permutations live inside each file.
 *
 * WARNING: intentional security vulnerabilities — never expose to an untrusted
 * network.
 */
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const { initDb } = require('./db');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

initDb();

const routesDir = path.join(__dirname, 'routes');
const mounted = [];
for (const file of fs.readdirSync(routesDir)) {
  if (!file.endsWith('.js')) continue;
  const mod = require(path.join(routesDir, file));
  if (mod && mod.base && mod.router) {
    app.use(mod.base, mod.router);
    mounted.push({ base: mod.base, router: mod.router });
  }
}

app.get('/', (req, res) => {
  const rows = [];
  for (const m of mounted) {
    for (const layer of m.router.stack) {
      if (!layer.route) continue;
      const methods = Object.keys(layer.route.methods).map((x) => x.toUpperCase()).join(', ');
      const suffix = layer.route.path === '/' ? '' : layer.route.path;
      rows.push({ methods, path: m.base + suffix });
    }
  }
  rows.sort((a, b) => a.path.localeCompare(b.path));
  const list = rows
    .map((r) => `<tr><td>${r.methods}</td><td><code>${r.path}</code></td></tr>`)
    .join('\n');
  res.send(`<!doctype html><html><head><meta charset="utf-8">
    <title>JavaScript VulnApp — endpoint index</title>
    <style>body{font-family:system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}
    td,th{border:1px solid #ddd;padding:.4rem .6rem;text-align:left}table{border-collapse:collapse;width:100%}
    code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}
    .warn{background:#fff3cd;border:1px solid #ffe69c;padding:.6rem 1rem;border-radius:6px}</style></head>
    <body><p class="warn">⚠️ Intentionally vulnerable demo app — for security education only.</p>
    <h1>JavaScript VulnApp</h1>
    <p>Deliberately vulnerable Express app demonstrating OWASP Top 10 code-level
    issues with multiple permutations per category.</p>
    <table><thead><tr><th>Methods</th><th>Path</th></tr></thead><tbody>${list}</tbody></table>
    </body></html>`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '127.0.0.1', () => {
  console.log(`JavaScript VulnApp listening on http://127.0.0.1:${PORT}/`);
});
