// Go VulnApp — deliberately vulnerable net/http app demonstrating OWASP Top 10
// code-level issues, with multiple permutations per category.
//
//	cd go && go run .        # http://127.0.0.1:8081/
//
// Vulnerability modules live in this package and self-register from their
// init() functions, so this file needs no edits to pick them up.
//
// WARNING: intentional security vulnerabilities — never expose to an untrusted
// network.
package main

import (
	"fmt"
	"log"
	"net/http"
	"sort"
)

func main() {
	initDB()
	mux := http.NewServeMux()
	for _, r := range routes {
		mux.HandleFunc(r.pattern, r.handler)
	}
	mux.HandleFunc("GET /{$}", index)
	addr := "127.0.0.1:8081"
	log.Printf("Go VulnApp listening on http://%s/", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func index(w http.ResponseWriter, r *http.Request) {
	rs := make([]route, len(routes))
	copy(rs, routes)
	sort.Slice(rs, func(i, j int) bool { return rs[i].pattern < rs[j].pattern })
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>Go VulnApp — endpoints</title>`+
		`<style>body{font-family:system-ui,sans-serif;max-width:64rem;margin:2rem auto;padding:0 1rem}`+
		`td{border:1px solid #ddd;padding:.35rem .6rem;text-align:left}table{border-collapse:collapse;width:100%}`+
		`code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}`+
		`.warn{background:#fff3cd;border:1px solid #ffe69c;padding:.6rem 1rem;border-radius:6px}</style>`+
		`<p class="warn">⚠️ Intentionally vulnerable demo app — for security education only.</p>`+
		`<h1>Go VulnApp</h1><p>Deliberately vulnerable net/http app demonstrating OWASP Top 10 `+
		`code-level issues with multiple permutations per category.</p>`+
		`<table><thead><tr><th>Endpoint</th><th>What it demonstrates</th></tr></thead><tbody>`)
	for _, r := range rs {
		fmt.Fprintf(w, "<tr><td><code>%s</code></td><td>%s</td></tr>", r.pattern, r.desc)
	}
	fmt.Fprint(w, "</tbody></table>")
}
