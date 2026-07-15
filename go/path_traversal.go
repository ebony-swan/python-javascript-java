// Path Traversal / Broken Access Control —
// OWASP 2021 A01 Broken Access Control (path traversal) -> OWASP 2025 A01 / A05.
//
// Same annotation format and init()-based self-registration as the reference
// module (injection_sql.go): main.go auto-discovers these routes with no wiring
// changes. A file endpoint is *supposed* to serve only files under
// data/public/, but the untrusted path component is joined onto the base with
// NO containment check, so ../ segments and absolute paths escape the base dir.
//
// Layout used by the demos (paths are relative to the go/ working directory):
//   data/public/welcome.txt   <- the intended, "public" file
//   data/secret.txt           <- one level UP; the traversal target (GO_TRAVERSAL_OK)
//
// Every dangerous sink is flagged with a `VULNERABLE:` comment and is used
// UNSANITIZED so the demos are really exploitable (read AND write). The file
// ends with ONE clearly-labelled SAFE handler that canonicalizes the resolved
// path and enforces containment within the base dir.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	register("GET /path/read", "path traversal: read file under public dir, no containment (../secret.txt, absolute paths)", ptRead)
	register("GET /path/download", "path traversal: stream file as attachment, no containment (Content-Disposition)", ptDownload)
	register("POST /path/extract", "zip slip: arbitrary file WRITE outside extract dir (name=../../pwned.txt)", ptExtract)
	register("GET /path/read-safe", "SAFE: filepath.Clean + abs-prefix containment check within base dir", ptReadSafe)
}

// ptPublicDir is the base directory the file endpoints are *supposed* to be
// restricted to. It is intentionally NOT enforced by the vulnerable handlers.
func ptPublicDir() string { return filepath.Join("data", "public") }

// ptResolve joins an untrusted request path onto base the way a lot of real Go
// code does: filepath.Join (which Cleans but does NOT constrain to base, so
// leftover ../ segments escape), with an IsAbs shortcut so an absolute input
// bypasses the base entirely. This is the shared dangerous sink for P1 and P2.
func ptResolve(base, name string) string {
	if filepath.IsAbs(name) {
		return name // VULNERABLE: absolute input bypasses the base dir completely.
	}
	// VULNERABLE: filepath.Join cleans the path but never checks that the result
	// stays under base, so "../secret.txt" resolves to data/secret.txt and
	// enough ../ segments climb out of the app entirely (…/etc/passwd).
	return filepath.Join(base, name)
}

// ============================================================================
// PERMUTATION 1 — read an arbitrary file via an unconstrained path parameter
// OWASP 2021 A01 Broken Access Control (path traversal) -> OWASP 2025 A01 / A05
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
// EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic, zero tooling; the raw
//   `file` param is joined onto the public dir with no containment and the file
//   BODY is returned, so `../secret.txt` (and absolute `/etc/passwd`) is read
//   with a single curl. Full local file read is the whole impact.
// PREVALENCE TODAY: greenfield MEDIUM (net/http has no safe-by-default file API
//   for THIS shape — filepath.Join looks safe but doesn't contain, and every
//   "serve a user-named file" feature is hand-rolled; http.FileServer/ServeFile
//   with http.Dir would have been safe, so awareness cuts it) | legacy/10yr
//   tech-debt HIGH (download/report/attachment endpoints that concatenate a
//   filename onto a root dir predate the safe patterns and are everywhere).
// EXAMPLE: GET /path/read?file=../secret.txt        -> leaks GO_TRAVERSAL_OK
//          GET /path/read?file=welcome.txt          -> the intended public file
//          GET /path/read?file=/etc/passwd          -> absolute path, root read
// FIX: filepath.Clean the joined path, resolve to absolute, and reject anything
//   whose prefix is not the base dir (see /path/read-safe).
// ============================================================================
func ptRead(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	if file == "" {
		file = "welcome.txt"
	}
	base := ptPublicDir()
	full := ptResolve(base, file) // VULNERABLE: no containment — ../ and absolute escape.
	data, err := os.ReadFile(full)
	if err != nil {
		writeJSON(w, 404, map[string]any{"base": base, "resolved": full, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{
		"base":     base,
		"file":     file,
		"resolved": full,
		"bytes":    len(data),
		"content":  string(data),
	})
}

// ============================================================================
// PERMUTATION 2 — download/stream a file as an attachment, no containment
// OWASP 2021 A01 Broken Access Control (path traversal) -> OWASP 2025 A01 / A05
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
// EXPLOITATION LIKELIHOOD: HIGH — identical traversal primitive on a distinct
//   surface: the `name` param is joined onto the base and the file is streamed
//   back via Content-Disposition, so `../secret.txt` or an absolute path is
//   exfiltrated as a saved download. Setting an attachment header adds no safety.
// PREVALENCE TODAY: greenfield MEDIUM (file-download features are always custom;
//   devs often reach for os.Open + io.Copy and forget containment) | legacy/10yr
//   tech-debt HIGH (export/attachment/"getFile?name=" handlers are classic and
//   rarely canonicalize the path).
// EXAMPLE: GET /path/download?name=../secret.txt     -> downloads the secret
//          GET /path/download?name=/etc/hostname     -> absolute path download
// FIX: canonicalize and containment-check exactly as in /path/read-safe before
//   opening the file; prefer http.FileServer(http.Dir(base)) which is safe.
// ============================================================================
func ptDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "welcome.txt"
	}
	base := ptPublicDir()
	full := ptResolve(base, name) // VULNERABLE: no containment — ../ and absolute escape.
	f, err := os.Open(full)
	if err != nil {
		writeJSON(w, 404, map[string]any{"base": base, "resolved": full, "error": err.Error()})
		return
	}
	defer f.Close()
	// The attachment filename is the attacker-controlled basename; the header is
	// cosmetic and provides no access-control benefit whatsoever.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(name)))
	w.Header().Set("X-Resolved-Path", full)
	_, _ = io.Copy(w, f)
}

// ptEntry is one file to materialize in the "extract" step: an in-archive name
// (attacker-controlled, may contain ../) and its raw content.
type ptEntry struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// ptExtractReq is the POST body shape: {"entries":[{"name":...,"content":...}]}.
type ptExtractReq struct {
	Entries []ptEntry `json:"entries"`
}

// ptExtractDir is where entries are *supposed* to land. It sits two levels below
// the working directory (go/data/extract), so "../../pwned.txt" climbs back out
// to the go/ app root — outside the extract dir.
func ptExtractDir() string { return filepath.Join("data", "extract") }

// ============================================================================
// PERMUTATION 3 — ZIP SLIP: arbitrary file WRITE from an unconstrained entry name
// OWASP 2021 A01 Broken Access Control (path traversal) -> OWASP 2025 A01 / A05
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
// EXPLOITATION LIKELIHOOD: HIGH — the entry `name` is joined onto the extract
//   dir with no containment and written to disk, so `../../pwned.txt` writes
//   OUTSIDE the extract dir. Arbitrary write is worse than read: overwrite a
//   config/cron/authorized_keys/served file to reach code execution. Needs a
//   POST body (hence not "trivially GET") but is deterministic and untooled.
// PREVALENCE TODAY: greenfield MEDIUM (archive/zip and archive/tar give NO
//   automatic containment — the extractor MUST validate each entry, and the
//   "Zip Slip" class keeps recurring in upload/import/plugin features) |
//   legacy/10yr tech-debt HIGH (unzip/untar-an-upload code written before Zip
//   Slip was named almost never checks the joined path).
// EXAMPLE:
//   curl -X POST localhost:8081/path/extract -H 'Content-Type: application/json' \
//     -d '{"entries":[{"name":"../../pwned.txt","content":"owned"}]}'
//   -> writes …/go/pwned.txt (outside data/extract) and returns its absolute path.
// FIX: for each entry, filepath.Clean the joined destination, resolve to
//   absolute, and reject any path not prefixed by the extract dir before writing
//   (same containment check as /path/read-safe), and reject absolute names.
// ============================================================================
func ptExtract(w http.ResponseWriter, r *http.Request) {
	var req ptExtractReq
	body, _ := io.ReadAll(r.Body)
	if len(strings.TrimSpace(string(body))) == 0 {
		writeJSON(w, 200, map[string]any{
			"usage":   "POST JSON {\"entries\":[{\"name\":\"../../pwned.txt\",\"content\":\"owned\"}]}",
			"note":    "each entry name is joined onto the extract dir with NO containment (Zip Slip, CWE-22).",
			"extract": ptExtractDir(),
		})
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "json: " + err.Error()})
		return
	}
	dir := ptExtractDir()
	_ = os.MkdirAll(dir, 0o755)
	var results []map[string]any
	for _, e := range req.Entries {
		// VULNERABLE: entry name joined onto the extract dir with no containment,
		// so "../../pwned.txt" (or an absolute name) escapes and writes anywhere
		// the process can write. filepath.Join Cleans but never constrains.
		dest := ptResolve(dir, e.Name)
		abs, _ := filepath.Abs(dest)
		// Create parent dirs so nested/escaping paths resolve, then write the file.
		_ = os.MkdirAll(filepath.Dir(dest), 0o755)
		werr := os.WriteFile(dest, []byte(e.Content), 0o644)
		res := map[string]any{"name": e.Name, "resolved": dest, "abs": abs, "bytes": len(e.Content)}
		if werr != nil {
			res["error"] = werr.Error()
		} else {
			res["escaped_extract_dir"] = !ptWithin(dir, dest)
		}
		results = append(results, res)
	}
	writeJSON(w, 200, map[string]any{"extract_dir": dir, "written": results})
}

// ptWithin reports whether resolved is contained inside base after both are made
// absolute and cleaned. It is the containment predicate the VULNERABLE handlers
// omit and the SAFE handler enforces.
func ptWithin(base, resolved string) bool {
	absBase, err1 := filepath.Abs(base)
	absPath, err2 := filepath.Abs(resolved)
	if err1 != nil || err2 != nil {
		return false
	}
	absBase = filepath.Clean(absBase)
	absPath = filepath.Clean(absPath)
	return absPath == absBase || strings.HasPrefix(absPath, absBase+string(os.PathSeparator))
}

// ============================================================================
// SAFE REFERENCE — canonicalize the resolved path and enforce containment.
// Contrast with PERMUTATION 1: the untrusted name is joined onto the base and
// the RESULT is Cleaned and resolved to an ABSOLUTE path, then rejected unless
// its prefix is the base dir (filepath.Clean + abs-prefix check — the Go analogue
// of Path.GetFullPath + StartsWith / realpath containment). A ".." that escapes
// the base is caught here instead of being served. No IsAbs shortcut, so absolute
// inputs collapse harmlessly under the base. Only files genuinely living under
// data/public/ are served.
// EXAMPLE: GET /path/read-safe?file=../secret.txt  -> 403 (escapes base, rejected)
//          GET /path/read-safe?file=welcome.txt    -> 200 (allowed)
// ============================================================================
func ptReadSafe(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	if file == "" {
		file = "welcome.txt"
	}
	base := ptPublicDir()
	// SAFE: join then canonicalize; filepath.Join Cleans the ".." segments, and
	// ptWithin resolves to absolute and REJECTS anything not prefixed by the base.
	full := filepath.Join(base, file)
	if !ptWithin(base, full) {
		writeJSON(w, 403, map[string]any{"base": base, "file": file, "resolved": full, "error": "path escapes base dir — rejected"})
		return
	}
	data, err := os.ReadFile(full)
	if err != nil {
		writeJSON(w, 404, map[string]any{"base": base, "resolved": full, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"base": base, "file": file, "resolved": full, "content": string(data)})
}
