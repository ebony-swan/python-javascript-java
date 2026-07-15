// OS Command Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
//
// Same annotation format and init()-based self-registration as the reference
// module (injection_sql.go): each permutation carries a standard header
// describing the flaw, its CWE, an exploitation-likelihood rating, a prevalence
// contrast (greenfield vs. 10-year tech-debt), an example payload, and the safe
// pattern. The genuine dangerous sinks (os/exec via `sh -c`, and an argv-array
// tar invocation) are used unsanitized so the demos are really exploitable.
//
// Note: the wrapped primary tools (ping / host) need not even be installed —
// the whole point is that the *injected* command runs anyway. In this container
// only `sh` and `tar` are present, so P1/P2 print a "not found" for the wrapper
// while the injected payload still executes.
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func init() {
	register("GET /injection/command/ping", "cmd injection: shell concat via sh -c (ping)", cmdPing)
	register("GET /injection/command/dns", "cmd injection: second shell tool (host) via sh -c", cmdDNS)
	register("GET /injection/command/backup", "cmd injection: tar argument injection (no shell)", cmdBackup)
	register("GET /injection/command/backup-safe", "SAFE: fixed argv + allow-list, no shell", cmdBackupSafe)
}

// cmdRun executes name+args, optionally in dir, and returns stdout, stderr and
// any run error as strings. strings.Builder implements io.Writer, so no extra
// imports are needed to capture both streams separately.
func cmdRun(dir, name string, args ...string) (stdout, stderr, errStr string) {
	c := exec.Command(name, args...)
	if dir != "" {
		c.Dir = dir
	}
	var out, errb strings.Builder
	c.Stdout = &out
	c.Stderr = &errb
	if err := c.Run(); err != nil {
		errStr = err.Error()
	}
	return out.String(), errb.String(), errStr
}

// ============================================================================
// PERMUTATION 1 — OS command built by string concatenation, run through a shell
// OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
// CWE-78: Improper Neutralization of Special Elements used in an OS Command
// EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic, zero tooling; because
//   exec.Command("sh","-c",cmd) hands the string to a shell, one metacharacter
//   (; | & $() ``) in the host param yields full RCE via a single curl. The
//   injected command runs even though `ping` itself is not installed here.
// PREVALENCE TODAY: greenfield LOW (idiomatic Go uses the net package or an argv
//   slice — exec.Command with no shell — and `sh -c` on request input is an
//   obvious code-review/SAST red flag; AI-generated snippets still reintroduce
//   it) | legacy/10yr tech-debt HIGH (hand-rolled "diagnostics" endpoints that
//   wrap ping/traceroute/ifconfig by concatenating input into a shell string are
//   endemic in old admin panels, routers and CGI tooling).
// EXAMPLE: GET /injection/command/ping?host=127.0.0.1;id
//   -> the ping wrapper fails, but `;id` still runs and returns uid=0(root)...
// FIX: never build a shell string from input; use exec.Command("ping","-c","1",
//   host) with no shell and validate host against an IP/hostname allow-list.
// ============================================================================
func cmdPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "127.0.0.1"
	}
	// VULNERABLE: untrusted input concatenated into a shell command line.
	line := fmt.Sprintf("ping -c 1 %s", host)
	stdout, stderr, errStr := cmdRun("", "sh", "-c", line)
	writeJSON(w, 200, map[string]any{
		"command": line,
		"argv":    []string{"sh", "-c", line},
		"shell":   true,
		"stdout":  stdout,
		"stderr":  stderr,
		"error":   errStr,
	})
}

// ============================================================================
// PERMUTATION 2 — second shell command using a different tool (arbitrary read)
// OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
// CWE-78: Improper Neutralization of Special Elements used in an OS Command
// EXPLOITATION LIKELIHOOD: HIGH — identical shell-injection primitive through a
//   distinct binary surface (a DNS-lookup helper); `;cat /etc/passwd` turns the
//   lookup into arbitrary file read and $(...) / | into full RCE. Deterministic,
//   no tooling, and works even when `host`/`nslookup` are absent.
// PREVALENCE TODAY: greenfield LOW (resolver work is done with net.LookupHost —
//   no process spawn, nothing to inject into) | legacy/10yr tech-debt HIGH
//   (nslookup/host/dig wrappers on "network tools" pages, monitoring scripts and
//   appliance firmware still concatenate the domain into a shell command).
// EXAMPLE: GET /injection/command/dns?domain=example.com;cat /etc/passwd
//   -> dumps /etc/passwd even though the `host` wrapper may be missing.
// FIX: resolve with net.LookupHost(domain) — no shell, no OS process — and
//   allow-list the domain with a hostname regex.
// ============================================================================
func cmdDNS(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = "example.com"
	}
	// VULNERABLE: untrusted input concatenated into a command handed to `sh -c`.
	line := "host " + domain
	stdout, stderr, errStr := cmdRun("", "sh", "-c", line)
	writeJSON(w, 200, map[string]any{
		"command": line,
		"argv":    []string{"sh", "-c", line},
		"shell":   true,
		"stdout":  stdout,
		"stderr":  stderr,
		"error":   errStr,
	})
}

// ============================================================================
// PERMUTATION 3 — argument injection into tar invoked WITHOUT a shell
// OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
// CWE-88: Improper Neutralization of Argument Delimiters in a Command (argument
//   injection; leads to CWE-78 OS command execution)
// EXPLOITATION LIKELIHOOD: MEDIUM — no shell is used (argv slice), so shell
//   metacharacters are inert and naive metacharacter filters pass; yet the
//   filename is split on whitespace into argv words and tar treats leading-dash
//   words as OPTIONS. `--checkpoint=1 --checkpoint-action=exec=CMD` makes tar
//   run CMD. Needs a real member file to reach a checkpoint and tool-specific
//   knowledge, hence MEDIUM rather than HIGH, but it is full RCE.
// PREVALENCE TODAY: greenfield MEDIUM (the standard "fix" — drop the shell, pass
//   exec.Command with an args slice — feels safe and passes SAST that only flags
//   `sh -c`, yet user-controlled words still reach tar/git/find/curl as flags;
//   argument injection is widely under-recognized) | legacy/10yr tech-debt HIGH
//   (backup/export features shelling to tar/zip with user-named files are common
//   and almost never use a `--` end-of-options guard).
// EXAMPLE: GET /injection/command/backup?filename=--checkpoint=1 --checkpoint-action=exec=id welcome.txt
//   -> argv: tar -czf /tmp/cmdBackup.tgz --checkpoint=1 --checkpoint-action=exec=id welcome.txt
//      runs `id` at the first checkpoint despite there being no shell. (tar runs
//      the exec= value through /bin/sh, so `exec=cat${IFS}/etc/passwd` smuggles
//      spaces even though the filename is split on whitespace.)
// FIX: pass a `--` end-of-options guard, reject arguments beginning with '-', and
//   allow-list to known basenames (see /injection/command/backup-safe).
// ============================================================================
func cmdBackup(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		filename = "welcome.txt"
	}
	dir := filepath.Join("data", "public")
	// VULNERABLE: filename split into argv words and passed straight to tar; no
	// shell is used, yet attacker-supplied --checkpoint-action=exec=... is read
	// by tar as an OPTION and executes commands — argv-exec is NOT auto-safe.
	argv := append([]string{"tar", "-czf", "/tmp/cmdBackup.tgz"}, strings.Fields(filename)...)
	stdout, stderr, errStr := cmdRun(dir, argv[0], argv[1:]...)
	writeJSON(w, 200, map[string]any{
		"argv":   argv,
		"cwd":    dir,
		"shell":  false,
		"stdout": stdout,
		"stderr": stderr,
		"error":  errStr,
	})
}

// ============================================================================
// SAFE REFERENCE — fixed argv + strict allow-list validation + `--` guard, no
// shell. Shown so the vulnerable/safe pair can be diffed by SAST tools and
// learners. Blocks P3-style argument injection: only a known basename in the
// public dir passes, nothing may contain a path separator or start with '-', and
// the `--` end-of-options marker stops any remaining value being read as a flag.
// ============================================================================
func cmdBackupSafe(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		filename = "welcome.txt"
	}
	dir := filepath.Join("data", "public")
	allowed := map[string]bool{}
	names := []string{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		allowed[e.Name()] = true
		names = append(names, e.Name())
	}
	if strings.HasPrefix(filename, "-") || strings.ContainsAny(filename, `/\`) || !allowed[filename] {
		writeJSON(w, 400, map[string]any{"error": "filename not allowed", "allowed": names, "filename": filename})
		return
	}
	// SAFE: fixed argv, `-C` into the public dir, `--` end-of-options guard, a
	// single non-split allow-listed basename, and no shell anywhere.
	argv := []string{"tar", "-czf", "/tmp/cmd-backup-safe.tgz", "-C", dir, "--", filename}
	stdout, stderr, errStr := cmdRun("", argv[0], argv[1:]...)
	writeJSON(w, 200, map[string]any{
		"argv":   argv,
		"shell":  false,
		"stdout": stdout,
		"stderr": stderr,
		"error":  errStr,
	})
}
