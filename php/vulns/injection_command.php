<?php
/**
 * Command Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
 *
 * Same annotation format and route() self-registration as the reference module
 * (injection_sql.php): each permutation carries a standard header describing the
 * flaw, its CWE, an exploitation-likelihood rating, a prevalence contrast
 * (greenfield vs. 10-year tech-debt), an example payload, and the safe pattern.
 * The genuine dangerous PHP sinks (shell_exec, and proc_open through `sh -c` or
 * an argv array) are used unsanitized so the demos are really exploitable.
 *
 * Note: the wrapped primary tools (ping / host) need not even be installed — the
 * whole point is that the *injected* command runs anyway. In this container only
 * `sh`, `id` and `tar` are present, so P1/P2 print a "not found" for the wrapper
 * binary while the injected payload still executes as root.
 */

// Runner for the argv/`sh -c` permutations: proc_open captures stdout and stderr
// on separate pipes. A STRING $spec is run by PHP through `/bin/sh -c` (a shell,
// exactly like shell_exec/system); an ARRAY $spec is exec'd directly with NO
// shell. Category-unique name to avoid clashing with other modules' helpers.
function command_injection_run($spec, ?string $cwd = null): array
{
    $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = @proc_open($spec, $descriptors, $pipes, $cwd);
    if (!is_resource($proc)) {
        return ['stdout' => '', 'stderr' => 'failed to launch process', 'exit' => -1];
    }
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit = proc_close($proc);
    return ['stdout' => $stdout, 'stderr' => $stderr, 'exit' => $exit];
}

// ============================================================================
// PERMUTATION 1 — OS command built by string concatenation, run through a shell
// OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
// CWE-78: Improper Neutralization of Special Elements used in an OS Command
// EXPLOITATION LIKELIHOOD: CRITICAL — pre-auth, deterministic, zero tooling;
//   shell_exec() hands the whole string to /bin/sh, so one metacharacter
//   (; | && $() ``) in the host param yields full RCE via a single curl. The
//   injected command runs even though `ping` itself is not installed here.
// PREVALENCE TODAY: greenfield LOW (modern PHP resolves/pings via libraries or
//   just does not shell out, and shell_exec on request input is an obvious code
//   review / SAST red flag) | legacy/10yr tech-debt HIGH (hand-rolled
//   "diagnostics" pages wrapping ping/traceroute/ifconfig by concatenating input
//   into shell_exec/system/backticks are endemic in old PHP admin panels, cPanel
//   clones, router UIs and CGI tooling).
// EXAMPLE: GET /injection/command/ping?host=127.0.0.1;id
//   -> the ping wrapper fails, but `;id` still runs and returns uid=0(root)...
// FIX: never build a shell string from input; validate host against an
//   IP/hostname allow-list and exec with a fixed argv array and no shell.
// ============================================================================
route('GET', '/injection/command/ping', function () {
    $host = $_GET['host'] ?? '127.0.0.1';
    // VULNERABLE: untrusted input concatenated into a shell command line, then
    // executed by shell_exec() (which runs it via /bin/sh -c). `2>&1` folds
    // stderr in so the wrapper's own error is visible alongside the payload out.
    $cmd = "ping -c 1 $host";
    $output = shell_exec($cmd . ' 2>&1');
    json_response([
        'command' => $cmd,
        'sink'    => 'shell_exec',
        'shell'   => true,
        'output'  => $output,
    ]);
}, 'cmd injection: shell_exec string concat (ping)');

// ============================================================================
// PERMUTATION 2 — second shell command using a different tool via `sh -c`
// OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
// CWE-78: Improper Neutralization of Special Elements used in an OS Command
// EXPLOITATION LIKELIHOOD: CRITICAL — identical shell-injection primitive through
//   a distinct binary surface (a DNS-lookup helper). Handing proc_open the array
//   ['sh','-c',$cmd] is still a shell: `;cat /etc/passwd` turns the lookup into
//   arbitrary file read and $(...) / | into full RCE. Deterministic, no tooling,
//   and it works even when `host`/`nslookup` are absent.
// PREVALENCE TODAY: greenfield LOW (resolver work uses gethostbyname/dns_get_record
//   — no process spawn, nothing to inject into) | legacy/10yr tech-debt HIGH
//   (nslookup/host/dig wrappers on "network tools" pages, monitoring scripts and
//   appliance firmware still splice the domain into a shell command string).
// EXAMPLE: GET /injection/command/dns?domain=example.com;cat /etc/passwd
//   -> dumps /etc/passwd even though the `host` wrapper may be missing.
// FIX: resolve with dns_get_record()/gethostbyname() — no shell, no OS process —
//   and allow-list the domain with a strict hostname regex.
// ============================================================================
route('GET', '/injection/command/dns', function () {
    $domain = $_GET['domain'] ?? 'example.com';
    // VULNERABLE: untrusted input concatenated into a command handed to `sh -c`;
    // proc_open with an ARRAY that starts with sh -c is still a full shell.
    $cmd = "host $domain";
    $argv = ['sh', '-c', $cmd];
    $r = command_injection_run($argv);
    json_response([
        'command' => $cmd,
        'argv'    => $argv,
        'shell'   => true,
        'exit'    => $r['exit'],
        'stdout'  => $r['stdout'],
        'stderr'  => $r['stderr'],
    ]);
}, 'cmd injection: second tool (host) via sh -c');

// ============================================================================
// PERMUTATION 3 — argument injection into tar invoked WITHOUT a shell
// OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
// CWE-78: Improper Neutralization of Special Elements used in an OS Command
//   (argument injection; see also CWE-88: Improper Neutralization of Argument
//   Delimiters in a Command)
// EXPLOITATION LIKELIHOOD: HIGH — no shell is used (proc_open with an argv array),
//   so shell metacharacters are inert and naive metachar filters pass; yet the
//   filename is split on whitespace into argv words and tar reads leading-dash
//   words as OPTIONS. `--checkpoint=1 --checkpoint-action=exec=CMD` makes tar run
//   CMD (tar runs the exec= value through /bin/sh). Needs a real member file to
//   reach a checkpoint and tar-specific knowledge, but it is full RCE — proving
//   argv-exec is NOT automatically safe.
// PREVALENCE TODAY: greenfield MEDIUM (the standard "fix" — drop the shell, pass
//   proc_open/exec an args array — feels safe and passes SAST that only flags
//   shell_exec/`sh -c`, yet user-controlled words still reach tar/git/find/curl
//   as flags; argument injection is widely under-recognized) | legacy/10yr
//   tech-debt HIGH (backup/export features shelling to tar/zip with user-named
//   files are common and almost never pass a `--` end-of-options guard).
// EXAMPLE: GET /injection/command/backup?filename=--checkpoint=1 --checkpoint-action=exec=id welcome.txt
//   -> argv: tar -czf /tmp/backup.tgz --checkpoint=1 --checkpoint-action=exec=id welcome.txt
//      runs `id` at the first checkpoint despite there being no shell. Because tar
//      passes exec= through /bin/sh, `exec=cat${IFS}/etc/passwd` (or
//      `exec=sh${IFS}-c${IFS}id`) smuggles spaces even though the filename is
//      split on whitespace into separate argv words.
// FIX: pass a `--` end-of-options guard, reject arguments beginning with '-', and
//   allow-list to known basenames (see /injection/command/backup-safe).
// ============================================================================
route('GET', '/injection/command/backup', function () {
    $filename = $_GET['filename'] ?? 'welcome.txt';
    $dir = __DIR__ . '/../data/public';
    // VULNERABLE: filename split into argv words and passed straight to tar. No
    // shell is used, yet an attacker-supplied --checkpoint-action=exec=... word is
    // read by tar as an OPTION and executes commands — argv-exec is NOT auto-safe.
    $argv = array_merge(['tar', '-czf', '/tmp/backup.tgz'], preg_split('/\s+/', trim($filename)));
    $r = command_injection_run($argv, $dir);
    json_response([
        'argv'   => $argv,
        'cwd'    => $dir,
        'shell'  => false,
        'exit'   => $r['exit'],
        'stdout' => $r['stdout'],
        'stderr' => $r['stderr'],
    ]);
}, 'cmd injection: tar argument injection (no shell)');

// ============================================================================
// SAFE REFERENCE — fixed argv + strict allow-list validation + `--` guard, no
// shell. Shown so the vulnerable/safe pair can be diffed by SAST tools and
// learners. Blocks P3-style argument injection: only a known basename in the
// public dir passes, nothing may contain a path separator or start with '-', and
// the `--` end-of-options marker stops any remaining value being read as a flag.
// ============================================================================
route('GET', '/injection/command/backup-safe', function () {
    $filename = $_GET['filename'] ?? 'welcome.txt';
    $dir = __DIR__ . '/../data/public';
    $allowed = array_values(array_diff(scandir($dir), ['.', '..']));
    if ($filename === '' || $filename[0] === '-'
        || strpbrk($filename, "/\\") !== false
        || !in_array($filename, $allowed, true)) {
        json_response(['error' => 'filename not allowed', 'allowed' => $allowed, 'filename' => $filename], 400);
        return;
    }
    // SAFE: fixed argv, `-C` into the public dir, `--` end-of-options guard, a
    // single non-split allow-listed basename, and no shell anywhere.
    $argv = ['tar', '-czf', '/tmp/backup-safe.tgz', '-C', $dir, '--', $filename];
    $r = command_injection_run($argv);
    json_response([
        'argv'   => $argv,
        'shell'  => false,
        'exit'   => $r['exit'],
        'stdout' => $r['stdout'],
        'stderr' => $r['stderr'],
    ]);
}, 'SAFE: fixed argv + allow-list, no shell');
