using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace VulnApp.Controllers;

/// <summary>
/// Command Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
///
/// Mirrors the annotation format and attribute-routed action style of
/// SqlInjectionController. Every handler shells out to (or execs) a real OS
/// process so the injection is genuinely exploitable when the app runs.
///
/// NOTE ON THIS LAB IMAGE: ping/host/nslookup are frequently absent from minimal
/// containers, but that does NOT blunt the vulnerability — in the shell-based
/// permutations the *injected* command (after ';', '|', '$()', …) still runs via
/// /bin/sh, which is what turns these into RCE.
/// </summary>
[ApiController]
public class CommandInjectionController : ControllerBase
{
    // ========================================================================
    // PERMUTATION 1 — OS command built by concatenation, run through a SHELL
    // OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
    // CWE-78: Improper Neutralization of Special Elements used in an OS Command
    // EXPLOITATION LIKELIHOOD: CRITICAL — unauthenticated GET, zero tooling; the
    //   textbook  host=127.0.0.1;id  yields deterministic RCE as the app process.
    // PREVALENCE TODAY: greenfield LOW (idiomatic .NET uses ProcessStartInfo.
    //   ArgumentList; SAST flags building a shell string) | legacy/10yr tech-debt
    //   HIGH (old admin/ops code shells out to ping/ffmpeg/git via concatenation).
    // EXAMPLE: GET /injection/command/ping?host=127.0.0.1;id  (encode as 127.0.0.1%3Bid) -> runs `id`
    // FIX: no shell — fixed argv via ArgumentList + allow-list (see /injection/command/ping-safe).
    // ========================================================================
    [HttpGet("/injection/command/ping")]
    public IActionResult Ping(string host = "127.0.0.1")
    {
        // The classic "shell out to a CLI tool" pattern: build a command LINE by
        // concatenation and hand the whole string to /bin/sh -c.
        var command = $"ping -c 1 {host}"; // VULNERABLE: host concatenated into a /bin/sh command line
        var (stdout, stderr, exit) = RunShell(command);
        return new JsonResult(new
        {
            shell = "/bin/sh -c",
            command,
            exit,
            stdout,
            stderr,
            note = "everything after ; | && $() runs via /bin/sh — e.g. host=127.0.0.1;id executes id"
        });
    }

    // ========================================================================
    // PERMUTATION 2 — a SECOND shell command using a different tool (DNS lookup)
    // OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
    // CWE-78: Improper Neutralization of Special Elements used in an OS Command
    // EXPLOITATION LIKELIHOOD: CRITICAL — identical pre-auth /bin/sh sink; the
    //   payload  domain=example.com;cat /etc/passwd  exfiltrates arbitrary files
    //   and is trivially escalated to full RCE.
    // PREVALENCE TODAY: greenfield LOW (teams resolve names with a DNS library, or
    //   use fixed argv, not /bin/sh) | legacy/10yr tech-debt HIGH (network-tool
    //   wrappers assembled as shell strings are everywhere in old code).
    // EXAMPLE: GET /injection/command/dns?domain=example.com;cat /etc/passwd -> dumps /etc/passwd
    // FIX: resolve names with System.Net.Dns, or fixed-argv host/nslookup + strict validation — no shell.
    // ========================================================================
    [HttpGet("/injection/command/dns")]
    public IActionResult Dns(string domain = "example.com")
    {
        // A different tool ("host"), same fatal mistake: concatenate + /bin/sh -c.
        var command = $"host {domain}"; // VULNERABLE: domain concatenated into a /bin/sh command line
        var (stdout, stderr, exit) = RunShell(command);
        return new JsonResult(new
        {
            shell = "/bin/sh -c",
            command,
            exit,
            stdout,
            stderr,
            note = "domain=example.com;cat /etc/passwd reads arbitrary files through the shell"
        });
    }

    // ========================================================================
    // PERMUTATION 3 — ARGUMENT (option) injection into tar with NO shell (argv)
    // OWASP 2021 A03 Injection -> OWASP 2025 A05 Injection
    // CWE-78: Improper Neutralization of Special Elements used in an OS Command
    // EXPLOITATION LIKELIHOOD: HIGH — no shell metacharacters required; relies on
    //   the app splitting user input into argv + a known tar option gadget, but is
    //   deterministic RCE once those hold. Proves argv-exec is NOT automatically safe.
    // PREVALENCE TODAY: greenfield MEDIUM (argv-exec is the *recommended* fix, so
    //   option injection is overlooked and the `--` end-of-options guard is routinely
    //   forgotten) | legacy/10yr tech-debt MEDIUM (same blind spot, more CLI shelling).
    // EXAMPLE: GET /injection/command/backup?filename=--checkpoint=1 --checkpoint-action=exec=id
    //          (URL-encode the spaces) -> tar runs `id` with no /bin/sh involved.
    // FIX: insert a literal "--" before any user token so tar stops parsing options,
    //      and allow-list filenames (reject leading '-').
    // ========================================================================
    [HttpGet("/injection/command/backup")]
    public IActionResult Backup(string filename = "")
    {
        // "We build the argv ourselves and never touch /bin/sh, so we're safe."
        // A common misconception. This handler backs up the app's data directory
        // and lets the caller add extra space-separated files to the archive.
        var argv = new List<string> { "-czf", "/tmp/backup.tgz" };
        // VULNERABLE: user tokens become LEADING tar arguments; any token starting
        // with '-' is parsed as an OPTION (e.g. --checkpoint-action=exec=CMD, which
        // tar itself runs through a shell) rather than as a filename to archive.
        foreach (var tok in filename.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            argv.Add(tok);
        argv.Add("data"); // real source, so tar writes records and reaches the checkpoint
        var (stdout, stderr, exit) = RunProcess("tar", argv);
        return new JsonResult(new
        {
            shell = "none (direct argv exec)",
            argv = new List<string> { "tar" }.Concat(argv),
            exit,
            stdout,
            stderr,
            note = "no shell was used, yet tar's --checkpoint-action=exec option still executes code"
        });
    }

    // ========================================================================
    // SAFE REFERENCE — strict allow-list + fixed argv + NO shell. Shown so the
    // vulnerable/safe pair can be diffed by SAST tooling and by learners.
    //   (1) allow-list validation rejects shell metachars and any leading '-';
    //   (2) no /bin/sh — the binary is exec'd directly with a fixed argv;
    //   (3) '--' end-of-options guard means a hostile value can never be an option.
    // ========================================================================
    [HttpGet("/injection/command/ping-safe")]
    public IActionResult PingSafe(string host = "127.0.0.1")
    {
        if (!Regex.IsMatch(host, "^(?!-)[A-Za-z0-9.-]{1,253}$"))
            return new JsonResult(new { safe = true, error = "invalid host — allow-list rejected it", host }) { StatusCode = 400 };

        var argv = new List<string> { "-c", "1", "--", host };
        var (stdout, stderr, exit) = RunProcess("ping", argv);
        return new JsonResult(new
        {
            safe = true,
            argv = new List<string> { "ping" }.Concat(argv),
            exit,
            stdout,
            stderr
        });
    }

    // --- helpers -------------------------------------------------------------

    // Run a command LINE through the system shell (the dangerous sink used by P1/P2).
    private static (string Stdout, string Stderr, int Exit) RunShell(string command)
        => RunProcess("/bin/sh", new List<string> { "-c", command });

    // Exec a program with an explicit argv (no shell) and capture stdout/stderr.
    private static (string Stdout, string Stderr, int Exit) RunProcess(string fileName, List<string> argv)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = Directory.GetCurrentDirectory(),
        };
        foreach (var a in argv) psi.ArgumentList.Add(a);

        try
        {
            using var p = Process.Start(psi);
            var outTask = p.StandardOutput.ReadToEndAsync();
            var errTask = p.StandardError.ReadToEndAsync();
            p.WaitForExit(10000);
            return (outTask.GetAwaiter().GetResult(), errTask.GetAwaiter().GetResult(),
                    p.HasExited ? p.ExitCode : -1);
        }
        catch (Exception e)
        {
            // e.g. the intended tool (ping/host) is not installed on a minimal image.
            return ("", e.Message, -1);
        }
    }
}
