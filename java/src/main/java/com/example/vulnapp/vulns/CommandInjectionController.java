package com.example.vulnapp.vulns;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * OS Command Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
 *
 * Mirrors the comment/annotation format of {@link SqlInjectionController}: each
 * permutation carries a standard header describing the flaw, its CWE, an
 * exploitation-likelihood rating, greenfield-vs-legacy prevalence, an example
 * payload, and the corresponding safe pattern. Every dangerous sink is a real,
 * exploitable {@code ProcessBuilder} that reaches the OS — nothing is stubbed.
 *
 * PRIMARY CWE: CWE-78 Improper Neutralization of Special Elements used in an OS
 * Command ('OS Command Injection').
 */
@RestController
@RequestMapping("/injection/command")
public class CommandInjectionController {

    // ========================================================================
    // PERMUTATION 1 — Shell command built by string concatenation (ping)
    // OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
    // CWE-78: Improper Neutralization of Special Elements used in an OS Command
    // EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic one-liner; the
    //   untrusted host is glued into a string and handed to `bash -c`, so a
    //   `;`/`|`/`$()` metacharacter runs an arbitrary second command. The
    //   injected command executes even if `ping` itself is absent.
    // PREVALENCE TODAY: greenfield LOW (modern stacks rarely shell out; when they
    //   must they use argv exec + libraries, and SAST/linters flag `bash -c` with
    //   a concatenated string) | legacy/10yr tech-debt HIGH (network/ops/admin
    //   features wrapping shell one-liners with string concat are everywhere in
    //   long-lived codebases).
    // EXAMPLE:
    //   GET /injection/command/ping?host=127.0.0.1;id
    //   GET /injection/command/ping?host=$(cat%20/etc/passwd)
    // FIX: never build a shell string from input — validate against an allow-list
    //   and exec an argv array with no shell (see /injection/command/ping-safe).
    // ========================================================================
    @GetMapping("/ping")
    public Map<String, Object> ping(@RequestParam(defaultValue = "127.0.0.1") String host) {
        // VULNERABLE: untrusted host concatenated into a command line run through a shell.
        String cmd = "ping -c 1 " + host;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("command", cmd);
        out.put("shell", "bash -c");
        out.putAll(exec(new ProcessBuilder("bash", "-c", cmd)));
        return out;
    }

    // ========================================================================
    // PERMUTATION 2 — Second shell sink with a different tool (nslookup)
    // OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
    // CWE-78: Improper Neutralization of Special Elements used in an OS Command
    // EXPLOITATION LIKELIHOOD: HIGH — same class as P1 but via `sh -c`; a lookup/
    //   diagnostics box concatenates the domain, so `example.com;cat /etc/passwd`
    //   leaks arbitrary files. Pre-auth, deterministic, no tooling required.
    // PREVALENCE TODAY: greenfield LOW (DNS/resolution is done with library calls,
    //   e.g. InetAddress, not by shelling out) | legacy/10yr tech-debt HIGH
    //   (hand-rolled `nslookup`/`host`/`dig` wrappers persist in old admin panels).
    // EXAMPLE:
    //   GET /injection/command/dns?domain=example.com;cat%20/etc/passwd
    //   GET /injection/command/dns?domain=x|id
    // FIX: resolve names with java.net.InetAddress; never pass input to a shell.
    // ========================================================================
    @GetMapping("/dns")
    public Map<String, Object> dns(@RequestParam(defaultValue = "example.com") String domain) {
        // VULNERABLE: untrusted domain concatenated into a command line run through a shell.
        String cmd = "nslookup " + domain;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("command", cmd);
        out.put("shell", "sh -c");
        out.putAll(exec(new ProcessBuilder("sh", "-c", cmd)));
        return out;
    }

    // ========================================================================
    // PERMUTATION 3 — Argument injection into argv exec, NO shell (tar)
    // OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
    // CWE-78: Improper Neutralization of Special Elements used in an OS Command
    //   (specifically CWE-88 Argument Injection, a CWE-78 variant)
    // EXPLOITATION LIKELIHOOD: MEDIUM — there is NO shell, so `;`/`|`/`$()` do
    //   nothing; the attacker must know that argv values beginning with `-` are
    //   parsed by `tar` as OPTIONS. Given that knowledge it is reliable: tar's
    //   own `--checkpoint-action=exec=` runs an arbitrary command. Reaching code
    //   execution takes more skill than a shell metacharacter, hence MEDIUM.
    // PREVALENCE TODAY: greenfield MEDIUM ("we use array exec, so we're safe" is a
    //   widespread myth; devs pass user input straight into a `tar`/`git`/`curl`/
    //   `ffmpeg` argv without a `--` end-of-options guard, and SAST rarely flags
    //   argv injection) | legacy/10yr tech-debt HIGH (countless CLI-wrapper
    //   backup/export features built by splitting a user string into args).
    // EXAMPLE (array-exec, still RCE — note: no metacharacters):
    //   GET /injection/command/backup?filename=--checkpoint=1 --checkpoint-action=exec=id pom.xml
    //   -> tar reaches a checkpoint and runs `id`; stdout is captured below.
    // FIX: insert a literal "--" end-of-options marker before user paths AND
    //   allow-list the values so they cannot be interpreted as flags.
    // ========================================================================
    @GetMapping("/backup")
    public Map<String, Object> backup(@RequestParam(defaultValue = "pom.xml") String filename) {
        List<String> argv = new ArrayList<>();
        argv.add("tar");
        argv.add("-czf");
        argv.add("/tmp/backup.tgz");
        // VULNERABLE: attacker-controlled filename split into argv tokens and passed to
        // tar with NO shell. Array-exec is NOT automatically safe: tokens starting with
        // '-' are consumed as tar OPTIONS (e.g. --checkpoint-action=exec=<cmd>), so tar
        // itself executes the command. There is no "--" end-of-options guard here.
        for (String tok : filename.trim().split("\\s+")) {
            if (!tok.isEmpty()) {
                argv.add(tok);
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("note", "no shell used — plain ProcessBuilder(argv); array-exec is NOT injection-proof");
        out.putAll(exec(new ProcessBuilder(argv)));
        return out;
    }

    // ========================================================================
    // SAFE REFERENCE — strict allow-list + argv exec, no shell. Shown so the
    // vulnerable/safe pair can be diffed by SAST tooling and learners.
    //
    // Two independent controls make this safe:
    //   1) the host must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$ — it cannot
    //      contain shell metacharacters AND cannot begin with '-', so it can
    //      never be reinterpreted as a command-line option (defeats P3-style
    //      argument injection too);
    //   2) it is passed as a single element of an argv array to ProcessBuilder
    //      with no shell at all (defeats P1/P2-style metacharacter injection).
    // ========================================================================
    private static final Pattern SAFE_HOST = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$");

    @GetMapping("/ping-safe")
    public Map<String, Object> pingSafe(@RequestParam(defaultValue = "127.0.0.1") String host) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("host", host);
        if (!SAFE_HOST.matcher(host).matches()) {
            // SAFE: reject anything that is not a bare hostname/IP before it reaches the OS.
            out.put("rejected", "host failed allow-list ^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$");
            return out;
        }
        // SAFE: no shell; host is one argv element that already passed validation.
        out.putAll(exec(new ProcessBuilder("ping", "-c", "1", host)));
        return out;
    }

    /**
     * Runs a process, captures stdout/stderr/exit code, and returns them for the
     * response. {@code readAllBytes()} blocks until each stream hits EOF (i.e.
     * the child closes it on exit), so this also serves as the wait for small
     * command outputs; a bounded {@code waitFor} guards against a hang.
     */
    private Map<String, Object> exec(ProcessBuilder pb) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("argv", new ArrayList<>(pb.command()));
        try {
            Process p = pb.start();
            String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            String stderr = new String(p.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            boolean finished = p.waitFor(20, TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
            }
            out.put("exitCode", finished ? p.exitValue() : null);
            out.put("stdout", stdout);
            out.put("stderr", stderr);
        } catch (Exception e) {
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }
}
