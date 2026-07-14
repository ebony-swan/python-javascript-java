"""Command Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.

Same annotation format as the reference module (``injection_sql.py``): each
permutation carries a standard header describing the flaw, its CWE, an
exploitation-likelihood rating, a prevalence contrast, an example payload, and
the corresponding safe pattern. The dangerous sink of each handler is marked
with an inline ``VULNERABLE:`` comment.

Note: the primary tools these handlers wrap (``ping``, ``nslookup``) need not
even be installed — the whole point is that the *injected* command runs anyway.
"""
import os
import subprocess

from flask import Blueprint, request, jsonify

bp = Blueprint("injection_command", __name__, url_prefix="/injection/command")


# =============================================================================
# PERMUTATION 1 — OS command built by string concatenation, run through a shell
# OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
# CWE-78: Improper Neutralization of Special Elements used in an OS Command
# EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic, zero tooling; a shell
#   metacharacter (;, |, &&, $()) in one query param yields full RCE via curl.
# PREVALENCE TODAY: greenfield LOW (modern code shells out rarely, uses argv
#   arrays, and SAST/linters flag shell=True on sight) | legacy/10yr tech-debt
#   HIGH (hand-rolled os.system/shell strings wrapping ping/traceroute/ifconfig
#   are endemic in old admin panels, routers, and CGI diagnostics).
# EXAMPLE:
#   GET /injection/command/ping?host=127.0.0.1;id
#   -> ping fails, but ';id' still executes and returns uid=0(root)...
# FIX: never build a shell string from input; use an argv array with shell=False
#   and validate host against an allow-list / IP-address regex.
# =============================================================================
@bp.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: untrusted input concatenated into a shell command line.
    cmd = f"ping -c 1 {host}"
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
    except Exception as exc:  # e.g. TimeoutExpired from an injected sleep
        return jsonify({"command": cmd, "error": str(exc)}), 500
    return jsonify(
        {
            "command": cmd,
            "shell": True,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    )


# =============================================================================
# PERMUTATION 2 — second shell command with a different tool (arbitrary file read)
# OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
# CWE-78: Improper Neutralization of Special Elements used in an OS Command
# EXPLOITATION LIKELIHOOD: HIGH — identical shell-injection primitive via a
#   distinct binary; ';cat /etc/passwd' turns a DNS lookup into arbitrary file
#   read (and, with $(...) or |, into full RCE). Deterministic, no tooling.
# PREVALENCE TODAY: greenfield LOW (safe-by-default subprocess/argv usage and
#   review catch this) | legacy/10yr tech-debt HIGH (nslookup/host/dig wrappers
#   in "network tools" pages and monitoring scripts still concatenate input).
# EXAMPLE:
#   GET /injection/command/dns?domain=example.com;cat /etc/passwd
#   -> dumps /etc/passwd even though nslookup itself may be missing.
# FIX: run the tool via an argv array (no shell) and allow-list the domain with
#   a hostname regex; reject anything containing shell metacharacters.
# =============================================================================
@bp.get("/dns")
def dns():
    domain = request.args.get("domain", "example.com")
    # VULNERABLE: untrusted input concatenated into a command handed to `sh -c`.
    cmd = "nslookup " + domain
    try:
        proc = subprocess.run(
            ["sh", "-c", cmd], capture_output=True, text=True, timeout=10
        )
    except Exception as exc:
        return jsonify({"command": cmd, "error": str(exc)}), 500
    return jsonify(
        {
            "command": cmd,
            "argv": ["sh", "-c", cmd],
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    )


# =============================================================================
# PERMUTATION 3 — argument injection into a real binary invoked WITHOUT a shell
# OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
# CWE-78: Improper Neutralization of Special Elements used in an OS Command
#   (argument injection; see also CWE-88: Improper Neutralization of Argument
#   Delimiters in a Command)
# EXPLOITATION LIKELIHOOD: MEDIUM — no shell is involved and naive metacharacter
#   filters pass, yet code still runs: attacker-controlled *arguments* reach tar,
#   whose --checkpoint-action=exec= option executes commands. Needs tool-specific
#   knowledge and the ability to inject multiple argv elements, but is full RCE.
# PREVALENCE TODAY: greenfield MEDIUM (developers "did the safe thing" by using
#   an argv array instead of a shell and believe they are done — argument
#   injection is widely under-recognized, so it slips past review and SAST that
#   only look for shell=True) | legacy/10yr tech-debt HIGH (endless shell-outs to
#   tar/find/curl/git/rsync with user-controlled filenames and flags).
# EXAMPLE:
#   GET /injection/command/backup?filename=--checkpoint=1 --checkpoint-action=exec=id welcome.txt
#   -> tar runs `id` at the first checkpoint despite there being no shell.
# FIX: pass a `--` end-of-options guard, reject arguments beginning with '-', and
#   allow-list to known filenames (see /injection/command/backup-safe).
# =============================================================================
@bp.get("/backup")
def backup():
    filename = request.args.get("filename", "welcome.txt")
    public_dir = os.path.join(os.path.dirname(__file__), "..", "data", "public")
    # VULNERABLE: input split into argv elements and passed straight to tar.
    # shell=False here — proving array-exec is NOT automatically safe: the
    # injected *arguments* (--checkpoint-action=exec=...) make tar run commands.
    args = ["tar", "-czf", "/tmp/backup.tgz"] + filename.split()
    try:
        proc = subprocess.run(
            args, cwd=public_dir, capture_output=True, text=True, timeout=10
        )
    except Exception as exc:
        return jsonify({"args": args, "error": str(exc)}), 500
    return jsonify(
        {
            "args": args,
            "shell": False,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    )


# =============================================================================
# SAFE REFERENCE — argv array + strict allow-list validation + no shell.
# Shown so the vulnerable/safe pair can be diffed by SAST tools and learners.
# Blocks P3-style argument injection: only known filenames pass, nothing may
# start with '-', and a `--` guard stops any remaining value being read as a flag.
# =============================================================================
@bp.get("/backup-safe")
def backup_safe():
    filename = request.args.get("filename", "welcome.txt")
    public_dir = os.path.join(os.path.dirname(__file__), "..", "data", "public")
    allowed = set(os.listdir(public_dir))
    if filename.startswith("-") or os.sep in filename or filename not in allowed:
        return jsonify({"error": "filename not allowed", "allowed": sorted(allowed)}), 400
    # SAFE: allow-listed basename, end-of-options guard, no shell.
    args = ["tar", "-czf", "/tmp/backup.tgz", "--", filename]
    proc = subprocess.run(args, cwd=public_dir, capture_output=True, text=True, timeout=10)
    return jsonify(
        {
            "args": args,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    )
