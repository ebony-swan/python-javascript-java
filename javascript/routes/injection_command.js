/**
 * OS Command Injection — OWASP 2021 A03 Injection | OWASP 2025 A05 Injection.
 *
 * Same annotation format as the SQL-injection reference module: each
 * permutation carries a standard header describing the flaw, its CWE, an
 * exploitation-likelihood rating, prevalence today, an example payload, and
 * the corresponding safe pattern. The genuine dangerous sinks (child_process
 * exec / execFile) are used unsanitized so the demos are really exploitable.
 */
'use strict';

const express = require('express');
const path = require('path');
const { exec, execFile } = require('child_process');

const router = express.Router();

// ===========================================================================
// PERMUTATION 1 — Shell command built by string concatenation (classic RCE)
// OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
// CWE-78: Improper Neutralization of Special Elements used in an OS Command
// EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic; exec() spawns
//   `/bin/sh -c`, so shell metacharacters (; | & $() ``) inject a second
//   command with no tooling required.
// PREVALENCE TODAY: greenfield LOW (modern code rarely shells out for network
//   ops; lint rules flag child_process.exec and steer to array-arg APIs —
//   though AI-generated snippets still reintroduce it) | legacy/10yr tech-debt
//   HIGH (hand-rolled "diagnostics" endpoints wrapping ping/traceroute/whois
//   by concatenating request input into a shell string are everywhere).
// EXAMPLE:
//   GET /injection/command/ping?host=127.0.0.1;id
//   GET /injection/command/ping?host=127.0.0.1%20|%20cat%20/etc/passwd
// FIX: never build a shell string from input; use execFile('ping',['-c','1',host])
//   with no shell and validate host (see /injection/command/backup-safe).
// ===========================================================================
router.get('/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  // VULNERABLE: user input concatenated into a command string run by a shell.
  const cmd = `ping -c 1 ${host}`;
  exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {
    res.json({ command: cmd, stdout, stderr, error: err ? err.message : null });
  });
});

// ===========================================================================
// PERMUTATION 2 — Second shell command using a different tool (nslookup)
// OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
// CWE-78: Improper Neutralization of Special Elements used in an OS Command
// EXPLOITATION LIKELIHOOD: HIGH — identical mechanism to P1 via a different
//   sink surface (DNS lookup helper); exec() shells out, so `;` / `|` chain an
//   arbitrary command. The injected command runs even when nslookup is absent.
// PREVALENCE TODAY: greenfield LOW (resolver work is done with dns/promises,
//   not by shelling out) | legacy/10yr tech-debt HIGH (admin panels that
//   "look up" a domain by calling nslookup/host/dig through the shell persist
//   in older ops tooling and appliance firmware).
// EXAMPLE:
//   GET /injection/command/dns?domain=example.com;cat /etc/passwd
//   GET /injection/command/dns?domain=$(id)
// FIX: use require('dns').promises.resolve(domain) — no shell, no OS process.
// ===========================================================================
router.get('/dns', (req, res) => {
  const domain = req.query.domain || 'example.com';
  // VULNERABLE: input concatenated into a string handed to a shell via exec().
  const cmd = `nslookup ${domain}`;
  exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {
    res.json({ command: cmd, stdout, stderr, error: err ? err.message : null });
  });
});

// ===========================================================================
// PERMUTATION 3 — Argument injection into tar invoked WITHOUT a shell
// OWASP 2021 A03 Injection  ->  OWASP 2025 A05 Injection
// CWE-88: Improper Neutralization of Argument Delimiters (leads to CWE-78 RCE)
// EXPLOITATION LIKELIHOOD: MEDIUM — no shell is used (execFile array args), so
//   metacharacters are inert; but the filename is split on spaces into argv and
//   tar itself treats leading-dash words as OPTIONS. `--checkpoint` +
//   `--checkpoint-action=exec=CMD` make tar run CMD. Needs a valid member file
//   to reach a checkpoint, hence MEDIUM rather than HIGH.
// PREVALENCE TODAY: greenfield MEDIUM (the popular "fix" — drop the shell, pass
//   an args array — feels safe and passes most SAST, yet user-controlled words
//   still reach tar/git/find/curl as flags; argument injection is widely
//   under-recognized) | legacy/10yr tech-debt HIGH (backup/export features
//   shelling to tar/zip with user-named files are common and rarely use `--`).
// EXAMPLE:
//   GET /injection/command/backup?filename=/etc/hostname --checkpoint=1 --checkpoint-action=exec=id
//   (argv: tar -czf /tmp/backup.tgz /etc/hostname --checkpoint=1 --checkpoint-action=exec=id -> runs `id`)
// FIX: terminate option parsing with `--`, allow-list the filename, and pass it
//   as a single non-split argument (see /injection/command/backup-safe).
// ===========================================================================
router.get('/backup', (req, res) => {
  const filename = req.query.filename || 'data/public/welcome.txt';
  const archive = '/tmp/backup.tgz';
  // VULNERABLE: filename split into argv words; no shell, but tar interprets
  // attacker-supplied `--checkpoint-action=exec=...` as an option -> RCE.
  const args = ['-czf', archive].concat(filename.split(' '));
  execFile('tar', args, { timeout: 5000 }, (err, stdout, stderr) => {
    res.json({ argv: ['tar', ...args], stdout, stderr, error: err ? err.message : null });
  });
});

// ===========================================================================
// SAFE REFERENCE — array args + strict allow-list + `--` option terminator.
// Shown so the vulnerable/safe pair can be diffed by SAST tooling and learners.
//   * no shell (execFile), so metacharacters are inert;
//   * filename allow-listed to a bare basename (rejects `-`, `/`, spaces), so
//     it can never be split into extra argv words or look like an option;
//   * `--` tells tar to stop parsing options, so even a dashy name is a file.
// ===========================================================================
router.get('/backup-safe', (req, res) => {
  const filename = req.query.filename || 'welcome.txt';
  if (!/^[A-Za-z0-9._-]+$/.test(filename) || filename.startsWith('-')) {
    return res.status(400).json({ error: 'invalid filename', filename });
  }
  const dir = path.join(__dirname, '..', 'data', 'public');
  const args = ['-czf', '/tmp/backup-safe.tgz', '-C', dir, '--', filename];
  execFile('tar', args, { timeout: 5000 }, (err, stdout, stderr) => {
    res.json({ argv: ['tar', ...args], stdout, stderr, error: err ? err.message : null });
  });
});

module.exports = { base: '/injection/command', router };
