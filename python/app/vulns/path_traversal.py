"""Path Traversal — OWASP 2021 A01 Broken Access Control  ->  OWASP 2025 A01 / A05.

A path-traversal flaw lets an attacker step *outside* the directory an endpoint
was meant to serve (or write into) by smuggling ``..`` segments — or an absolute
path — into a filename that the code joins onto a trusted base and then hands to
``open()``. Unlike injection, no ORM/driver fixes it: safe file access is
application logic (canonicalize, then confirm the result stays inside the base).

The comment/annotation format here mirrors the reference module
``app/vulns/injection_sql.py``: every permutation carries a standard header with
its CWE, an exploitation-likelihood rating, prevalence notes, an example
request, and the corresponding safe pattern. Every dangerous sink is marked
``VULNERABLE:`` and the file ends with ONE clearly-labelled SAFE reference
handler.

The endpoints are supposed to be restricted to ``app/data/public`` (which holds
``welcome.txt``); the target the traversals reach is ``app/data/secret.txt``,
one level up.
"""
import os

from flask import Blueprint, request, jsonify, Response

bp = Blueprint("path_traversal", __name__, url_prefix="/path")

# The directory the file endpoints are *supposed* to be confined to, and the
# scratch directory the "archive extractor" is *supposed* to unpack into.
BASE_PUBLIC_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "public")
EXTRACT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "extract")


# =============================================================================
# PERMUTATION 1 — Arbitrary file READ via unchecked path join
# OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
# EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic, zero tooling. One
#   query parameter selects the file; a single '..' hop or an absolute path
#   reads anything the process can (app secrets, /etc/passwd, config, keys).
# PREVALENCE TODAY: greenfield MEDIUM (frameworks ship safe helpers like
#   send_from_directory/safe_join, but hand-rolled file-preview, avatar/image,
#   report and template-include endpoints still concatenate a user-named path)
#   | legacy/10yr tech-debt HIGH (download.php?file=... style code that opens
#   base + user_input with no normalization is endemic in old codebases).
# EXAMPLE:
#   curl 'http://127.0.0.1:5000/path/read?file=../secret.txt'   -> Flag: PY_TRAVERSAL_OK
#   curl 'http://127.0.0.1:5000/path/read?file=/etc/passwd'
#   curl 'http://127.0.0.1:5000/path/read?file=../../../../etc/passwd'
# FIX: realpath the joined path and verify it stays within the base dir, or use
#   the framework's safe_join / send_from_directory (see the SAFE handler below).
# =============================================================================
@bp.get("/read")
def read_file():
    filename = request.args.get("file", "welcome.txt")
    # VULNERABLE: user-controlled name joined onto the base dir with NO
    # normalization or containment check; '..' and absolute paths escape.
    path = os.path.join(BASE_PUBLIC_DIR, filename)
    try:
        with open(path) as fh:
            contents = fh.read()
    except OSError as exc:
        return jsonify({"file": filename, "path": path, "error": str(exc)}), 404
    return jsonify(
        {"file": filename, "resolved_path": os.path.realpath(path), "contents": contents}
    )


# =============================================================================
# PERMUTATION 2 — Arbitrary file DOWNLOAD via unchecked path join
# OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
# EXPLOITATION LIKELIHOOD: HIGH — identical traversal to P1, just framed as a
#   file download: the same '..'/absolute-path payload streams any readable file
#   back with an attachment header. Pre-auth, deterministic, no tooling.
# PREVALENCE TODAY: greenfield MEDIUM ("download this attachment/export by name"
#   endpoints are routinely hand-rolled with a Content-Disposition header even in
#   modern apps, and the safe download helpers are under-used) | legacy/10yr
#   tech-debt HIGH (getFile?name=... download servlets/handlers everywhere).
# EXAMPLE:
#   curl -OJ 'http://127.0.0.1:5000/path/download?name=../secret.txt'
#   curl 'http://127.0.0.1:5000/path/download?name=/etc/passwd'
# FIX: canonicalize + containment-check (or send_from_directory), and derive the
#   download filename from an allow-list, never from the raw path.
# =============================================================================
@bp.get("/download")
def download():
    name = request.args.get("name", "welcome.txt")
    # VULNERABLE: same unchecked join; whatever path the client names is streamed
    # back as an attachment, including '..' escapes and absolute paths.
    path = os.path.join(BASE_PUBLIC_DIR, name)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return jsonify({"name": name, "path": path, "error": str(exc)}), 404
    download_name = os.path.basename(name) or "download"
    resp = Response(data, mimetype="application/octet-stream")
    resp.headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
    resp.headers["X-Resolved-Path"] = os.path.realpath(path)
    return resp


# =============================================================================
# PERMUTATION 3 — Arbitrary file WRITE via "archive extraction" (Zip Slip)
# OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
# EXPLOITATION LIKELIHOOD: MEDIUM-HIGH — arbitrary WRITE is more powerful than a
#   read (overwrite web-root code, drop a cron/systemd unit or ~/.ssh key -> RCE),
#   but landing impact usually needs a known writable, executable target path and
#   sometimes a second step to trigger it, so it rates just below the direct read.
# PREVALENCE TODAY: greenfield MEDIUM (zipfile.extractall sanitizes members by
#   default, but hand-rolled extraction loops, tar handling, and upload-unpack /
#   storage-sync code that writes join(dir, entry.name) keep Zip Slip recurring
#   across every ecosystem — it was a broad 2018 disclosure wave) | legacy/10yr
#   tech-debt HIGH (manual per-entry extraction with no path check is the norm).
# EXAMPLE:
#   curl -X POST -H 'Content-Type: application/json' \
#     -d '{"entries":[{"name":"../../pwned.txt","content":"owned"}]}' \
#     http://127.0.0.1:5000/path/extract
#   -> writes app/pwned.txt, OUTSIDE the intended extract dir (absolute names work too)
# FIX: for each entry, realpath(join(dir, name)) and reject anything that does
#   not stay under the extraction root (same check as the SAFE handler below).
# =============================================================================
@bp.post("/extract")
def extract():
    body = request.get_json(silent=True) or {}
    entries = body.get("entries", [])
    os.makedirs(EXTRACT_DIR, exist_ok=True)
    results = []
    for entry in entries:
        name = entry.get("name", "")
        content = entry.get("content", "")
        # VULNERABLE: the archive entry name is joined onto the extract dir with
        # NO containment check; '../../pwned.txt' (or an absolute path) writes
        # OUTSIDE extractDir — the classic "Zip Slip" arbitrary file write.
        dest = os.path.join(EXTRACT_DIR, name)
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(dest, "w") as fh:
            fh.write(content)
        results.append({"name": name, "written_to": os.path.realpath(dest)})
    return jsonify(
        {"extract_dir": os.path.realpath(EXTRACT_DIR), "extracted": results}
    )


# =============================================================================
# SAFE REFERENCE — canonicalize, then enforce containment within the base dir.
# os.path.realpath resolves '..' segments and symlinks to a single absolute
# path; requiring it to equal the base or sit under base + os.sep rejects every
# traversal payload BEFORE the file is opened. This is the safe counterpart to
# PERMUTATION 1 (and the same check fixes P2's download and P3's per-entry
# write). Shown so the vulnerable/safe pair can be diffed by SAST and learners.
# =============================================================================
@bp.get("/read-safe")
def read_safe():
    filename = request.args.get("file", "welcome.txt")
    base = os.path.realpath(BASE_PUBLIC_DIR)
    requested = os.path.realpath(os.path.join(base, filename))
    # SAFE: reject anything whose canonical path escapes the intended base dir.
    if requested != base and not requested.startswith(base + os.sep):
        return jsonify(
            {"error": "path escapes base directory", "file": filename}
        ), 403
    try:
        with open(requested) as fh:
            contents = fh.read()
    except OSError as exc:
        return jsonify({"error": str(exc), "file": filename}), 404
    return jsonify({"file": filename, "resolved_path": requested, "contents": contents})
