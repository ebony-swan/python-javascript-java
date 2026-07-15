using Microsoft.AspNetCore.Mvc;
using System.IO;

namespace VulnApp.Controllers;

/// <summary>
/// Path Traversal —
/// OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05.
///
/// Mirrors the annotation format and attribute-routed action style of
/// SqlInjectionController (the reference module for the C# app). Every permutation
/// carries a standard header describing the flaw, its CWE, an exploitation-likelihood
/// rating, greenfield-vs-legacy prevalence, an example request and the safe pattern.
/// The dangerous line in each handler is tagged with a "VULNERABLE:" inline comment
/// and the file ends with ONE clearly-labelled SAFE reference handler.
///
/// A path-traversal flaw lets an attacker step OUTSIDE the directory an endpoint was
/// meant to serve (or write into) by smuggling ".." segments — or an absolute path —
/// into a filename that the code joins onto a trusted base and hands to the filesystem.
/// No ORM/driver fixes it: safe file access is application logic (canonicalize the
/// resolved path, then confirm it stays inside the base directory).
///
/// Layout (paths are relative to the process cwd, which is the csharp/ app root):
///   base "public" dir : data/public   (contains welcome.txt — the ONLY thing these
///                                       endpoints are supposed to serve)
///   secret target     : data/secret.txt   (one level UP — reachable via ../secret.txt,
///                                           returns the flag CSHARP_TRAVERSAL_OK)
///   extract scratch   : data/extract   (where P3 pretends to unpack an archive)
///
/// NOTE ON THE .NET SINK: Path.Combine does NOT normalize — Path.Combine("data/public",
/// "../secret.txt") yields "data/public/../secret.txt" and the OS collapses the ".."
/// at open time, while Path.Combine(base, "/etc/passwd") DISCARDS the base and returns
/// the absolute path verbatim. Both escapes therefore work with no extra effort.
/// </summary>
[ApiController]
public class PathTraversalController : ControllerBase
{
    // The directory these endpoints are (supposedly) restricted to, and the scratch
    // directory the "archive extractor" is (supposedly) confined to.
    private static readonly string BasePublicDir = Path.Combine("data", "public");
    private static readonly string ExtractDir = Path.Combine("data", "extract");

    // ========================================================================
    // PERMUTATION 1 — Path traversal file READ (base + name, no containment)
    // OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
    // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    // EXPLOITATION LIKELIHOOD: HIGH — reachable pre-auth, deterministic, zero tooling;
    //   the server joins data/public with the raw ?file= value and reads it, so a single
    //   "../secret.txt" hop escapes the public dir and an absolute "/etc/passwd" is read
    //   verbatim. One GET dumps any file the process user can read (secrets, keys, config).
    // PREVALENCE TODAY: greenfield MEDIUM (ASP.NET Core static-file serving via
    //   PhysicalFileProvider normalizes and rejects "..", but the moment a dev hand-rolls
    //   "serve a file by user-supplied name" — file preview, avatar/image, report/export,
    //   template include — nothing guards the concatenated path) | legacy/10yr tech-debt
    //   HIGH (download.ashx?file=... / GetFile?name=... handlers that concatenate a
    //   request param into File.ReadAllText are endemic in old ASP.NET codebases).
    // EXAMPLE:
    //   curl 'http://127.0.0.1:5001/path/read?file=welcome.txt'                 # intended
    //   curl --data-urlencode 'file=../secret.txt' -G 'http://127.0.0.1:5001/path/read'   # escape -> Flag: CSHARP_TRAVERSAL_OK
    //   curl --data-urlencode 'file=/etc/passwd'   -G 'http://127.0.0.1:5001/path/read'   # absolute
    // FIX: canonicalize (Path.GetFullPath) and verify StartsWith(baseFull) BEFORE
    //   reading; see the SAFE reference handler /path/read-safe.
    // ========================================================================
    [HttpGet("/path/read")]
    public IActionResult Read(string file = "welcome.txt")
    {
        // VULNERABLE: base dir joined with the untrusted name, NO normalization or
        // containment check; ".." escapes and an absolute path replaces the base.
        var path = Path.Combine(BasePublicDir, file);
        var resolved = Path.GetFullPath(path);
        try
        {
            var contents = System.IO.File.ReadAllText(path);
            return new JsonResult(new { file, resolved_path = resolved, contents });
        }
        catch (Exception e)
        {
            return new JsonResult(new { file, resolved_path = resolved, error = e.Message }) { StatusCode = 404 };
        }
    }

    // ========================================================================
    // PERMUTATION 2 — Path traversal file DOWNLOAD (Content-Disposition stream)
    // OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
    // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    // EXPLOITATION LIKELIHOOD: HIGH — identical traversal to P1 but framed as a download:
    //   the ?name= value is joined to data/public and streamed back with an attachment
    //   header, so "../secret.txt" / "/etc/passwd" are exfiltrated as a downloaded file.
    //   Pre-auth, deterministic, no tooling.
    // PREVALENCE TODAY: greenfield MEDIUM (download-with-Content-Disposition is a
    //   first-class feature and framework static serving is safe, but a bespoke
    //   "download controller that builds the path from a filename param" is a thing devs
    //   still write by hand for exports/attachments) | legacy/10yr tech-debt HIGH (the
    //   classic Download.aspx?file= / getFile?name= handler pattern that shipped and stayed).
    // EXAMPLE:
    //   curl -OJ 'http://127.0.0.1:5001/path/download?name=welcome.txt'          # intended
    //   curl 'http://127.0.0.1:5001/path/download?name=../secret.txt'            # escape
    //   curl 'http://127.0.0.1:5001/path/download?name=/etc/passwd'              # absolute
    //   (the resolved path is echoed in the X-Resolved-Path response header)
    // FIX: canonicalize + containment-check the resolved path before streaming, and
    //   derive the download filename from an allow-list; see /path/read-safe.
    // ========================================================================
    [HttpGet("/path/download")]
    public IActionResult Download(string name = "welcome.txt")
    {
        // VULNERABLE: same unchecked join; whatever path the client names is streamed
        // back as an attachment, including ".." escapes and absolute paths.
        var path = Path.Combine(BasePublicDir, name);
        var resolved = Path.GetFullPath(path);
        Response.Headers["X-Resolved-Path"] = resolved;
        try
        {
            var bytes = System.IO.File.ReadAllBytes(path);
            var downloadName = Path.GetFileName(name);
            if (string.IsNullOrEmpty(downloadName)) downloadName = "download";
            return File(bytes, "application/octet-stream", downloadName);
        }
        catch (Exception e)
        {
            return new JsonResult(new { name, resolved_path = resolved, error = e.Message }) { StatusCode = 404 };
        }
    }

    // ========================================================================
    // PERMUTATION 3 — Zip Slip / arbitrary file WRITE (extractDir + entry.name)
    // OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
    // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    // EXPLOITATION LIKELIHOOD: MEDIUM-HIGH — simulates archive extraction: each entry is
    //   written to Path.Combine(extractDir, entry.name) with no containment, so an entry
    //   named "../../pwned.txt" lands OUTSIDE the extract dir (an absolute name writes
    //   anywhere the process user can). The write itself is 100% reliable and pre-auth;
    //   escalation to RCE is what keeps it below HIGH — it needs a useful writable target
    //   (web root .cshtml/.dll, a cron/systemd unit, ~/.ssh/authorized_keys, appsettings),
    //   so impact depends on the environment.
    // PREVALENCE TODAY: greenfield MEDIUM (ZipFile.ExtractToDirectory now validates entry
    //   paths stay under the destination, and the 2018 "Zip Slip" wave + SAST rules raised
    //   awareness — but hand-rolled extraction loops and multipart upload handlers keep it
    //   recurring: IFormFile.FileName is NOT sanitized and can contain ".." segments) |
    //   legacy/10yr tech-debt HIGH (manual per-entry unzip loops predating Zip Slip, and
    //   upload handlers that trust the client-supplied filename verbatim).
    // EXAMPLE:
    //   curl -X POST 'http://127.0.0.1:5001/path/extract' -H 'Content-Type: application/json' \
    //     -d '{"entries":[{"name":"note.txt","content":"hi"},
    //                     {"name":"../../pwned.txt","content":"zip-slip-was-here"}]}'
    //   -> the second entry's write_path is csharp/pwned.txt (the app root), OUTSIDE
    //      data/extract, and escaped_extract_dir=true. Add more "../" (or an absolute
    //      name like /tmp/pwned.txt) to write anywhere the process user can.
    // FIX: for every entry, Path.GetFullPath the resolved target and require it to
    //   StartsWith(extractDirFull) before writing (reject otherwise); mirror the SAFE handler.
    // ========================================================================
    [HttpPost("/path/extract")]
    public IActionResult Extract([FromBody] PathExtractRequest body)
    {
        var extractFull = Path.GetFullPath(ExtractDir);
        Directory.CreateDirectory(ExtractDir);
        var results = new List<object>();
        var entries = body?.Entries ?? new List<PathExtractEntry>();
        foreach (var entry in entries)
        {
            var name = entry?.Name ?? "";
            var content = entry?.Content ?? "";
            // VULNERABLE: the extract dir is joined with the archive entry name with NO
            // containment check — "../../pwned.txt" (or an absolute name) escapes the
            // extract dir; the classic "Zip Slip" arbitrary file write.
            var dest = Path.Combine(ExtractDir, name);
            var resolved = Path.GetFullPath(dest);
            try
            {
                var parent = Path.GetDirectoryName(resolved);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                System.IO.File.WriteAllText(dest, content);
                results.Add(new
                {
                    name,
                    write_path = resolved,
                    bytes_written = System.Text.Encoding.UTF8.GetByteCount(content),
                    escaped_extract_dir = !resolved.StartsWith(extractFull + Path.DirectorySeparatorChar)
                });
            }
            catch (Exception e)
            {
                results.Add(new { name, write_path = resolved, error = e.Message });
            }
        }
        return new JsonResult(new { extract_dir = extractFull, extracted = results });
    }

    // ========================================================================
    // SAFE REFERENCE — canonicalize the resolved path, then enforce containment.
    // Shown so the vulnerable/safe pair can be diffed by SAST tooling and learners.
    //
    // Path.GetFullPath collapses ".." segments to a single absolute path; requiring the
    // result to equal the base dir or sit under base + separator rejects every traversal
    // payload BEFORE the file is opened. "../secret.txt" canonicalizes to data/secret.txt
    // (fails the check) and an absolute "/etc/passwd" canonicalizes to itself (fails the
    // check) — both rejected, while "welcome.txt" passes and is served. This is the safe
    // counterpart to P1 (and the same check fixes P2's download and P3's per-entry write).
    //   curl 'http://127.0.0.1:5001/path/read-safe?file=welcome.txt'      # allowed
    //   curl 'http://127.0.0.1:5001/path/read-safe?file=../secret.txt'    # rejected (403)
    //   curl 'http://127.0.0.1:5001/path/read-safe?file=/etc/passwd'      # rejected (403)
    // ========================================================================
    [HttpGet("/path/read-safe")]
    public IActionResult ReadSafe(string file = "welcome.txt")
    {
        var baseFull = Path.GetFullPath(BasePublicDir);
        var requested = Path.GetFullPath(Path.Combine(BasePublicDir, file));
        // SAFE: refuse anything whose canonical path escapes the intended base dir.
        if (requested != baseFull && !requested.StartsWith(baseFull + Path.DirectorySeparatorChar))
            return new JsonResult(new { file, resolved_path = requested, error = "path escapes base directory" }) { StatusCode = 403 };
        try
        {
            var contents = System.IO.File.ReadAllText(requested);
            return new JsonResult(new { file, resolved_path = requested, contents });
        }
        catch (Exception e)
        {
            return new JsonResult(new { file, resolved_path = requested, error = e.Message }) { StatusCode = 404 };
        }
    }
}

// ============================================================================
// Request DTOs for the P3 "archive extractor". Category-unique names (Path…) so
// they never collide with the shared VulnApp.Controllers namespace used by the
// other lab modules. Inert data holders — the vulnerability is the unchecked
// join in Extract(), not these types.
// ============================================================================
public class PathExtractRequest
{
    public List<PathExtractEntry> Entries { get; set; }
}

public class PathExtractEntry
{
    public string Name { get; set; }
    public string Content { get; set; }
}
