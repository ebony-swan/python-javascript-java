package com.example.vulnapp.vulns;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Path Traversal —
 * OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05.
 *
 * Comment/annotation format mirrors {@link SqlInjectionController} (the reference
 * module): every permutation carries a standard header describing the flaw, its
 * CWE, an exploitation-likelihood rating, greenfield-vs-legacy prevalence, an
 * example request, and the corresponding safe pattern. The dangerous line in each
 * handler is tagged with a "VULNERABLE:" inline comment. The file ends with ONE
 * clearly-labelled SAFE reference handler.
 *
 * PRIMARY CWE: CWE-22 Improper Limitation of a Pathname to a Restricted Directory.
 *
 * Layout (paths are relative to the process cwd, which is the java/ app root):
 *   base "public" dir : data/public   (contains welcome.txt — the ONLY thing these
 *                                       endpoints are supposed to serve)
 *   secret target     : data/secret.txt   (one level UP from public — reachable
 *                                           with ../secret.txt)
 * The sinks below join the base dir with a user-controlled name using
 * {@link Path#resolve(String)} and perform NO normalization / containment check.
 * resolve() keeps ".." segments verbatim and, when handed an ABSOLUTE path,
 * returns it unchanged — so both "../secret.txt" and "/etc/passwd" escape.
 */
@RestController
@RequestMapping("/path")
public class PathTraversalController {

    /** The directory these endpoints are (supposedly) restricted to. */
    private static final Path BASE_PUBLIC_DIR = Paths.get("data/public");
    /** Where P3 pretends to unpack an uploaded archive. */
    private static final Path EXTRACT_DIR = Paths.get("data/extract");

    // ========================================================================
    // PERMUTATION 1 — Path traversal file READ (base + name, no containment)
    // OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
    // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    // EXPLOITATION LIKELIHOOD: HIGH — reachable pre-auth, deterministic, no tooling;
    //   the server joins data/public with the raw ?file= value and reads it, so
    //   "../secret.txt" escapes the public dir and an absolute "/etc/passwd" is read
    //   verbatim. One GET dumps any file the JVM user can read.
    // PREVALENCE TODAY: greenfield MEDIUM (framework STATIC handlers normalize and
    //   reject ".." by default, but the moment a dev hand-rolls "serve a file by
    //   user-supplied name" — report/export/attachment downloads, AI-generated
    //   snippets — nothing guards it) | legacy/10yr tech-debt HIGH (old file-download
    //   servlets/CGIs that concatenate a request param into a path are everywhere).
    // EXAMPLE:
    //   curl 'http://127.0.0.1:8080/path/read?file=welcome.txt'          # intended
    //   curl --data-urlencode 'file=../secret.txt' -G 'http://127.0.0.1:8080/path/read'   # escape -> Flag: JAVA_TRAVERSAL_OK
    //   curl --data-urlencode 'file=/etc/passwd'   -G 'http://127.0.0.1:8080/path/read'   # absolute
    // FIX: canonicalize (Path.toRealPath) and verify startsWith(baseReal) BEFORE
    //   reading; see the SAFE reference handler /path/read-safe.
    // ========================================================================
    @GetMapping("/read")
    public Map<String, Object> read(@RequestParam(defaultValue = "welcome.txt") String file) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("base_dir", BASE_PUBLIC_DIR.toAbsolutePath().normalize().toString());
        out.put("requested_file", file);
        // VULNERABLE: base dir joined with untrusted name, no normalization/containment.
        // resolve() keeps ".." and returns an absolute argument unchanged.
        Path target = BASE_PUBLIC_DIR.resolve(file);
        out.put("resolved_path", target.toAbsolutePath().normalize().toString());
        try {
            byte[] bytes = Files.readAllBytes(target);
            out.put("bytes_read", bytes.length);
            out.put("content", new String(bytes, StandardCharsets.UTF_8));
        } catch (Exception e) {
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }

    // ========================================================================
    // PERMUTATION 2 — Path traversal file DOWNLOAD (Content-Disposition stream)
    // OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
    // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    // EXPLOITATION LIKELIHOOD: HIGH — identical traversal to P1 but framed as a
    //   download: the ?name= value is joined to data/public and streamed back with an
    //   attachment header, so "../secret.txt" / "/etc/passwd" are exfiltrated as a
    //   file. Pre-auth, deterministic, no tooling.
    // PREVALENCE TODAY: greenfield MEDIUM (download-with-Content-Disposition is a
    //   first-class feature and framework static serving is safe, but bespoke
    //   "download controller that builds the path from a filename param" is a common
    //   thing devs still write by hand) | legacy/10yr tech-debt HIGH (the classic
    //   download.jsp?file= / getFile?name= servlet pattern that shipped and stayed).
    // EXAMPLE:
    //   curl -OJ 'http://127.0.0.1:8080/path/download?name=welcome.txt'         # intended
    //   curl 'http://127.0.0.1:8080/path/download?name=../secret.txt'           # escape
    //   curl 'http://127.0.0.1:8080/path/download?name=/etc/passwd'             # absolute
    //   (the resolved path is echoed in the X-Resolved-Path response header)
    // FIX: canonicalize + containment-check the resolved path before streaming;
    //   see the SAFE reference handler /path/read-safe.
    // ========================================================================
    @GetMapping("/download")
    public ResponseEntity<byte[]> download(@RequestParam(defaultValue = "welcome.txt") String name) {
        // VULNERABLE: base dir joined with untrusted name, no normalization/containment.
        Path target = BASE_PUBLIC_DIR.resolve(name);
        String resolved = target.toAbsolutePath().normalize().toString();
        try {
            byte[] bytes = Files.readAllBytes(target);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentDisposition(ContentDisposition.attachment()
                    .filename(target.getFileName().toString()).build());
            headers.add("X-Resolved-Path", resolved);
            return ResponseEntity.ok()
                    .headers(headers)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(bytes);
        } catch (Exception e) {
            String msg = "download failed for '" + name + "' (resolved " + resolved + "): "
                    + e.getClass().getSimpleName() + ": " + e.getMessage();
            return ResponseEntity.status(404)
                    .header("X-Resolved-Path", resolved)
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(msg.getBytes(StandardCharsets.UTF_8));
        }
    }

    // ========================================================================
    // PERMUTATION 3 — Zip Slip / arbitrary file WRITE (extractDir + entry.name)
    // OWASP 2021 A01 Broken Access Control (path traversal)  ->  OWASP 2025 A01 / A05
    // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    // EXPLOITATION LIKELIHOOD: MEDIUM-HIGH — simulates archive extraction: each entry
    //   is written to resolve(extractDir, entry.name) with no containment, so an entry
    //   named "../../pwned.txt" lands OUTSIDE the extract dir. The write itself is
    //   100% reliable and pre-auth; escalation to RCE is what tempers it from HIGH —
    //   it needs a useful writable target (web root, cron, a startup/rc script, a
    //   config file), so impact depends on the environment.
    // PREVALENCE TODAY: greenfield MEDIUM (the 2018 "Zip Slip" disclosure + SAST rules
    //   mean many teams now check entry paths, but the broader "write a file using an
    //   attacker-supplied name/path" bug recurs via multipart upload filenames —
    //   MultipartFile.getOriginalFilename() is NOT sanitized and can contain "..") |
    //   legacy/10yr tech-debt HIGH (hand-rolled unzip loops predating Zip Slip, and
    //   upload handlers that trust the client-supplied filename verbatim).
    // EXAMPLE:
    //   curl -X POST 'http://127.0.0.1:8080/path/extract' -H 'Content-Type: application/json' \
    //     -d '{"entries":[{"name":"note.txt","content":"hi"},
    //                      {"name":"../../pwned.txt","content":"zip-slip-was-here"}]}'
    //   -> the second entry's resolved_path is java/pwned.txt (the app root), OUTSIDE
    //      data/extract, and the response flags escaped_extract_dir=true. Add more
    //      "../" (or an absolute name) to write anywhere the JVM user can.
    // FIX: for every entry, resolve then canonicalize and require
    //   target.toRealPath().startsWith(extractDir.toRealPath()) before writing (reject
    //   otherwise); mirror the containment check in the SAFE reference handler.
    // ========================================================================
    @SuppressWarnings("unchecked")
    @PostMapping("/extract")
    public Map<String, Object> extract(@RequestBody(required = false) Map<String, Object> body) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("extract_dir", EXTRACT_DIR.toAbsolutePath().normalize().toString());
        List<Map<String, Object>> results = new ArrayList<>();
        out.put("results", results);
        try {
            Files.createDirectories(EXTRACT_DIR);
            Object rawEntries = body == null ? null : body.get("entries");
            if (!(rawEntries instanceof List<?> entries)) {
                out.put("error", "expected JSON body {\"entries\":[{\"name\":...,\"content\":...}]}");
                return out;
            }
            for (Object rawEntry : entries) {
                Map<String, Object> r = new LinkedHashMap<>();
                results.add(r);
                if (!(rawEntry instanceof Map<?, ?> entry)) {
                    r.put("error", "entry is not an object");
                    continue;
                }
                Object nameObj = ((Map<String, Object>) entry).get("name");
                Object contentObj = ((Map<String, Object>) entry).get("content");
                String name = nameObj == null ? "" : nameObj.toString();
                String content = contentObj == null ? "" : contentObj.toString();
                r.put("name", name);
                // VULNERABLE: extract dir joined with the archive entry name, no
                // containment check — "../../pwned.txt" escapes the extract dir (Zip Slip).
                Path target = EXTRACT_DIR.resolve(name);
                String resolved = target.toAbsolutePath().normalize().toString();
                r.put("resolved_path", resolved);
                try {
                    if (target.getParent() != null) {
                        Files.createDirectories(target.getParent());
                    }
                    Files.write(target, content.getBytes(StandardCharsets.UTF_8));
                    r.put("wrote_bytes", content.getBytes(StandardCharsets.UTF_8).length);
                    r.put("escaped_extract_dir",
                            !resolved.startsWith(EXTRACT_DIR.toAbsolutePath().normalize().toString()));
                } catch (Exception e) {
                    r.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }

    // ========================================================================
    // SAFE REFERENCE — canonicalize the resolved path and enforce containment.
    // Shown so the vulnerable/safe pair can be diffed by SAST tooling and learners.
    //
    // Path.toRealPath() collapses ".." and resolves symlinks to the true on-disk
    // location; startsWith(baseReal) then proves the target lives inside data/public.
    // "../secret.txt" canonicalizes to data/secret.txt (fails the check) and an
    // absolute "/etc/passwd" canonicalizes to itself (fails the check) — both are
    // rejected, while "welcome.txt" passes and is served. Contrast with P1/P2, which
    // read whatever resolve() produced without ever canonicalizing or checking.
    //   curl 'http://127.0.0.1:8080/path/read-safe?file=welcome.txt'      # allowed
    //   curl 'http://127.0.0.1:8080/path/read-safe?file=../secret.txt'    # rejected
    //   curl 'http://127.0.0.1:8080/path/read-safe?file=/etc/passwd'      # rejected
    // ========================================================================
    @GetMapping("/read-safe")
    public Map<String, Object> readSafe(@RequestParam(defaultValue = "welcome.txt") String file) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("requested_file", file);
        try {
            Path baseReal = BASE_PUBLIC_DIR.toRealPath();
            out.put("base_dir", baseReal.toString());
            // Resolve then CANONICALIZE to the true on-disk path (collapses .. / symlinks).
            Path targetReal = BASE_PUBLIC_DIR.resolve(file).toRealPath();
            out.put("resolved_path", targetReal.toString());
            // SAFE: refuse anything that canonicalizes outside the intended base dir.
            if (!targetReal.startsWith(baseReal)) {
                out.put("rejected", "resolved path escapes the public base dir");
                return out;
            }
            byte[] bytes = Files.readAllBytes(targetReal);
            out.put("bytes_read", bytes.length);
            out.put("content", new String(bytes, StandardCharsets.UTF_8));
        } catch (Exception e) {
            // toRealPath() throws NoSuchFileException for a missing file — also safe.
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }
}
