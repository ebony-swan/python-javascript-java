#!/usr/bin/env python3
"""
SAST report -> ground-truth benchmark engine (vendor-neutral).

Drop in any SAST vendor's report and score it against this project's known
planted vulnerabilities (benchmark/baseline.json).

    python3 benchmark/compare.py <report>              # auto-detect format
    python3 benchmark/compare.py report.sarif
    python3 benchmark/compare.py report.csv --md out.md --json out.json

Supported formats (auto-detected): SARIF (.sarif/.json), generic JSON array,
and CSV (columns auto-detected; override with --col-* flags). No third-party
dependencies.

What it reports:
  * Coverage matrix  - did the tool detect each planted vuln class per language?
  * Recall           - planted category x language cells detected / 24
  * Precision        - false positives on the SAFE control handlers (needs line #s)
  * Inflation        - duplicate paths / multiple rules per sink
  * Buckets          - core / data-exposure / hardening / noise / cross-file / framework
  * Severity         - vendor histogram vs the CVSS ground-truth baseline
"""
import argparse
import csv as csvmod
import json
import os
import re
import sys
from collections import defaultdict, Counter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

LANG_DIRS = {
    "python": os.path.join(REPO, "python", "app", "vulns"),
    "javascript": os.path.join(REPO, "javascript", "routes"),
    "java": os.path.join(REPO, "java", "src", "main", "java", "com", "example", "vulnapp", "vulns"),
}


# --------------------------------------------------------------------------- #
# Normalisation helpers
# --------------------------------------------------------------------------- #
def norm_sev(raw):
    s = str(raw or "").strip()
    if not s:
        return "Info"
    try:
        v = float(s)  # numeric CVSS score
        if v >= 9:
            return "Critical"
        if v >= 7:
            return "High"
        if v >= 4:
            return "Medium"
        if v > 0:
            return "Low"
        return "Info"
    except ValueError:
        pass
    u = s.lower()
    table = {
        "critical": "Critical", "crit": "Critical", "blocker": "Critical",
        "high": "High", "error": "High", "severe": "High", "major": "High",
        "medium": "Medium", "moderate": "Medium", "warning": "Medium", "med": "Medium", "warn": "Medium",
        "low": "Low", "minor": "Low", "note": "Low",
        "info": "Info", "informational": "Info", "information": "Info", "none": "Info",
    }
    return table.get(u, s.title())


def extract_cwe(*vals):
    for v in vals:
        if v is None:
            continue
        m = re.search(r"cwe[-_ /]?(\d+)", str(v), re.I)
        if m:
            return int(m.group(1))
    return None


def detect_lang(path):
    p = (path or "").lower()
    if p.endswith(".py"):
        return "python"
    if p.endswith((".js", ".jsx", ".ts", ".mjs", ".cjs")):
        return "javascript"
    if p.endswith((".java", ".html")):
        return "java"
    return None


def map_module(path, patterns):
    b = os.path.basename(path or "").lower()
    full = (path or "").lower()
    for pat, mod in patterns:
        if pat in b or pat in full:
            return mod
    return None


def _norm_rule(rule):
    return re.sub(r"[\s\-]+", "_", (rule or "").strip().lower())


def map_category(rule, cwe, baseline):
    """Return (category_id_or_None, bucket). bucket in
    {core, data-exposure, hardening, noise, unmapped}.

    Vendor rule *names* are usually more precise than their CWE tags (e.g. a
    finding named "Cross-site Scripting" mis-tagged CWE-94), so the rule name
    is tried first for the core category, with CWE as the fallback."""
    r = _norm_rule(rule)
    # 1) core category by rule-name keyword (most precise vendor signal)
    for kw, cid in baseline["rule_keywords"]:
        if kw in r:
            return cid, "core"
    # 2) core category by CWE (fallback for opaque rule ids, e.g. SARIF)
    if cwe is not None:
        for cid, meta in baseline["categories"].items():
            if cwe in meta["cwes"]:
                return cid, "core"
    # 3) non-core rule families by name
    for kw in baseline.get("data_exposure_rules", []):
        if kw in r:
            return None, "data-exposure"
    for kw in baseline.get("hardening_rules", []):
        if kw in r:
            return None, "hardening"
    for kw in baseline.get("noise_rules", []):
        if kw in r:
            return None, "noise"
    # 4) data-exposure by CWE
    if cwe is not None and cwe in baseline.get("data_exposure_cwes", []):
        return None, "data-exposure"
    return None, "unmapped"


# --------------------------------------------------------------------------- #
# Source scan: locate SAFE reference handler line ranges (the control group)
# --------------------------------------------------------------------------- #
def scan_safe_ranges():
    """Return {basename: [(start_line, end_line), ...]} for SAFE reference
    handlers only.

    A handler counts as SAFE when its ROUTE PATH or its FUNCTION/METHOD NAME
    contains 'safe' (e.g. /login-safe, read_safe, resetTokenSafe) -- NOT merely
    because a nearby comment says "see the SAFE reference". Comment-based
    matching would wrongly flag every handler, since each documents its safe
    counterpart."""
    anchor_rx = {
        "python": re.compile(r"^\s*@bp\.(?:get|post|put|delete|route)\(", re.I),
        "javascript": re.compile(r"^\s*router\.(?:get|post|put|delete|use)\(", re.I),
        "java": re.compile(r"^\s*@(?:Get|Post|Put|Delete|Request)Mapping\b"),
    }
    quoted = re.compile(r"""["']([^"']*)["']""")
    py_def = re.compile(r"^\s*def\s+(\w+)")
    java_name = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    ranges = defaultdict(list)
    for lang, d in LANG_DIRS.items():
        if not os.path.isdir(d):
            continue
        rx = anchor_rx[lang]
        for fn in os.listdir(d):
            path = os.path.join(d, fn)
            if not os.path.isfile(path):
                continue
            try:
                lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
            except OSError:
                continue
            starts = [i + 1 for i, ln in enumerate(lines) if rx.match(ln)]
            starts.append(len(lines) + 1)  # sentinel
            for k in range(len(starts) - 1):
                s, e = starts[k], starts[k + 1] - 1
                m = quoted.search(lines[s - 1])
                route = m.group(1) if m else ""
                name = ""
                if lang == "python":
                    dm = py_def.search("\n".join(lines[s - 1:min(s + 4, e + 1)]))
                    name = dm.group(1) if dm else ""
                elif lang == "java":
                    for ln in lines[s:min(s + 6, e + 1)]:
                        st = ln.strip()
                        if st.startswith(("//", "*", "/*", "@")):
                            continue  # skip comments/annotations (a comment word
                                      # like "unsafe (" must not be read as a method)
                        if "(" in ln:
                            jm = java_name.search(ln)
                            name = jm.group(1) if jm else ""
                            break
                if "safe" in route.lower() or "safe" in name.lower():
                    ranges[fn].append((s, e))
    return ranges


# --------------------------------------------------------------------------- #
# Report loaders
# --------------------------------------------------------------------------- #
def load_report(path, fmt, col_overrides):
    if fmt == "auto":
        fmt = guess_format(path)
    if fmt == "sarif":
        return parse_sarif(json.load(open(path, encoding="utf-8-sig")))
    if fmt == "json":
        return parse_json(json.load(open(path, encoding="utf-8-sig")))
    if fmt == "csv":
        return parse_csv(path, col_overrides)
    raise SystemExit(f"unknown format: {fmt}")


def guess_format(path):
    lower = path.lower()
    if lower.endswith(".csv"):
        return "csv"
    if lower.endswith(".sarif"):
        return "sarif"
    try:
        head = open(path, encoding="utf-8-sig").read(4096).lstrip()
    except OSError:
        return "csv"
    if head.startswith("{") or head.startswith("["):
        data = json.load(open(path, encoding="utf-8-sig"))
        if isinstance(data, dict) and ("runs" in data or "$schema" in data and "sarif" in str(data.get("$schema", ""))):
            return "sarif"
        return "sarif" if isinstance(data, dict) and "runs" in data else "json"
    return "csv"


def parse_sarif(data):
    out = []
    for run in data.get("runs", []):
        # index rule metadata for cwe/name lookups
        rules = {}
        driver = run.get("tool", {}).get("driver", {})
        for r in driver.get("rules", []):
            rules[r.get("id")] = r
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            rule = rules.get(rid, {})
            name = rule.get("name") or rid
            # location
            fpath, line = "", None
            locs = res.get("locations") or []
            if locs:
                phys = locs[0].get("physicalLocation", {})
                fpath = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                line = (phys.get("region", {}) or {}).get("startLine")
            # severity: prefer security-severity (CVSS), else level
            sev = (res.get("properties", {}) or {}).get("security-severity")
            if sev is None:
                sev = (rule.get("properties", {}) or {}).get("security-severity")
            if sev is None:
                sev = res.get("level") or rule.get("defaultConfiguration", {}).get("level")
            # cwe: search rule tags/properties/relationships + ids
            tags = (rule.get("properties", {}) or {}).get("tags", []) or []
            cwe = extract_cwe(rid, name, " ".join(map(str, tags)),
                              json.dumps(rule.get("relationships", [])),
                              json.dumps(res.get("taxa", [])),
                              (rule.get("properties", {}) or {}).get("cwe"))
            out.append({"file": fpath, "line": line, "rule": name, "cwe": cwe,
                        "severity": norm_sev(sev)})
    return out


def parse_json(data):
    items = data if isinstance(data, list) else data.get("findings") or data.get("results") or []
    out = []
    for it in items:
        f = it.get("file") or it.get("path") or it.get("location") or ""
        line = it.get("line") or it.get("startLine") or it.get("lineNumber")
        rule = it.get("rule") or it.get("type") or it.get("name") or it.get("query") or it.get("category") or ""
        cwe = extract_cwe(it.get("cwe"), it.get("cweId"), rule)
        sev = it.get("severity") or it.get("level") or it.get("risk")
        out.append({"file": f, "line": _to_int(line), "rule": rule, "cwe": cwe,
                    "severity": norm_sev(sev)})
    return out


def _to_int(v):
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return None


def _pick_col(headers, candidates):
    low = {h.lower().strip(): h for h in headers}
    for c in candidates:              # exact match first
        if c in low:
            return low[c]
    for c in candidates:              # then substring (skip dest/target columns)
        for h in headers:
            hl = h.lower()
            if c in hl and "dest" not in hl and "target" not in hl:
                return h
    return None


def parse_csv(path, overrides):
    rows = list(csvmod.DictReader(open(path, newline="", encoding="utf-8-sig")))
    if not rows:
        return []
    headers = list(rows[0].keys())
    col = {
        "file": overrides.get("file") or _pick_col(headers, ["srcfilename", "filename", "file", "filepath", "path", "location", "file/artifact"]),
        "line": overrides.get("line") or _pick_col(headers, ["line", "startline", "linenumber", "location line"]),
        "rule": overrides.get("rule") or _pick_col(headers, ["query", "type", "rule", "ruleid", "checker", "name", "vulnerability", "issue type", "category name"]),
        "cwe": overrides.get("cwe") or _pick_col(headers, ["cwe", "cweid", "cwe id"]),
        "sev": overrides.get("severity") or _pick_col(headers, ["result severity", "severity", "risk", "priority"]),
    }
    sys.stderr.write(f"[csv] columns -> file={col['file']!r} line={col['line']!r} "
                     f"rule={col['rule']!r} cwe={col['cwe']!r} severity={col['sev']!r}\n")
    out = []
    for r in rows:
        f = (r.get(col["file"]) or "").strip() if col["file"] else ""
        rule = (r.get(col["rule"]) or "").strip() if col["rule"] else ""
        cwe = extract_cwe(r.get(col["cwe"]) if col["cwe"] else None, rule)
        sev = r.get(col["sev"]) if col["sev"] else None
        line = _to_int(r.get(col["line"])) if col["line"] else None
        out.append({"file": f, "line": line, "rule": rule, "cwe": cwe, "severity": norm_sev(sev)})
    return out


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def in_safe_range(basename, line, safe_ranges):
    if line is None:
        return False
    for s, e in safe_ranges.get(basename, []):
        if s <= line <= e:
            return True
    return False


def classify(findings, baseline, safe_ranges):
    have_lines = any(f["line"] is not None for f in findings)
    seen = set()
    for f in findings:
        f["basename"] = os.path.basename(f["file"] or "")
        f["lang"] = detect_lang(f["file"])
        f["module"] = map_module(f["file"], baseline["module_patterns"])
        cat, bucket = map_category(f["rule"], f["cwe"], baseline)
        f["category"] = cat
        f["bucket"] = bucket
        f["fp_safe"] = in_safe_range(f["basename"], f["line"], safe_ranges)
        key = (f["basename"], f["line"], _norm_rule(f["rule"]))
        f["duplicate"] = have_lines and key in seen
        if have_lines:
            seen.add(key)
        # final disposition
        if f["fp_safe"]:
            f["disp"] = "fp-control"
        elif bucket == "core" and f["module"] == cat:
            f["disp"] = "match"          # right vuln type, right module
        elif bucket == "core" and f["module"] == "__framework__":
            f["disp"] = "framework"
        elif bucket == "core":
            f["disp"] = "cross-file"     # right vuln type, different module
        else:
            f["disp"] = bucket           # data-exposure / hardening / noise / unmapped
    return have_lines


def score(findings, baseline):
    have_lines = any(f["line"] is not None for f in findings)
    cats = ["sqli", "command", "xss", "access", "crypto", "deser", "path", "ssrf"]
    langs = ["python", "javascript", "java"]

    # coverage: crediting findings = disp match (right type, right module, not FP)
    credit = defaultdict(list)
    for f in findings:
        if f["disp"] == "match":
            credit[(f["lang"], f["category"])].append(f)

    matrix = {}
    detected_cells = 0
    for lang in langs:
        for cat in cats:
            fs = credit.get((lang, cat), [])
            exp = len(baseline["expected"][lang][cat])
            if have_lines:
                distinct = len({(x["basename"], x["line"]) for x in fs})
            else:
                distinct = len(fs)  # best effort without lines
            status = "miss" if not fs else ("full" if distinct >= exp else "partial")
            if fs:
                detected_cells += 1
            matrix[(lang, cat)] = {"n": len(fs), "distinct": distinct, "exp": exp, "status": status}

    buckets = Counter(f["disp"] for f in findings)
    sev_hist = Counter(f["severity"] for f in findings)
    fp = [f for f in findings if f["disp"] == "fp-control"]
    dups = sum(1 for f in findings if f.get("duplicate"))

    # baseline severity histogram
    base_sev = Counter()
    for lang in langs:
        for cat in cats:
            for _id, sev, _cwe, _ep in baseline["expected"][lang][cat]:
                base_sev[sev] += 1
    base_total = sum(base_sev.values())

    return {
        "total": len(findings), "have_lines": have_lines, "matrix": matrix,
        "detected_cells": detected_cells, "cells": len(langs) * len(cats),
        "buckets": buckets, "sev_hist": sev_hist, "fp": fp, "dups": dups,
        "base_sev": base_sev, "base_total": base_total, "langs": langs, "cats": cats,
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
CAT_NAMES = {"sqli": "SQL Injection", "command": "Command Injection", "xss": "XSS",
             "access": "Broken Access Control", "crypto": "Cryptographic Failures",
             "deser": "Insecure Deserialization", "ssrf": "SSRF", "path": "Path Traversal"}


def _cell(m):
    if m["status"] == "miss":
        return "  --  "
    tag = "FULL" if m["status"] == "full" else "part"
    return f"{tag}({m['n']})"


def render(s, baseline, report_path):
    L = []
    p = L.append
    p(f"# Benchmark: {os.path.basename(report_path)} vs ground-truth ({baseline['project']})\n")
    p(f"Report findings: {s['total']}   |   Ground-truth planted (SAST): {s['base_total']}")
    if not s["have_lines"]:
        p("NOTE: report has no line numbers -> control-group false-positive detection "
          "and per-sink dedup are disabled; coverage is category-level only.")
    p("")

    # severity
    p("## Severity")
    p(f"{'':10}{'Critical':>9}{'High':>7}{'Medium':>8}{'Low':>6}{'Info':>6}   Total")
    row = "".join(f"{s['sev_hist'].get(k,0):>{w}}" for k, w in
                  zip(["Critical", "High", "Medium", "Low", "Info"], [19, 7, 8, 6, 6]))
    p(f"{'report':10}{row}   {s['total']}")
    brow = "".join(f"{s['base_sev'].get(k,0):>{w}}" for k, w in
                   zip(["Critical", "High", "Medium", "Low", "Info"], [19, 7, 8, 6, 6]))
    p(f"{'baseline':10}{brow}   {s['base_total']}")
    p("")

    # coverage matrix
    p("## Coverage matrix (planted vuln class detected in its module, per language)")
    p(f"{'category':22}{'python':>10}{'javascript':>12}{'java':>8}")
    for cat in s["cats"]:
        cells = "".join(f"{_cell(s['matrix'][(lang, cat)]):>{w}}"
                        for lang, w in zip(s["langs"], [10, 12, 8]))
        p(f"{CAT_NAMES[cat]:22}{cells}")
    p("")
    recall = 100.0 * s["detected_cells"] / s["cells"]
    p(f"Recall (category x language cells detected): {s['detected_cells']}/{s['cells']}  ({recall:.0f}%)")
    missed = [f"{CAT_NAMES[c]}/{lang}" for lang in s["langs"] for c in s["cats"]
              if s["matrix"][(lang, c)]["status"] == "miss"]
    if missed:
        p("Missed cells: " + ", ".join(missed))
    p("")

    # buckets
    p("## Finding disposition")
    order = ["match", "cross-file", "framework", "data-exposure", "hardening", "noise", "unmapped", "fp-control"]
    labels = {
        "match": "match (planted vuln, right module)",
        "cross-file": "cross-file (right vuln type, different module)",
        "framework": "framework/seed code (db, __init__, server)",
        "data-exposure": "data-exposure family (adjacent, not in baseline)",
        "hardening": "hardening/config (headers, TLS, CSRF)",
        "noise": "code-quality noise (resource, loop, error, privacy)",
        "unmapped": "unmapped (no CWE/rule match)",
        "fp-control": "FALSE POSITIVE on a SAFE control handler",
    }
    for b in order:
        if s["buckets"].get(b):
            p(f"  {s['buckets'][b]:>4}  {labels[b]}")
    if s["dups"]:
        p(f"  {s['dups']:>4}  (of which duplicate source->sink paths)")
    p("")

    # precision / control group
    p("## Precision (control group)")
    if not s["have_lines"]:
        p("  n/a - report has no line numbers, so findings cannot be located "
          "inside the known-safe handlers. Re-export with line detail to measure.")
    elif s["fp"]:
        p(f"  {len(s['fp'])} false positive(s) on SAFE reference handlers:")
        for f in s["fp"]:
            p(f"    {f['basename']}:{f['line']}  [{f['severity']}]  {f['rule']}")
    else:
        p("  0 false positives on the safe control handlers. Clean.")
    p("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Score a SAST report against the lab's ground truth.")
    ap.add_argument("report", help="path to the vendor report (SARIF/CSV/JSON)")
    ap.add_argument("--format", default="auto", choices=["auto", "sarif", "csv", "json"])
    ap.add_argument("--baseline", default=os.path.join(HERE, "baseline.json"))
    ap.add_argument("--md", help="write the markdown report to this path")
    ap.add_argument("--json", help="write machine-readable results to this path")
    for c in ["file", "line", "rule", "cwe", "severity"]:
        ap.add_argument(f"--col-{c}", help=f"override the CSV column used for {c}")
    args = ap.parse_args()

    baseline = json.load(open(args.baseline, encoding="utf-8"))
    overrides = {c: getattr(args, f"col_{c}") for c in ["file", "line", "rule", "cwe", "severity"]}
    findings = load_report(args.report, args.format, overrides)
    if not findings:
        raise SystemExit("no findings parsed from report")
    safe_ranges = scan_safe_ranges()
    classify(findings, baseline, safe_ranges)
    s = score(findings, baseline)
    text = render(s, baseline, args.report)
    print(text)

    if args.md:
        open(args.md, "w", encoding="utf-8").write(text)
    if args.json:
        out = {
            "report": os.path.basename(args.report),
            "total": s["total"], "have_lines": s["have_lines"],
            "recall_cells": f"{s['detected_cells']}/{s['cells']}",
            "severity": dict(s["sev_hist"]), "baseline_severity": dict(s["base_sev"]),
            "buckets": dict(s["buckets"]), "duplicates": s["dups"],
            "control_false_positives": [
                {"file": f["basename"], "line": f["line"], "rule": f["rule"], "severity": f["severity"]}
                for f in s["fp"]
            ],
            "coverage": {f"{lang}/{cat}": s["matrix"][(lang, cat)]
                         for lang in s["langs"] for cat in s["cats"]},
        }
        json.dump(out, open(args.json, "w", encoding="utf-8"), indent=2)


if __name__ == "__main__":
    main()
