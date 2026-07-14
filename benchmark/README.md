# SAST Benchmark Engine

Drop in **any** SAST vendor's report and score it against this project's
ground-truth — the deliberately-planted vulnerabilities and the known-safe
"control" handlers. Answers: *how much did the scanner actually find, what did it
miss, and how noisy / false-positive-prone was it?*

Zero dependencies (Python 3 standard library only).

```bash
python3 benchmark/compare.py <report>                    # auto-detect format
python3 benchmark/compare.py report.sarif
python3 benchmark/compare.py report.csv --md out.md --json out.json
```

## Supported report formats (auto-detected)

| Format | Notes |
|--------|-------|
| **SARIF** (`.sarif`, SARIF JSON) | The portable standard most tools can export. Reads CWE from rule `tags`/`properties`, severity from `security-severity` (CVSS) or `level`. |
| **CSV** | Columns auto-detected (file, line, rule/type, CWE, severity). Override with `--col-file`, `--col-line`, `--col-rule`, `--col-cwe`, `--col-severity`. |
| **JSON** | A generic array of `{file, line, rule/type, cwe, severity}` objects. |

If your CSV columns aren't picked up automatically:

```bash
python3 benchmark/compare.py report.csv \
  --col-file "Source File" --col-rule "Category" --col-cwe "CWE ID" --col-severity "Risk"
```

## What it reports

- **Coverage matrix** — for each planted vulnerability class × language, was it
  detected *in the right module*? (`FULL` / `part(n)` / `--`).
- **Recall** — planted category×language cells detected out of 24.
- **Precision (control group)** — false positives landing on the **safe
  reference handlers**. These are the `*-safe` endpoints that a precise tool must
  *not* flag; the engine locates them in source automatically. *Requires line
  numbers in the report* — reports without lines (some exports) skip this.
- **Finding disposition** — every report finding bucketed as:
  `match` (planted vuln, right module) · `cross-file` (right vuln type, wrong
  module) · `framework/seed` (db/init/server code) · `data-exposure` (adjacent
  sensitive-data rules, not in the baseline) · `hardening` (headers/TLS/CSRF) ·
  `noise` (resource/loop/error/privacy) · `unmapped` · `fp-control`.
- **Severity** — the report's histogram next to the CVSS ground-truth baseline.
- **Inflation** — duplicate source→sink paths (when lines are present).

## How scoring works

1. **Normalize** each finding to `{file, line, rule, cwe, severity}`.
2. **Category** is inferred from the rule/type name first (vendor names are
   usually precise), then the CWE as a fallback.
3. **Language & module** come from the file path.
4. A finding is a **match** when its vuln class equals the module it sits in and
   it isn't on a safe handler; if it's on a safe handler it's a **false
   positive**; other buckets capture framework/data-exposure/hardening/noise.
5. **Coverage** and **recall** are computed from matches; **precision** from the
   safe-handler false positives.

Comparisons should be read **by CWE/vuln-class, not by raw totals** — different
tools use very different rule taxonomies and severity models, so raw counts
(e.g. 81 vs 87 vs 165) are not like-for-like.

## The answer key: `baseline.json`

- `expected` — the planted vulnerabilities, per language × category, each with a
  representative CVSS severity, CWE, and endpoint. Edit this if you add or change
  vulnerabilities in the lab.
- `categories` — CWE sets per OWASP category (with 2021↔2025 mapping).
- `module_patterns`, `rule_keywords`, `data_exposure_*`, `hardening_rules`,
  `noise_rules` — how findings are routed to a category or bucket. Add your
  scanner's rule names here if something lands in `unmapped`.

The safe-handler line ranges are **not** hard-coded — they are detected from the
source at runtime (handlers whose route or function name contains `safe`), so
they stay correct as the code changes.

## Notes

- This engine and its baseline are **vendor-neutral**: they name no scanner and
  work against any SAST report you provide.
- Authorization flaws (IDOR, missing function-level authz, mass assignment) have
  no tainted-data sink, so most SAST tools miss them — expect the
  `Broken Access Control` row to be weak regardless of vendor; cover it with
  DAST/IAST or manual review.
- A report without line numbers still scores coverage/recall, but its
  control-group precision can't be measured (findings can't be located inside
  the safe handlers). Re-export with line detail to get that.
