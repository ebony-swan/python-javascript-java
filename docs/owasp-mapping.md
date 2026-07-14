# OWASP Top 10 — 2021 ↔ 2025 Cross-Reference

This lab is organized around the well-established **OWASP Top 10:2021**
categories, but every vulnerability is also tagged with its **OWASP Top 10:2025**
home so the material stays current. This page shows the full mapping.

## The two editions side by side

| 2021 | 2025 | Notes on the shift |
|------|------|--------------------|
| **A01:2021 – Broken Access Control** | **A01:2025 – Broken Access Control** | Still #1. **SSRF (was A10:2021) is folded in here.** |
| **A02:2021 – Cryptographic Failures** | **A04:2025 – Cryptographic Failures** | Same theme, moved down. |
| **A03:2021 – Injection** | **A05:2025 – Injection** | Same theme (incl. XSS), moved down. |
| **A04:2021 – Insecure Design** | **A06:2025 – Insecure Design** | Renumbered. |
| **A05:2021 – Security Misconfiguration** | **A02:2025 – Security Misconfiguration** | Rose to #2. |
| **A06:2021 – Vulnerable & Outdated Components** | **A03:2025 – Software Supply Chain Failures** | Broadened & renamed; new #3 with the highest incidence rate. |
| **A07:2021 – Identification & Authentication Failures** | **A07:2025 – Authentication Failures** | Slight rename, same slot. |
| **A08:2021 – Software & Data Integrity Failures** | **A08:2025 – Software & Data Integrity Failures** | Stable (includes insecure deserialization). |
| **A09:2021 – Security Logging & Monitoring Failures** | **A09:2025 – Security Logging & Alerting Failures** | Slight rename, same slot. |
| **A10:2021 – Server-Side Request Forgery (SSRF)** | *(folded into A01:2025)* | No longer standalone. |
| *(new)* | **A10:2025 – Mishandling of Exceptional Conditions** | Brand-new category (improper error handling, failing open, logic errors). |

**Two new categories in 2025:** Software Supply Chain Failures (A03) and
Mishandling of Exceptional Conditions (A10). **One consolidation:** SSRF merged
into Broken Access Control.

## How this lab's categories map

| Lab category | Primary CWE(s) | OWASP 2021 | OWASP 2025 |
|--------------|----------------|------------|------------|
| SQL Injection | CWE-89 | A03 Injection | A05 Injection |
| Command Injection | CWE-78 | A03 Injection | A05 Injection |
| Cross-Site Scripting (XSS) | CWE-79 (+ CWE-1336 SSTI) | A03 Injection | A05 Injection |
| Broken Access Control / IDOR | CWE-639, 862, 915, 602 | A01 Broken Access Control | A01 Broken Access Control |
| Cryptographic Failures | CWE-327, 916, 798, 338 | A02 Cryptographic Failures | A04 Cryptographic Failures |
| Insecure Deserialization | CWE-502, 95, 1321 | A08 Software & Data Integrity Failures | A08 Software & Data Integrity Failures |
| Server-Side Request Forgery | CWE-918 | A10 SSRF | A01 Broken Access Control (folded) |
| Path Traversal | CWE-22 | A01 Broken Access Control | A01 Broken Access Control / A05 Injection-adjacent |

## What this lab intentionally does **not** cover

The "core code-level" scope focuses on flaws that are demonstrable as
self-contained, exploitable code. Several Top 10 categories are primarily
*design*, *process*, or *configuration* concerns and are better shown as
architecture or pipeline exercises than as a vulnerable endpoint:

- **A03:2025 Software Supply Chain Failures / A06:2021 Vulnerable Components** —
  partially represented by the deliberately-outdated npm dependencies
  (`node-serialize`, `lodash`) that back the deserialization demos, but not given
  a dedicated code category.
- **A06:2025 Insecure Design**, **A02:2025 Security Misconfiguration**,
  **A09:2025 Logging & Alerting Failures**, **A10:2025 Mishandling of Exceptional
  Conditions** — out of scope here.

Sources: OWASP Top 10:2025 (owasp.org/Top10/2025) and OWASP Top 10:2021
(owasp.org/Top10/).
