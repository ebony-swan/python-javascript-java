# 04 — Insecure Deserialization / Software & Data Integrity Failures

**OWASP 2021:** A08 Software and Data Integrity Failures → **OWASP 2025:** A08 (same)
**Primary CWEs:** CWE-502 (deserialization of untrusted data), CWE-95 (eval injection), CWE-1321 (prototype pollution)

Turning attacker-controlled bytes back into live objects/code is a fast path to
remote code execution. Each language demonstrates its own idiomatic sink, so the
endpoints differ by app.

Endpoints: `/deserialization`.

| # | Python | JavaScript | Java | CWE | Exploitation | Prev. G | Prev. L |
|---|--------|------------|------|-----|--------------|:-------:|:-------:|
| 1 (native) | `POST /pickle` `pickle.loads` | `POST /native` `node-serialize` | `POST /native` `ObjectInputStream` | 502 | **HIGH** (RCE) | MED/RARE | HIGH |
| 2 (config) | `POST /yaml` `yaml.unsafe_load` | `POST /eval` `eval('('+d+')')` | `POST /yaml` SnakeYAML `load` | 502/95 | **HIGH** | LOW | MED–HIGH |
| 3 (integrity) | `POST /eval` `eval()` | `POST /merge` prototype pollution | `POST /xml` `XMLDecoder` | 95/1321/502 | **CRITICAL / HIGH** | LOW–MED | MEDIUM |

- **P1 — native deserialization.** `pickle.loads`, `node-serialize.unserialize`,
  and `ObjectInputStream.readObject` all execute embedded logic on untrusted
  input (verified in Python: a `__reduce__` payload ran `os.system('id')`).
  Exploitation is **HIGH** — deterministic RCE — though it usually needs a known
  gadget/payload. *Prevalence:* **RARE–MEDIUM** in greenfield (JSON-first APIs
  avoid native serialization), but **HIGH** in ~10-yr code that serialized HTTP
  sessions, used Java RMI, or cached objects with pickle. This is the archetypal
  "legacy tech-debt" RCE.
- **P2 — unsafe config formats.** `yaml.unsafe_load` builds arbitrary Python
  objects (`!!python/object/apply` → RCE); JS `eval('(' + data + ')')` executes
  the "config" as code (CWE-95); SnakeYAML's `load` instantiates declared types
  (SnakeYAML 2.x blocks the classic `ScriptEngine` gadget but the pattern is
  still unsafe). *Prevalence:* **LOW** greenfield (PyYAML has defaulted to safe
  loading for years; `eval`-parsing is a textbook red flag), **MED–HIGH** legacy.
- **P3 — integrity-specific.** Python `eval()` of a user "formula" is
  **CRITICAL** (the string runs as Python). JS **prototype pollution** via a
  recursive merge of attacker JSON (`{"__proto__":{"isAdmin":true}}`) corrupts
  `Object.prototype` app-wide (CWE-1321) — very much a *modern* JS bug, so
  greenfield prevalence is **MEDIUM** here. Java `XMLDecoder.readObject` on user
  XML is a classic RCE.

**Fix:** never deserialize untrusted data with a code-capable deserializer. Use
data-only parsers (`json.loads`, `JSON.parse` into a plain object, `yaml.safe_load`,
Jackson to a fixed DTO); for JS merges, block `__proto__`/`constructor`/`prototype`
keys or use a null-prototype object / `Map`. See each app's `…safe` handler.
