# 04 — Insecure Deserialization / Software & Data Integrity Failures

**OWASP 2021:** A08 Software and Data Integrity Failures → **OWASP 2025:** A08 (same)
**Primary CWEs:** CWE-502 (deserialization of untrusted data), CWE-95 (eval injection), CWE-1321 (prototype pollution), CWE-94 (code injection), CWE-345 (insufficient verification of data authenticity)

Turning attacker-controlled bytes back into live objects/code is a fast path to
remote code execution.

Endpoints: `/deserialization`. This is the category where the five apps diverge
most — each language demonstrates its own idiomatic sink, so the routes are
listed per language rather than sharing one path:

| Language | P1 — native | P2 — config-as-code | P3 — integrity |
|----------|-------------|---------------------|----------------|
| **Python** | `POST /pickle` `pickle.loads` | `POST /yaml` `yaml.unsafe_load` | `POST /eval` `eval()` |
| **JavaScript** | `POST /native` `node-serialize` | `POST /eval` `eval('('+d+')')` | `POST /merge` prototype pollution |
| **Java** | `POST /native` `ObjectInputStream` | `POST /yaml` SnakeYAML `load` | `POST /xml` `XMLDecoder` |
| **C#** | `POST /native` Json.NET `TypeNameHandling.All` | `POST /yaml` YamlDotNet → side-effecting type | `POST /xml` `XmlSerializer`, type from request |
| **Go** | `POST /native` `encoding/gob` | `POST /template` `text/template` | `POST /decode` unsigned base64-JSON token |

| # | CWE | Exploitation | Prev. G | Prev. L |
|---|-----|--------------|:-------:|:-------:|
| 1 (native) | 502 | **HIGH** (RCE) — *Go: MEDIUM, no RCE* | MED/RARE | HIGH |
| 2 (config) | 502/95, Go 94 | **HIGH** | LOW | MED–HIGH |
| 3 (integrity) | 95/1321/502, Go 345 | **CRITICAL / HIGH** | LOW–MED | MEDIUM |

- **P1 — native deserialization.** `pickle.loads`, `node-serialize.unserialize`,
  and `ObjectInputStream.readObject` all execute embedded logic on untrusted
  input (verified in Python: a `__reduce__` payload ran `os.system('id')`).
  **C#** joins them via Json.NET `TypeNameHandling.All`: the attacker's `$type`
  chooses which CLR type is instantiated and its setters run during load — the
  classic .NET sink, and deterministic RCE the moment any side-effecting gadget
  type is loadable (this app ships one). Exploitation is **HIGH** — deterministic
  RCE — though it usually needs a known gadget/payload. *Prevalence:*
  **RARE–MEDIUM** in greenfield (JSON-first APIs avoid native serialization),
  but **HIGH** in ~10-yr code that serialized HTTP sessions, used Java RMI,
  cached objects with pickle, or copy-pasted `TypeNameHandling.Auto` out of an
  old tutorial. This is the archetypal "legacy tech-debt" RCE.
  **Go is the honest exception:** `encoding/gob` does **not** invoke methods or
  constructors on decode, so there is no equivalent RCE. The real harm is **type
  confusion** — the attacker picks which registered concrete type is
  instantiated, smuggling a privileged internal type into a field meant for a
  benign one — plus resource exhaustion from a stream declaring huge
  slice/map lengths. Impactful, but rated **MEDIUM**, not RCE.
- **P2 — unsafe config formats.** `yaml.unsafe_load` builds arbitrary Python
  objects (`!!python/object/apply` → RCE); JS `eval('(' + data + ')')` executes
  the "config" as code (CWE-95); SnakeYAML's `load` instantiates declared types
  (SnakeYAML 2.x blocks the classic `ScriptEngine` gadget but the pattern is
  still unsafe). **C#** uses YamlDotNet, which — unlike PyYAML/SnakeYAML — does
  *not* auto-instantiate arbitrary tagged types; the flaw is deserializing
  untrusted YAML into a rich config object whose property setter runs a command,
  so it needs the app to supply the dangerous type — *exploitation* is therefore
  rated **MEDIUM** even though the impact, once reached, is still RCE.
  **Go** substitutes `text/template` compiled from request input (CWE-94/1336):
  a template can read any exported field (`{{.Secret}}`) and call any method on
  its context — here `{{.ReadFile "data/secret.txt"}}` gives arbitrary local file
  read in one curl. Its ceiling depends on what the context exposes, so no RCE
  here, but real config-template contexts routinely expose helpers.
  *Prevalence:* **LOW** greenfield (PyYAML has defaulted to safe loading for
  years; `eval`-parsing is a textbook red flag), **MED–HIGH** legacy.
- **P3 — integrity-specific.** Python `eval()` of a user "formula" is
  **CRITICAL** (the string runs as Python). JS **prototype pollution** via a
  recursive merge of attacker JSON (`{"__proto__":{"isAdmin":true}}`) corrupts
  `Object.prototype` app-wide (CWE-1321) — very much a *modern* JS bug, so
  greenfield prevalence is **MEDIUM** here. Java `XMLDecoder.readObject` on user
  XML is a classic RCE. **C#** resolves the `XmlSerializer`'s *target type* from
  the request, so the caller supplies both the type name and the XML — an
  obvious review smell in greenfield, but common in old SOAP/plugin/importer
  code that picks a type by name from a header or query param.
  **Go** demonstrates the purest form of the category: a base64-JSON token whose
  `role` field is decoded and trusted with **no signature or HMAC verification**
  (CWE-345), so anyone forges `{"role":"admin"}`. No memory-unsafety and no
  gadget chain — just believing deserialized data. Exploitation is **HIGH**
  (pre-auth, deterministic, zero tooling) even though the severity band is
  Medium, and hand-rolled signed-cookie schemes make it **HIGH** in legacy code.

**Fix:** never deserialize untrusted data with a code-capable deserializer. Use
data-only parsers (`json.loads`, `JSON.parse` into a plain object, `yaml.safe_load`,
Jackson to a fixed DTO, `System.Text.Json` with no type embedding); for JS merges,
block `__proto__`/`constructor`/`prototype` keys or use a null-prototype object /
`Map`. In **C#**, never enable `TypeNameHandling` on untrusted input, bind XML to
a *fixed* type rather than one named by the caller, and deserialize YAML into an
inert DTO with no side-effecting setters. In **Go**, don't `gob`-decode from
client-reachable channels, use `html/template` (never `text/template`) for
anything HTML and never compile a template from request input, and **verify a MAC
before trusting any token** — the fix for P3 is authentication, not a better
parser. See each app's `…safe` handler.
