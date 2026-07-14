"""Insecure Deserialization / Software & Data Integrity Failures.

OWASP 2021 A08 Software and Data Integrity Failures  ->  OWASP 2025 A08.

This module mirrors the comment/annotation format of the reference SQL-injection
module: each permutation carries a standard header describing the flaw, its CWE,
an exploitation-likelihood rating, prevalence today, an example payload, and the
corresponding safe pattern. Every dangerous sink is marked ``VULNERABLE:`` and
the file ends with ONE clearly-labelled SAFE reference handler.

All handlers accept the named field from a JSON body, a form field, or a query
arg, so any of these work:

    curl -X POST /deserialization/pickle -d 'data=<base64>'
    curl -X POST /deserialization/pickle -H 'Content-Type: application/json' -d '{"data":"<base64>"}'
"""
import base64
import json
import pickle

import yaml
from flask import Blueprint, jsonify, request

bp = Blueprint("deserialization", __name__, url_prefix="/deserialization")


def _field(name: str, default: str = "") -> str:
    """Pull a field from a JSON body, form body, or query string (in that order)."""
    body = request.get_json(silent=True) or {}
    if name in body:
        return body[name]
    return request.form.get(name, request.args.get(name, default))


# =============================================================================
# PERMUTATION 1 — Native pickle deserialization of attacker-controlled bytes
# OWASP 2021 A08 Software and Data Integrity Failures  ->  OWASP 2025 A08 Software and Data Integrity Failures
# CWE-502: Deserialization of Untrusted Data
# EXPLOITATION LIKELIHOOD: HIGH — pre-auth, deterministic RCE. pickle.loads runs
#   the object's __reduce__ during unpickling, so a self-contained payload (no
#   external gadget chain needed) executes arbitrary code; only caveat is the
#   attacker must craft/encode the pickle, which is a trivial 5-line script.
# PREVALENCE TODAY: greenfield MEDIUM (web frameworks avoid pickle, but the
#   Python ML/data-science stack still pickles models, joblib artifacts, Celery/
#   Redis task payloads and caches by default) | legacy/10yr tech-debt HIGH
#   (pickle-backed sessions, caches and RPC are everywhere in old Python code).
# EXAMPLE — build a payload whose __reduce__ shells out, then POST it:
#   python -c "import pickle,base64,subprocess as s;\
#   class E:\
#     def __reduce__(self): return (s.check_output, (['id'],))\
#   print(base64.b64encode(pickle.dumps(E())).decode())"
#   curl -X POST localhost:5000/deserialization/pickle -d "data=<paste base64>"
#   -> {"result": "b'uid=0(root) ...\\n'", ...}
# FIX: never unpickle untrusted input; use a data-only format (json.loads) — see
#   the SAFE reference handler below.
# =============================================================================
@bp.post("/pickle")
def pickle_load():
    data = _field("data")
    raw = base64.b64decode(data)
    # VULNERABLE: pickle.loads executes __reduce__ on attacker-controlled bytes -> RCE.
    obj = pickle.loads(raw)
    return jsonify({"deserialized_type": type(obj).__name__, "result": repr(obj)})


# =============================================================================
# PERMUTATION 2 — Unsafe config-format deserialization (yaml.unsafe_load)
# OWASP 2021 A08 Software and Data Integrity Failures  ->  OWASP 2025 A08 Software and Data Integrity Failures
# CWE-502: Deserialization of Untrusted Data
# EXPLOITATION LIKELIHOOD: HIGH — deterministic RCE with a one-line payload.
#   yaml.unsafe_load honours the !!python/object/apply tag, which constructs
#   arbitrary objects and CALLS arbitrary functions during parsing; no gadget
#   hunting required because the YAML names the callable directly.
# PREVALENCE TODAY: greenfield LOW (PyYAML has defaulted to safe loading since
#   5.1 and yaml.load without a Loader now warns; you must explicitly reach for
#   unsafe_load/Loader=UnsafeLoader) | legacy/10yr tech-debt MEDIUM-HIGH (heaps
#   of pre-5.1 code call bare yaml.load(), which used to be unsafe by default).
# EXAMPLE:
#   curl -X POST localhost:5000/deserialization/yaml \
#     --data-urlencode 'data=!!python/object/apply:subprocess.check_output [["id"]]'
#   -> {"result": "b'uid=0(root) ...\\n'", ...}
# FIX: yaml.safe_load(...) (SafeLoader) — see the SAFE reference handler below.
# =============================================================================
@bp.post("/yaml")
def yaml_load():
    data = _field("data")
    # VULNERABLE: unsafe_load constructs/invokes arbitrary Python objects via YAML tags -> RCE.
    obj = yaml.unsafe_load(data)
    return jsonify({"deserialized_type": type(obj).__name__, "result": repr(obj)})


# =============================================================================
# PERMUTATION 3 — Integrity failure via eval() of a user "formula"/config value
# OWASP 2021 A08 Software and Data Integrity Failures  ->  OWASP 2025 A08 Software and Data Integrity Failures
# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
# EXPLOITATION LIKELIHOOD: CRITICAL — eval() runs the string as Python, so a
#   plain expression like __import__('os').popen('id').read() yields immediate,
#   reliable RCE with zero tooling and no gadget; trivially discovered and abused.
# PREVALENCE TODAY: greenfield LOW (eval on request data is a textbook red flag
#   that linters/SAST/code-review catch, and safe expression libs like ast or
#   simpleeval exist) | legacy/10yr tech-debt MEDIUM (hand-rolled calculators,
#   rules engines and "dynamic config" that eval() a stored formula still lurk).
# EXAMPLE:
#   curl -X POST localhost:5000/deserialization/eval \
#     --data-urlencode "expr=__import__('os').popen('id').read()"
#   -> {"result": "'uid=0(root) ...\\n'", "expr": "__import__('os')..."}
# FIX: parse data, don't execute it — ast.literal_eval for literals, or a
#   sandboxed expression evaluator; see the SAFE reference handler below.
# =============================================================================
@bp.post("/eval")
def eval_formula():
    expr = _field("expr")
    # VULNERABLE: eval() executes attacker-supplied text as Python code -> RCE.
    result = eval(expr)
    return jsonify({"expr": expr, "result": repr(result)})


# =============================================================================
# SAFE REFERENCE — data-only parsing, no code execution.
# json.loads / yaml.safe_load construct ONLY primitive types (dict/list/str/
# int/float/bool/None); the !!python/object and __reduce__ machinery is never
# reachable, so a hostile payload can at worst produce a benign parse error.
# Shown so the vulnerable/safe pair can be diffed by SAST tools and learners.
# =============================================================================
@bp.post("/safe")
def safe_load():
    data = _field("data")
    try:
        # SAFE: json.loads yields plain data, never executes anything.
        parsed = json.loads(data)
    except (ValueError, TypeError) as exc:
        # SAFE: yaml.safe_load refuses python/object tags -> ConstructorError, not RCE.
        try:
            parsed = yaml.safe_load(data)
        except yaml.YAMLError as yexc:
            return jsonify({"error": f"{exc}; {yexc}"}), 400
    return jsonify({"parsed_type": type(parsed).__name__, "parsed": parsed})
