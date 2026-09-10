"""Server-Side Request Forgery (SSRF) — OWASP 2021 A10  ->  OWASP 2025 A01.

SSRF is a *trust-boundary* bug: the server is tricked into making an outbound
request to a location the attacker chooses. Unlike SQL/command injection, no
framework, ORM, or HTTP client fixes it for you — ``requests.get(url)`` will
cheerfully connect to ``169.254.169.254`` (the cloud metadata service),
``127.0.0.1``, or any RFC-1918 host, and there is no "safe-by-default" URL
fetcher that blocks internal ranges. The defense is application logic that must
be written (and reviewed) by hand.

The comment/annotation format here mirrors the reference module
``app/vulns/injection_sql.py``: each permutation carries a standard header with
its CWE, an exploitation-likelihood rating, a greenfield-vs-legacy prevalence
contrast, an example request, and the corresponding safe pattern. The dangerous
sink of each handler is marked with an inline ``VULNERABLE:`` comment.
"""
import ipaddress
import socket
import urllib.parse

import requests
from flask import Blueprint, request, jsonify

bp = Blueprint("ssrf", __name__, url_prefix="/ssrf")


# =============================================================================
# PERMUTATION 1 — Direct fetch of a user-supplied URL (no allow-list)
# OWASP 2021 A10 Server-Side Request Forgery  ->  folded into OWASP 2025 A01 Broken Access Control
# CWE-918: Server-Side Request Forgery (SSRF)
# EXPLOITATION LIKELIHOOD: HIGH — one GET param, pre-auth, deterministic, zero
#   tooling. The server connects wherever the attacker points it and hands back
#   the response body, so it reaches internal-only services (Redis/Elastic/admin
#   panels) and reads AWS/GCP/Azure metadata (169.254.169.254) to steal IAM creds.
# PREVALENCE TODAY: greenfield MEDIUM (URL-fetch features — link/image previews,
#   "import from URL", avatar proxies, SSO/OIDC discovery — are everywhere and no
#   library blocks internal targets by default; returning the raw body is a smell
#   review/SAST increasingly catch) | legacy/10yr tech-debt HIGH (old proxies,
#   RSS/feed readers, and integration fetchers pull arbitrary URLs with no egress
#   controls, on instances whose metadata endpoint is wide open).
# EXAMPLE:
#   curl "http://127.0.0.1:5000/ssrf/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
#   curl "http://127.0.0.1:5000/ssrf/fetch?url=http://127.0.0.1:6379/"   (internal port)
# FIX: allow-list scheme+host, resolve DNS and reject private/link-local IPs,
#   disable redirects, block the metadata IP (see /ssrf/fetch-safe).
# =============================================================================
@bp.get("/fetch")
def fetch():
    url = request.args.get("url", "")
    # VULNERABLE: server issues a request to a fully attacker-controlled URL.
    try:
        resp = requests.get(url, timeout=3, allow_redirects=True)
    except Exception as exc:  # network/DNS/timeout errors — echo the target back
        return jsonify({"url": url, "error": str(exc)}), 502
    return jsonify(
        {
            "url": url,
            "final_url": resp.url,          # reveals where redirects landed
            "status": resp.status_code,
            "snippet": resp.text[:500],
        }
    )


# =============================================================================
# PERMUTATION 2 — Blind/internal SSRF via a user-supplied webhook/callback URL
# OWASP 2021 A10 Server-Side Request Forgery  ->  folded into OWASP 2025 A01 Broken Access Control
# CWE-918: Server-Side Request Forgery (SSRF)
# EXPLOITATION LIKELIHOOD: MEDIUM — the response is not (fully) returned to the
#   caller, so it is "blind": no direct body exfil. Still lets an attacker port-
#   scan the internal network (timing/status oracles), invoke GET-triggered
#   internal actions, and hit http://169.254.169.254/latest/meta-data/ for
#   credential theft where any status/latency detail leaks or an OOB channel exists.
# PREVALENCE TODAY: greenfield HIGH (outbound webhooks / callback URLs are a
#   flagship modern-SaaS feature — notifications, CI/CD, payment callbacks — and
#   the user-supplied destination is almost never validated against internal
#   ranges or placed behind an egress proxy) | legacy/10yr tech-debt MEDIUM (older
#   monoliths shipped fewer user-configurable callbacks, but "ping this URL"
#   notifiers exist and never had egress controls either).
# EXAMPLE:
#   curl -X POST -H 'Content-Type: application/json' \
#     -d '{"url":"http://169.254.169.254/latest/meta-data/"}' \
#     http://127.0.0.1:5000/ssrf/webhook
#   curl -X POST -H 'Content-Type: application/json' \
#     -d '{"callback":"http://127.0.0.1:8080/admin/shutdown"}' http://127.0.0.1:5000/ssrf/webhook
# FIX: validate the callback host against an egress allow-list, deny RFC-1918 /
#   link-local after DNS resolution, and route outbound webhooks through a proxy
#   that cannot reach the metadata service (see /ssrf/fetch-safe for the pattern).
# =============================================================================
@bp.post("/webhook")
def webhook():
    data = request.get_json(silent=True)
    if data is None:
        data = request.form.to_dict()
    data = data or {}
    url = data.get("url") or data.get("callback", "")
    # VULNERABLE: server "delivers" to a user-supplied callback with no target
    # validation — a classic blind/internal SSRF primitive.
    try:
        resp = requests.get(url, timeout=3, allow_redirects=True)
    except Exception as exc:
        return jsonify({"webhook": url, "delivered": False, "error": str(exc)}), 502
    # A real blind webhook would discard the response; we surface a little detail
    # so the demo is observable (and to show how even status/length leaks help).
    return jsonify(
        {
            "webhook": url,
            "delivered": True,
            "status": resp.status_code,
            "response_length": len(resp.content),
            "snippet": resp.text[:200],
        }
    )


# =============================================================================
# PERMUTATION 3 — SSRF behind a NAIVE, bypassable substring blocklist
# OWASP 2021 A10 Server-Side Request Forgery  ->  folded into OWASP 2025 A01 Broken Access Control
# CWE-918: Server-Side Request Forgery (SSRF)
# EXPLOITATION LIKELIHOOD: HIGH — the only defense is a substring check for
#   'localhost'/'127.0.0.1', which is trivially bypassed by well-known one-liners:
#   decimal/octal/hex IPs, alternate loopback spellings, IPv6, DNS names that
#   resolve to loopback, or an external URL that 302-redirects internally.
#   Deterministic, pre-auth, no tooling beyond knowing one encoding trick.
# PREVALENCE TODAY: greenfield MEDIUM (teams that "handle SSRF" usually reach for
#   a denylist/regex — the canonical incomplete fix — instead of resolve-then-
#   check-IP; the naive substring block is a very common first attempt) |
#   legacy/10yr tech-debt HIGH (hand-rolled string checks against 'localhost' /
#   '127.0.0.1' are the textbook legacy "mitigation" and stay in production).
# EXAMPLE:
#   curl "http://127.0.0.1:5000/ssrf/preview?url=http://127.0.0.1/"        -> blocked
#   curl "http://127.0.0.1:5000/ssrf/preview?url=http://2130706433/"       -> 127.0.0.1 as decimal
#   curl "http://127.0.0.1:5000/ssrf/preview?url=http://0177.0.0.1/"       -> 127.0.0.1 in octal
#   curl "http://127.0.0.1:5000/ssrf/preview?url=http://127.0.0.1.nip.io/" -> DNS resolves to loopback
#   curl "http://127.0.0.1:5000/ssrf/preview?url=http://[::1]/"            -> IPv6 loopback
#   curl "http://127.0.0.1:5000/ssrf/preview?url=http://evil.example/r"    -> 302 -> http://127.0.0.1/
# FIX: never denylist by substring; parse the URL, resolve the host to its IP(s),
#   allow-list and reject private/link-local ranges, and disable redirects
#   (see /ssrf/fetch-safe).
# =============================================================================
@bp.get("/preview")
def preview():
    url = request.args.get("url", "")
    lowered = url.lower()
    # NAIVE BLOCKLIST: substring match only — does not decode IPs, resolve DNS,
    # cover IPv6, or account for redirects. Bypassable a dozen ways (see EXAMPLE).
    if "localhost" in lowered or "127.0.0.1" in lowered:
        return jsonify(
            {
                "url": url,
                "blocked": True,
                "reason": "blocklist matched 'localhost'/'127.0.0.1' substring",
            }
        ), 403
    # VULNERABLE: everything that slips past the substring check is fetched.
    try:
        resp = requests.get(url, timeout=3, allow_redirects=True)
    except Exception as exc:
        return jsonify({"url": url, "error": str(exc)}), 502
    return jsonify(
        {
            "url": url,
            "final_url": resp.url,          # shows redirect-based bypass landing
            "status": resp.status_code,
            "snippet": resp.text[:500],
        }
    )


# =============================================================================
# SAFE REFERENCE — scheme+host allow-list, resolve-then-check-IP, no redirects.
# Shown so the vulnerable/safe pair can be diffed by SAST tools and learners.
# Enforces the four defenses the vulnerable handlers skip:
#   1. only http/https schemes (blocks file://, gopher://, etc.),
#   2. host must be on an explicit allow-list (not a denylist),
#   3. EVERY resolved IP is rejected if private/loopback/link-local/reserved,
#      which also blocks the 169.254.169.254 metadata service and DNS tricks,
#   4. redirects disabled, so a 302 -> internal cannot bypass the checks.
# =============================================================================
_ALLOWED_SCHEMES = {"http", "https"}
_ALLOWED_HOSTS = {"example.com", "www.example.com"}


def _ip_is_blocked(ip_str):
    ip = ipaddress.ip_address(ip_str)
    # Covers 127.0.0.0/8 (loopback), 10/8 + 172.16/12 + 192.168/16 (private),
    # 169.254/16 (link-local, incl. the cloud metadata IP), and reserved space.
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


@bp.get("/fetch-safe")
def fetch_safe():
    url = request.args.get("url", "")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return jsonify({"url": url, "allowed": False, "reason": "scheme not allowed"}), 400
    host = parsed.hostname or ""
    if host not in _ALLOWED_HOSTS:
        return jsonify(
            {
                "url": url,
                "allowed": False,
                "reason": "host not on allow-list",
                "allow_list": sorted(_ALLOWED_HOSTS),
            }
        ), 400
    # SAFE: resolve the host and verify NONE of its addresses are internal before
    # connecting (defeats decimal/octal/IPv6 encodings and DNS-to-loopback).
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as exc:
        return jsonify({"url": url, "allowed": False, "error": str(exc)}), 400
    for info in infos:
        ip_str = info[4][0]
        if _ip_is_blocked(ip_str):
            return jsonify(
                {"url": url, "allowed": False, "reason": "host resolves to a blocked address"}
            ), 400
    # SAFE: allow-listed + validated; disable redirects so a 302 cannot re-target.
    try:
        resp = requests.get(url, timeout=3, allow_redirects=False)
    except Exception as exc:
        return jsonify({"url": url, "allowed": True, "error": str(exc)}), 502
    return jsonify({"url": url, "allowed": True, "status": resp.status_code})
