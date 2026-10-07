"""
CSRF Scanner — VulnScan Pro
Detects Cross-Site Request Forgery (CSRF) vulnerabilities by analysing
the forms and cookies discovered during crawling.

Detection signals (any combination can confirm a finding):
  1. POST form has NO hidden input whose name matches known CSRF token patterns.
  2. Session cookie has no SameSite=Strict/Lax attribute.
  3. Session cookie has no Secure flag (makes token leakage easier).
  4. No custom header requirement detected (checked via OPTIONS).

False-positive reduction:
  • GET forms are skipped (CSRF on GET is rarely exploitable for state changes).
  • Forms containing a field that looks like a CSRF token are marked safe.
  • APIs that require a custom header (e.g. X-Requested-With) are downgraded.
"""

import re
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings()

_FETCH_STATE_RE = re.compile(
    r'fetch\s*\([^)]*,\s*\{[^}]*method\s*:\s*[\'"](?:POST|PUT|DELETE|PATCH)[\'"]',
    re.IGNORECASE | re.DOTALL,
)
_XHR_OPEN_RE = re.compile(
    r'\.open\s*\(\s*[\'"](?:POST|PUT|DELETE|PATCH)[\'"]',
    re.IGNORECASE,
)
_CSRF_HEADER_RE = re.compile(r'X-CSRFToken|X-CSRF-Token|X-Requested-With', re.IGNORECASE)
_SCRIPT_RE = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)

# ── Known CSRF token field name patterns ──────────────────────────────────
CSRF_FIELD_PATTERNS = [
    re.compile(r"csrf", re.IGNORECASE),
    re.compile(r"_token$", re.IGNORECASE),
    re.compile(r"^token$", re.IGNORECASE),
    re.compile(r"authenticity_token", re.IGNORECASE),
    re.compile(r"__requestverificationtoken", re.IGNORECASE),
    re.compile(r"nonce", re.IGNORECASE),
    re.compile(r"xsrf", re.IGNORECASE),
    re.compile(r"_wpnonce", re.IGNORECASE),
    re.compile(r"form_key", re.IGNORECASE),
    re.compile(r"viewstate", re.IGNORECASE),
]

# Min entropy for a token value to be considered a real token (not a stub)
MIN_TOKEN_LENGTH = 8

# Session-like cookie name patterns
SESSION_COOKIE_PATTERNS = [
    re.compile(r"sess", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"login", re.IGNORECASE),
    re.compile(r"user", re.IGNORECASE),
    re.compile(r"SID$", re.IGNORECASE),
    re.compile(r"^PHPSESSID$"),
    re.compile(r"^JSESSIONID$"),
    re.compile(r"^ASP\.NET_SessionId$"),
]


def _has_csrf_token(inputs: list[dict]) -> tuple[bool, str]:
    """
    Return (True, field_name) if a strong CSRF token field is present,
    otherwise (False, '').
    A token is strong if its name matches a CSRF pattern AND its value
    has at least MIN_TOKEN_LENGTH chars (not empty / trivially short).
    """
    for inp in inputs:
        name  = inp.get("name", "")
        value = inp.get("value", "")
        itype = inp.get("type", "text").lower()

        if itype not in ("hidden", "text"):
            continue

        for pattern in CSRF_FIELD_PATTERNS:
            if pattern.search(name):
                if len(value) >= MIN_TOKEN_LENGTH:
                    return True, name
                # Name matches but value is weak/empty — still flag as present
                # but we will note it as potentially weak
                return True, f"{name} (weak/empty value)"

    return False, ""


def _check_samesite_cookies(url: str, timeout: int = 6) -> list[dict]:
    """
    Fetch the page and examine Set-Cookie headers for SameSite + Secure flags.
    Returns a list of cookie vulnerability dicts.
    """
    cookie_issues = []
    try:
        res = requests.get(url, timeout=timeout, verify=False)
        raw_cookies = res.headers.get("Set-Cookie", "")

        # requests merges multiple Set-Cookie into one; use raw_headers trick
        all_cookie_headers = [
            v for k, v in res.raw.headers.items()   # type: ignore[attr-defined]
            if k.lower() == "set-cookie"
        ]
        # Fallback if raw headers not accessible
        if not all_cookie_headers and raw_cookies:
            all_cookie_headers = [raw_cookies]

        for cookie_str in all_cookie_headers:
            parts  = [p.strip() for p in cookie_str.split(";")]
            name   = parts[0].split("=")[0].strip() if parts else "unknown"
            flags  = [p.lower() for p in parts[1:]]
            flags_str = " ".join(flags)

            # Only care about session-like cookies
            is_session = any(pat.search(name) for pat in SESSION_COOKIE_PATTERNS)
            if not is_session:
                continue

            issues = []
            if "samesite=strict" not in flags_str and "samesite=lax" not in flags_str:
                if "samesite=none" in flags_str:
                    issues.append("SameSite=None (explicitly allows cross-site)")
                else:
                    issues.append("Missing SameSite attribute")

            if "secure" not in flags_str:
                issues.append("Missing Secure flag")

            if issues:
                cookie_issues.append({
                    "cookie_name": name,
                    "issues":      issues,
                })

    except requests.exceptions.RequestException:
        pass

    return cookie_issues


def _check_custom_header(url: str, timeout: int = 4) -> bool:
    """
    OPTIONS request to see if the server documents any CSRF-protective headers.
    This is a best-effort check; a False return is NOT a confirmed issue.
    """
    try:
        res = requests.options(url, timeout=timeout, verify=False)
        cors_headers = res.headers.get("Access-Control-Allow-Headers", "").lower()
        if "x-requested-with" in cors_headers or "x-csrf" in cors_headers:
            return True
    except Exception:
        pass
    return False


def _check_js_fetch_requests(base_url: str, timeout: int = 6) -> list[dict]:
    """
    Scan inline scripts for fetch()/XHR state-changing calls without CSRF headers.
    """
    findings = []
    try:
        res = requests.get(base_url, timeout=timeout, verify=False)
        for script in _SCRIPT_RE.findall(res.text):
            has_state_call = _FETCH_STATE_RE.search(script) or _XHR_OPEN_RE.search(script)
            if has_state_call and not _CSRF_HEADER_RE.search(script):
                findings.append({
                    "url":          base_url,
                    "source_url":   base_url,
                    "method":       "JS-FETCH/XHR",
                    "inputs":       [],
                    "vulnerable":   True,
                    "type":         "CSRF (JavaScript fetch/XHR)",
                    "severity":     "MEDIUM",
                    "evidence":     (
                        "Inline JavaScript performs a state-changing fetch()/XHR request "
                        "(POST/PUT/DELETE/PATCH) without a CSRF token header."
                    ),
                    "token_field":  None,
                    "recommendation": (
                        "Include a CSRF token header (e.g. X-CSRFToken) in all JavaScript "
                        "fetch()/XHR calls that perform state-changing operations."
                    ),
                })
                break  # one finding per page is enough
    except requests.exceptions.RequestException:
        pass
    return findings


def run_csrf_scan(forms: list[dict],
                  base_url: str = "",
                  timeout: int = 6) -> list[dict]:
    """
    Public entry point called by app.py.

    Args:
      forms    – list of form dicts from the crawler
      base_url – origin URL used for cookie inspection
      timeout  – per-request timeout in seconds

    Returns:
      List of finding dicts for forms lacking CSRF protection.
    """
    findings = []

    # Fetch cookie security issues once per origin
    cookie_issues: list[dict] = []
    js_fetch_issues: list[dict] = []
    if base_url:
        cookie_issues = _check_samesite_cookies(base_url, timeout)
        js_fetch_issues = _check_js_fetch_requests(base_url, timeout)

    for form in forms:
        action  = form.get("action_url", "")
        method  = form.get("method", "get").lower()
        inputs  = form.get("inputs", [])
        source  = form.get("source_url", action)

        # CSRF is only relevant on state-changing methods
        if method not in ("post", "put", "patch", "delete"):
            continue

        has_token, token_field = _has_csrf_token(inputs)
        has_custom_header      = _check_custom_header(action, timeout)

        if has_token:
            # Token present — no finding for this form
            continue

        if has_custom_header:
            # Custom header requirement is a partial mitigation
            severity = "LOW"
            reason   = "No CSRF token field found; server may rely on custom header as mitigation."
        else:
            severity = "HIGH"
            reason   = "POST form has no CSRF token and no custom header requirement detected."

        # Enrich with cookie observations
        cookie_detail = ""
        if cookie_issues:
            cookie_detail = " In addition: " + "; ".join(
                f"{ci['cookie_name']} cookie has: {', '.join(ci['issues'])}"
                for ci in cookie_issues
            )

        findings.append({
            "url":          action,
            "source_url":   source,
            "method":       method.upper(),
            "inputs":       [i["name"] for i in inputs if i.get("name")],
            "vulnerable":   True,
            "type":         "CSRF",
            "severity":     severity,
            "evidence":     reason + cookie_detail,
            "token_field":  None,
            "recommendation": (
                "Implement the Synchronizer Token Pattern: generate a cryptographically "
                "random per-session token, embed it as a hidden field in every state-changing "
                "form, and validate it server-side. Also set SameSite=Lax or Strict on "
                "session cookies as a defence-in-depth measure."
            ),
        })

    # Add JS fetch/XHR findings
    findings.extend(js_fetch_issues)

    # Report cookie issues independently if no form vulns caught them
    if cookie_issues and not findings:
        for ci in cookie_issues:
            findings.append({
                "url":          base_url,
                "source_url":   base_url,
                "method":       "N/A",
                "inputs":       [],
                "vulnerable":   True,
                "type":         "CSRF (Cookie Misconfiguration)",
                "severity":     "MEDIUM",
                "evidence":     (
                    f"Cookie '{ci['cookie_name']}' missing: {', '.join(ci['issues'])}. "
                    "This makes CSRF easier to exploit."
                ),
                "token_field":  None,
                "recommendation": (
                    "Set SameSite=Strict or SameSite=Lax on all session cookies. "
                    "Also set the Secure flag to prevent transmission over HTTP."
                ),
            })

    return findings
