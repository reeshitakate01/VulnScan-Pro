"""
Open Redirect Scanner — VulnScan Pro
Tests URL parameters and form inputs whose names suggest redirect behaviour
(e.g. `next`, `url`, `return`, `redirect`) by injecting external domain
payloads and inspecting whether the server follows the redirect.

Design decisions:
  • Only tests parameters whose NAMES appear in a curated list.  This avoids
    flooding every parameter with redirect payloads and keeps FP rate low.
  • Uses allow_redirects=False so we can catch the Location header directly,
    without actually leaving the target domain.
  • Falls back to checking the final URL after auto-redirect in case the
    server-side redirect is implemented in meta-refresh or JS (best-effort).
"""

import requests
import urllib3
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin, quote

urllib3.disable_warnings()

# ── Redirect-parameter name patterns ──────────────────────────────────────
REDIRECT_PARAM_NAMES = {
    "url", "next", "redirect", "redirect_uri", "redirect_url",
    "return", "return_url", "returnUrl", "return_to", "returnTo",
    "callback", "callbackUrl", "continue", "destination", "dest",
    "forward", "go", "goto", "jump", "link", "location", "out",
    "redir", "ref", "referrer", "target", "to", "uri", "path",
    "success_url", "failure_url", "after_login", "after_logout",
}

# ── Payloads: domains/paths that must never appear in a redirect target ────
PAYLOADS = [
    "//evil.com",                              # Protocol-relative
    "https://evil.com",                        # Absolute HTTPS
    "//evil.com/%2F..",                        # Path traversal + host
    r"\/\/evil.com",                           # Backslash bypass
    "//evil%2Ecom",                            # URL-encoded dot
    "https:///evil.com",                       # Triple-slash
    "//evil.com%23",                           # Fragment-anchored
    "https://evil.com?legitimate.com",         # Query confuse
]

CANARY_HOST = "evil.com"


def _is_redirected_to_evil(response: requests.Response) -> bool:
    """Return True if any redirect in the chain lands on CANARY_HOST."""
    # Direct Location header (allow_redirects=False)
    location = response.headers.get("Location", "")
    if location and CANARY_HOST in location:
        return True

    # Walk the redirect history (allow_redirects=True fallback)
    for hist_resp in response.history:
        loc = hist_resp.headers.get("Location", "")
        if CANARY_HOST in loc:
            return True

    # Final URL (when following redirects)
    if CANARY_HOST in response.url:
        return True

    return False


def _test_url_params(url: str, timeout: int = 6) -> list[dict]:
    """Test GET parameters in the URL itself."""
    findings = []
    parsed = urlparse(url)
    params  = parse_qs(parsed.query, keep_blank_values=True)

    redirect_params = {k for k in params if k.lower() in REDIRECT_PARAM_NAMES
                       or k in REDIRECT_PARAM_NAMES}
    if not redirect_params:
        return findings

    for param in redirect_params:
        for payload in PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            test_url = urlunparse(parsed._replace(
                query=urlencode(test_params, doseq=True)
            ))

            try:
                # First: don't follow — grab Location header raw
                res = requests.get(test_url, timeout=timeout, verify=False,
                                   allow_redirects=False)
                if res.is_redirect and _is_redirected_to_evil(res):
                    findings.append(_make_finding(url, param, payload,
                                                  "GET (URL param)",
                                                  res.headers.get("Location", ""),
                                                  res.status_code))
                    break  # one confirmed hit per param is enough

                # Fallback: follow redirects and check final URL
                res2 = requests.get(test_url, timeout=timeout, verify=False,
                                    allow_redirects=True)
                if _is_redirected_to_evil(res2):
                    findings.append(_make_finding(url, param, payload,
                                                  "GET (URL param - followed)",
                                                  res2.url, res2.status_code))
                    break

            except requests.exceptions.RequestException:
                pass

    return findings


def _test_forms(forms: list[dict], timeout: int = 6) -> list[dict]:
    """Test form inputs whose names suggest redirect destinations."""
    findings = []

    for form in forms:
        action  = form.get("action_url", "")
        method  = form.get("method", "get").lower()
        inputs  = form.get("inputs", [])

        if not action:
            continue

        redirect_inputs = [
            inp for inp in inputs
            if inp.get("name", "").lower() in REDIRECT_PARAM_NAMES
            or inp.get("name", "") in REDIRECT_PARAM_NAMES
        ]

        if not redirect_inputs:
            continue

        for inp in redirect_inputs:
            param_name = inp["name"]
            for payload in PAYLOADS:
                # Build a form data dict with dummy values for other fields
                data = {}
                for other in inputs:
                    n = other.get("name")
                    if not n:
                        continue
                    data[n] = payload if n == param_name else "test"

                try:
                    if method == "post":
                        res = requests.post(action, data=data, timeout=timeout,
                                            verify=False, allow_redirects=False)
                    else:
                        res = requests.get(action, params=data, timeout=timeout,
                                           verify=False, allow_redirects=False)

                    if res.is_redirect and _is_redirected_to_evil(res):
                        findings.append(_make_finding(
                            action, param_name, payload,
                            f"{method.upper()} form",
                            res.headers.get("Location", ""),
                            res.status_code))
                        break

                    # Follow-redirect fallback
                    if method == "post":
                        res2 = requests.post(action, data=data, timeout=timeout,
                                             verify=False, allow_redirects=True)
                    else:
                        res2 = requests.get(action, params=data, timeout=timeout,
                                            verify=False, allow_redirects=True)

                    if _is_redirected_to_evil(res2):
                        findings.append(_make_finding(
                            action, param_name, payload,
                            f"{method.upper()} form (followed)",
                            res2.url, res2.status_code))
                        break

                except requests.exceptions.RequestException:
                    pass

    return findings


def _make_finding(url: str, param: str, payload: str, method: str,
                   evidence: str, status_code: int) -> dict:
    return {
        "url":          url,
        "parameter":    param,
        "payload":      payload,
        "method":       method,
        "evidence":     f"Redirected to: {evidence}",
        "status_code":  status_code,
        "vulnerable":   True,
        "severity":     "HIGH",
        "type":         "Open Redirect",
        "recommendation": (
            "Validate redirect targets against a strict server-side allowlist. "
            "Never pass user-supplied URLs as redirect destinations without validation."
        ),
    }


def run_open_redirect_scan(urls: list[str] = None,
                           forms: list[dict] = None,
                           timeout: int = 6) -> list[dict]:
    """
    Public entry point called by app.py.

    Args:
      urls  – list of page URLs discovered by the crawler (URL params tested)
      forms – list of form dicts from the crawler (form inputs tested)

    Returns:
      List of finding dicts, one per confirmed vulnerable parameter.
    """
    findings = []

    if urls:
        for url in urls:
            findings.extend(_test_url_params(url, timeout))

    if forms:
        findings.extend(_test_forms(forms, timeout))

    # Deduplicate by (url, parameter)
    seen = set()
    unique = []
    for f in findings:
        key = (f["url"], f["parameter"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
