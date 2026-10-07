"""
HTTP Methods Scanner — VulnScan Pro.

Enumerates the methods a server advertises (via OPTIONS) and confirms the
TRACE method (Cross-Site Tracing / XST) with a single, harmless TRACE request
that the server merely echoes back.

Safety: this module is strictly non-destructive. It never sends PUT, DELETE,
PATCH or CONNECT — it only *reports* when the server advertises them in the
Allow header, so no remote state can be changed by the scan.
"""
from scanner.safe_requests import get_session, validate_target, TargetNotAllowed
from config import config

DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "CONNECT"}


def run_http_methods_scan(url: str) -> list[dict]:
    ok, reason = validate_target(url)
    if not ok:
        raise TargetNotAllowed(reason)

    session = get_session()
    findings: list[dict] = []

    # 1. Enumerate advertised methods via OPTIONS (non-destructive).
    allowed = set()
    try:
        resp = session.options(url, timeout=config.HTTP_TIMEOUT, verify=False)
        allow_hdr = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods", "")
        allowed = {m.strip().upper() for m in allow_hdr.split(",") if m.strip()}
    except Exception:  # noqa: BLE001
        pass

    advertised_dangerous = sorted(allowed & DANGEROUS_METHODS)
    if advertised_dangerous:
        findings.append({
            "title": f"Server advertises write methods: {', '.join(advertised_dangerous)}",
            "severity": "MEDIUM",
            "description": (
                "The OPTIONS response lists state-changing HTTP methods "
                f"({', '.join(advertised_dangerous)}). If these are reachable "
                "without authentication they may allow unauthorised writes. "
                "(The scanner only reports this; it did not invoke them.)"
            ),
            "recommendation": (
                "Disable HTTP methods the application does not need at the web "
                "server/framework level, and enforce auth/authorisation on the rest."
            ),
            "vulnerable": True,
            "finding_key": "dangerous_http_method",
        })

    # 2. Confirm TRACE (XST) — a TRACE request is an echo and changes nothing.
    try:
        tr = session.request("TRACE", url, timeout=config.HTTP_TIMEOUT, verify=False)
        trace_on = tr.status_code == 200 and "TRACE" in (tr.text or "").upper()
        if trace_on or "TRACE" in allowed:
            findings.append({
                "title": "HTTP TRACE method enabled (XST)",
                "severity": "MEDIUM",
                "description": (
                    "The server responds to TRACE, enabling Cross-Site Tracing "
                    "which can be abused to read sensitive headers (e.g. cookies) "
                    "in some legacy configurations."
                ),
                "recommendation": "Disable the TRACE method on the web server.",
                "vulnerable": True,
                "finding_key": "http_trace_enabled",
            })
    except Exception:  # noqa: BLE001
        pass

    if not findings:
        findings.append({
            "title": "No dangerous HTTP methods detected",
            "severity": "INFO",
            "description": f"Advertised methods: {', '.join(sorted(allowed)) or 'unknown'}.",
            "recommendation": "",
            "vulnerable": False,
            "finding_key": None,
        })

    return findings


if __name__ == "__main__":
    import json
    print(json.dumps(run_http_methods_scan("https://example.com"), indent=2))
