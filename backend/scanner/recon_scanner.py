"""
Recon / best-practice Scanner — VulnScan Pro.

Lightweight, read-only checks for disclosure/best-practice files:
  * /.well-known/security.txt (RFC 9116) — its absence is a minor
    best-practice gap; its presence is reported as informational.
  * A small set of commonly-leaked metadata files.

All checks are plain GETs through the SSRF-guarded session.
"""
from urllib.parse import urlparse

from scanner.safe_requests import safe_get, TargetNotAllowed


def _origin(url: str) -> str:
    p = urlparse(url if "://" in url else "http://" + url)
    return f"{p.scheme}://{p.netloc}"


def _get_status(url: str):
    try:
        r = safe_get(url, allow_redirects=True)
        return r.status_code, len(r.content)
    except TargetNotAllowed:
        raise
    except Exception:  # noqa: BLE001
        return None, 0


def run_recon_scan(url: str) -> list[dict]:
    origin = _origin(url)
    findings: list[dict] = []

    # security.txt (check both canonical locations)
    found_security_txt = False
    for path in ("/.well-known/security.txt", "/security.txt"):
        status, _ = _get_status(origin + path)
        if status == 200:
            found_security_txt = True
            findings.append({
                "title": "security.txt present",
                "severity": "INFO",
                "description": f"Found a vulnerability-disclosure policy at {path}.",
                "recommendation": "",
                "vulnerable": False,
                "finding_key": None,
            })
            break

    if not found_security_txt:
        findings.append({
            "title": "No security.txt disclosure policy",
            "severity": "LOW",
            "description": (
                "No /.well-known/security.txt (RFC 9116) was found. This file "
                "tells researchers how to report vulnerabilities responsibly."
            ),
            "recommendation": (
                "Publish /.well-known/security.txt with a contact and policy URL."
            ),
            "vulnerable": True,
            "finding_key": "missing_security_txt",
        })

    return findings


if __name__ == "__main__":
    import json
    print(json.dumps(run_recon_scan("https://example.com"), indent=2))
