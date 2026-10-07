"""
CORS Misconfiguration Scanner — VulnScan Pro.

Sends a cross-origin probe and inspects the Access-Control-Allow-Origin (ACAO)
and Access-Control-Allow-Credentials (ACAC) response headers. Purely a GET
request with a spoofed Origin header — nothing state-changing.

Risk logic:
  * ACAO reflects an arbitrary attacker Origin AND ACAC=true  -> HIGH
    (any site can read authenticated responses).
  * ACAO reflects an arbitrary attacker Origin, no credentials -> MEDIUM.
  * ACAO = "*"                                                 -> LOW
    (wildcard cannot be combined with credentials by browsers).
"""
from scanner.safe_requests import safe_get, TargetNotAllowed

PROBE_ORIGIN = "https://vulnscan-cors-probe.example"


def run_cors_scan(url: str) -> list[dict]:
    findings: list[dict] = []
    try:
        resp = safe_get(url, headers={"Origin": PROBE_ORIGIN})
    except TargetNotAllowed:
        raise
    except Exception as exc:  # noqa: BLE001
        return [{
            "title": "CORS check could not complete",
            "severity": "INFO",
            "description": f"Request failed: {exc}",
            "recommendation": "",
            "vulnerable": False,
            "finding_key": None,
        }]

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if acao == PROBE_ORIGIN:
        findings.append({
            "title": "CORS reflects arbitrary Origin"
                     + (" with credentials" if acac else ""),
            "severity": "HIGH" if acac else "MEDIUM",
            "description": (
                f"Server reflected the attacker-controlled Origin "
                f"'{PROBE_ORIGIN}' in Access-Control-Allow-Origin"
                + (" and set Access-Control-Allow-Credentials: true, so any "
                   "website can read this origin's authenticated responses."
                   if acac else ".")
            ),
            "recommendation": (
                "Do not reflect the Origin header. Validate it against a strict "
                "server-side allowlist and only send "
                "Access-Control-Allow-Credentials: true for trusted origins."
            ),
            "vulnerable": True,
            "finding_key": "cors_reflected_origin",
        })
    elif acao == "*":
        findings.append({
            "title": "CORS allows any origin (wildcard)",
            "severity": "LOW",
            "description": (
                "Access-Control-Allow-Origin is '*'. Browsers will not send "
                "credentials with a wildcard, but any site can read "
                "non-credentialed responses from this origin."
            ),
            "recommendation": (
                "Restrict Access-Control-Allow-Origin to the specific origins "
                "that legitimately need cross-origin access."
            ),
            "vulnerable": True,
            "finding_key": "cors_wildcard",
        })
    else:
        findings.append({
            "title": "CORS policy looks restrictive",
            "severity": "INFO",
            "description": (
                f"Cross-origin probe was not reflected "
                f"(Access-Control-Allow-Origin: '{acao or 'not set'}')."
            ),
            "recommendation": "",
            "vulnerable": False,
            "finding_key": None,
        })

    return findings


if __name__ == "__main__":
    import json
    print(json.dumps(run_cors_scan("https://example.com"), indent=2))
