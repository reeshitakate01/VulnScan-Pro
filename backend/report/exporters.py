"""
Machine-readable report exporters — VulnScan Pro.

  * build_json_export(): a clean, stable JSON structure for programmatic use.
  * build_sarif():       SARIF 2.1.0, which GitHub code scanning and many CI
                         systems ingest directly, turning a scan into
                         annotations on a pull request.
"""
from datetime import datetime, timezone

TOOL_NAME = "VulnScan Pro"
TOOL_VERSION = "2.1.0"
INFO_URI = "https://github.com/reeshitakate01/VulnScan-Pro"

# SARIF severity levels: error | warning | note
_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}
# Numeric security-severity (GitHub uses this to bucket alerts)
_SECURITY_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "3.0",
    "INFO": "0.0",
}


def _iter_findings(modules: dict):
    """Yield (module, finding) across the flattened per-module findings."""
    for module, findings in (modules or {}).items():
        for finding in findings or []:
            yield module, finding


def build_json_export(scan: dict) -> dict:
    """
    `scan` is the parsed results_json plus top-level metadata:
    {url, score, grade, summary, results_json:{pdf_data:{modules,...}, score_data}}
    """
    rj = scan.get("results_json") or {}
    pdf_data = rj.get("pdf_data", {})
    modules = pdf_data.get("modules", {})

    findings = []
    for module, f in _iter_findings(modules):
        findings.append({
            "module": module,
            "title": f.get("Finding"),
            "severity": f.get("Severity"),
            "description": f.get("Description"),
            "recommendation": f.get("Recommendation"),
            "owasp_category": f.get("owasp_category"),
            "cwe": f.get("cwe"),
            "cvss_score": f.get("cvss_score"),
        })

    return {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "target": scan.get("url"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score": scan.get("score"),
        "grade": scan.get("grade"),
        "summary": scan.get("summary"),
        "findings_count": rj.get("score_data", {}).get("findings_count", {}),
        "owasp_summary": pdf_data.get("owasp_summary", {}),
        "findings": findings,
    }


def build_sarif(scan: dict) -> dict:
    rj = scan.get("results_json") or {}
    modules = rj.get("pdf_data", {}).get("modules", {})
    target = scan.get("url") or "unknown"

    rules_by_id: dict[str, dict] = {}
    results = []

    for module, f in _iter_findings(modules):
        severity = (f.get("Severity") or "INFO").upper()
        rule_id = f.get("finding_key") or f"{module}:{f.get('Finding', 'finding')}"

        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": (f.get("Finding") or rule_id)[:120],
                "shortDescription": {"text": (f.get("Finding") or rule_id)[:200]},
                "fullDescription": {"text": f.get("Recommendation") or f.get("Description") or ""},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY.get(severity, "0.0"),
                    "tags": [t for t in [f.get("owasp_category"), f.get("cwe")] if t],
                },
            }

        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(severity, "note"),
            "message": {"text": f"{f.get('Finding', '')}. {f.get('Description', '')}".strip()},
            "properties": {"severity": severity, "module": module},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": target}}
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": INFO_URI,
                "rules": list(rules_by_id.values()),
            }},
            "results": results,
        }],
    }
