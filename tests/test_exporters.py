"""Tests for the JSON and SARIF exporters (pure transforms, no network)."""
from report.exporters import build_json_export, build_sarif

SAMPLE = {
    "url": "https://example.com",
    "score": 72,
    "grade": "C",
    "summary": "Found 1 high severity issue.",
    "results_json": {
        "score_data": {"findings_count": {"HIGH": 1, "INFO": 0}},
        "pdf_data": {
            "owasp_summary": {},
            "modules": {
                "headers": [{
                    "Finding": "Missing Content-Security-Policy",
                    "Severity": "HIGH",
                    "Description": "CSP header absent.",
                    "Recommendation": "Add a CSP header.",
                    "finding_key": "missing_csp",
                    "owasp_category": "A05:2021",
                    "cwe": "CWE-693",
                    "cvss_score": 6.1,
                }],
            },
        },
    },
}


def test_json_export_shape():
    out = build_json_export(SAMPLE)
    assert out["target"] == "https://example.com"
    assert out["grade"] == "C"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["title"] == "Missing Content-Security-Policy"
    assert f["owasp_category"] == "A05:2021"
    assert f["cwe"] == "CWE-693"


def test_sarif_is_valid_shape():
    sarif = build_sarif(SAMPLE)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VulnScan Pro"
    # one rule, one result, HIGH -> error
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert run["tool"]["driver"]["rules"][0]["id"] == "missing_csp"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["ruleId"] == "missing_csp"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://example.com"


def test_sarif_empty_modules():
    sarif = build_sarif({"url": "https://x", "results_json": {}})
    assert sarif["runs"][0]["results"] == []
