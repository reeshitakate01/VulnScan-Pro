"""Tests for the security-hardening pass. `client` is authenticated (conftest)."""


def test_sqli_payloads_are_non_destructive():
    from scanner.sql_injection import PAYLOADS
    flat = " ".join(p.upper() for cat in PAYLOADS.values() for p in cat)
    for forbidden in ("DROP TABLE", "XP_CMDSHELL", "INSERT INTO", "DELETE FROM", "TRUNCATE"):
        assert forbidden not in flat, f"destructive payload present: {forbidden}"


def test_report_rejects_non_uuid_scan_id(client):
    resp = client.get("/api/report/not-a-uuid")
    assert resp.status_code == 400


def test_report_rejects_path_traversal(client):
    # The string converter blocks slashes; a traversal-looking id is rejected
    # as a non-UUID before any filesystem access.
    resp = client.get("/api/report/..%2f..%2fetc%2fpasswd")
    assert resp.status_code in (400, 404)


def test_estimate_handles_empty_body(client):
    # No JSON body must not 500.
    resp = client.post("/api/estimate")
    assert resp.status_code == 200


def test_cors_not_permissive_by_default(client):
    resp = client.get("/")
    assert resp.headers.get("Access-Control-Allow-Origin") != "*"
