"""API-level tests using Flask's test client (no real scans are launched)."""
import pytest


@pytest.fixture()
def client():
    import app as appmod
    appmod.app.config["TESTING"] = True
    return appmod.app.test_client()


def test_scan_requires_url(client):
    resp = client.post("/api/scan", json={})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_scan_blocks_ssrf_target(client):
    # SAFE_MODE is on in the test env; a loopback target must be refused
    # before any scan thread is started.
    resp = client.post("/api/scan", json={"url": "http://127.0.0.1:5000"})
    assert resp.status_code == 400
    assert "not allowed" in resp.get_json()["error"].lower()


def test_estimate_returns_duration(client):
    resp = client.post("/api/estimate", json={"modules": ["header_scanner", "crawler"]})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "display" in data
    assert data["total_seconds"] > 0
