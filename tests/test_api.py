"""API-level tests using Flask's test client (no real scans are launched).

The `client` fixture (see conftest) is already authenticated; `anon_client`
is not.
"""


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


def test_scans_list_endpoint(client):
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)


def test_history_page_renders(client):
    resp = client.get("/history")
    assert resp.status_code == 200
    assert b"Scan History" in resp.data


def test_api_requires_auth(anon_client):
    assert anon_client.post("/api/scan", json={"url": "http://x"}).status_code == 401
    assert anon_client.get("/api/scans").status_code == 401
