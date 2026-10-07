"""Mocked tests for http_methods, recon modules and the OWASP mapper."""
import pytest

import scanner.http_methods_scanner as hm
import scanner.recon_scanner as recon
from scanner.owasp_mapper import OWASPMapper
from config import config


class _Resp:
    def __init__(self, status=200, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text
        self.content = text.encode()


@pytest.fixture(autouse=True)
def _safe_mode_off():
    saved = config.SAFE_MODE
    config.SAFE_MODE = False  # skip DNS in validate_target for mocked hosts
    yield
    config.SAFE_MODE = saved


def test_http_methods_flags_dangerous_and_trace(monkeypatch):
    class FakeSession:
        def options(self, url, **k):
            return _Resp(headers={"Allow": "GET, POST, DELETE, TRACE"})
        def request(self, method, url, **k):
            return _Resp(status=200, text="TRACE / HTTP/1.1")
    monkeypatch.setattr(hm, "get_session", lambda: FakeSession())
    keys = {f["finding_key"] for f in hm.run_http_methods_scan("https://example.com")}
    assert "dangerous_http_method" in keys
    assert "http_trace_enabled" in keys


def test_http_methods_clean(monkeypatch):
    class FakeSession:
        def options(self, url, **k):
            return _Resp(headers={"Allow": "GET, POST"})
        def request(self, method, url, **k):
            return _Resp(status=405, text="")
    monkeypatch.setattr(hm, "get_session", lambda: FakeSession())
    findings = hm.run_http_methods_scan("https://example.com")
    assert all(not f["vulnerable"] for f in findings)


def test_recon_missing_security_txt(monkeypatch):
    monkeypatch.setattr(recon, "safe_get", lambda url, **k: _Resp(status=404))
    findings = recon.run_recon_scan("https://example.com")
    assert findings[0]["finding_key"] == "missing_security_txt"
    assert findings[0]["vulnerable"] is True


def test_recon_present_security_txt(monkeypatch):
    monkeypatch.setattr(recon, "safe_get", lambda url, **k: _Resp(status=200, text="Contact: x"))
    findings = recon.run_recon_scan("https://example.com")
    assert findings[0]["vulnerable"] is False


def test_owasp_mapper_enriches_and_summarises():
    m = OWASPMapper()
    f = {"finding_key": "missing_csp", "Severity": "HIGH"}
    m.enrich_finding(f)
    assert f["owasp_category"] == "A05:2021"
    assert f["cwe"].startswith("CWE-")
    summary = m.generate_owasp_summary([f])
    assert summary["A05:2021"]["count"] == 1
    assert summary["A05:2021"]["highest_severity"] == "HIGH"
