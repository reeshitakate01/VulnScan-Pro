"""Tests for OSV CVE enrichment (network mocked; must fail open)."""
import pytest

import scanner.cve_lookup as cve
from config import config


class _FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, resp):
        self._resp = resp

    def post(self, *a, **k):
        return self._resp


@pytest.fixture(autouse=True)
def _clear_cache():
    cve._CACHE.clear()
    saved = config.OSV_ENABLED
    config.OSV_ENABLED = True
    yield
    config.OSV_ENABLED = saved


def test_query_osv_prefers_cve_alias(monkeypatch):
    payload = {"vulns": [
        {"id": "GHSA-abcd", "aliases": ["CVE-2020-1111"]},
        {"id": "GHSA-noalias", "aliases": []},
    ]}
    monkeypatch.setattr(cve, "get_session", lambda: _FakeSession(_FakeResp(200, payload)))
    ids = cve.query_osv("jquery", "1.12.4")
    assert "CVE-2020-1111" in ids
    assert "GHSA-noalias" in ids


def test_unknown_ecosystem_returns_empty(monkeypatch):
    monkeypatch.setattr(cve, "get_session", lambda: _FakeSession(_FakeResp(200, {"vulns": []})))
    assert cve.query_osv("nginx", "1.18.0") == []  # not in ECOSYSTEM_MAP


def test_disabled_flag_skips(monkeypatch):
    config.OSV_ENABLED = False
    assert cve.query_osv("jquery", "1.12.4") == []


def test_network_error_fails_open(monkeypatch):
    class _Boom:
        def post(self, *a, **k):
            raise RuntimeError("network down")
    monkeypatch.setattr(cve, "get_session", lambda: _Boom())
    assert cve.query_osv("jquery", "1.12.4") == []


def test_enrich_merges_without_duplicates(monkeypatch):
    monkeypatch.setattr(cve, "query_osv", lambda n, v: ["CVE-2020-1111"])
    techs = [{"name": "jquery", "version": "1.12.4", "cves_found": ["CVE-2015-9251"]}]
    cve.enrich_technologies(techs)
    assert techs[0]["cves_found"] == ["CVE-2015-9251", "CVE-2020-1111"]
    assert techs[0]["cve_source"] == "osv.dev"
