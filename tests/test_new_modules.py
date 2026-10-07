"""Tests for the new config-posture modules and their scoring integration."""
import types

import pytest

import scanner.cors_scanner as cors_mod
from scanner.cors_scanner import run_cors_scan, PROBE_ORIGIN
from scanner.score_engine import calculate_score


class _FakeResp:
    def __init__(self, headers):
        self.headers = headers


def _patch_cors(monkeypatch, headers):
    monkeypatch.setattr(cors_mod, "safe_get", lambda url, **kw: _FakeResp(headers))


def test_cors_reflected_origin_with_credentials_is_high(monkeypatch):
    _patch_cors(monkeypatch, {
        "Access-Control-Allow-Origin": PROBE_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    })
    findings = run_cors_scan("https://example.com")
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["finding_key"] == "cors_reflected_origin"
    assert findings[0]["vulnerable"] is True


def test_cors_wildcard_is_low(monkeypatch):
    _patch_cors(monkeypatch, {"Access-Control-Allow-Origin": "*"})
    findings = run_cors_scan("https://example.com")
    assert findings[0]["finding_key"] == "cors_wildcard"
    assert findings[0]["severity"] == "LOW"


def test_cors_restrictive_is_info(monkeypatch):
    _patch_cors(monkeypatch, {})
    findings = run_cors_scan("https://example.com")
    assert findings[0]["vulnerable"] is False


def test_score_engine_handles_config_posture_modules():
    r = calculate_score({
        "cors": [{"vulnerable": True, "severity": "HIGH"}],
        "http_methods": [{"vulnerable": True, "severity": "MEDIUM"}],
        "recon": [{"vulnerable": True, "severity": "LOW"}],
    })
    # 100 - 15 (HIGH) - 8 (MEDIUM) - 3 (LOW) = 74
    assert r["score"] == 74
    assert r["findings_count"]["HIGH"] == 1
    assert r["findings_count"]["MEDIUM"] == 1
    assert r["findings_count"]["LOW"] == 1
