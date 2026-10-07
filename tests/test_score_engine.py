"""Tests for the security scoring engine."""
from scanner.score_engine import calculate_score


def test_clean_scan_is_perfect():
    r = calculate_score({})
    assert r["score"] == 100
    assert r["grade"] == "A"


def test_high_header_finding_deducts_15():
    r = calculate_score({"headers": [{"severity": "HIGH"}]})
    assert r["score"] == 85
    assert r["grade"] == "B"
    assert r["findings_count"]["HIGH"] == 1


def test_sqli_is_critical():
    r = calculate_score({"sqli": [{"vulnerable": True}]})
    assert r["score"] == 75
    assert r["grade"] == "C"
    assert r["findings_count"]["CRITICAL"] == 1


def test_waf_gives_small_bonus():
    # MEDIUM header (-8) plus WAF bonus (+5) => 97
    r = calculate_score({
        "headers": [{"severity": "MEDIUM"}],
        "waf": {"waf_detected": True},
    })
    assert r["score"] == 97
    assert r["grade"] == "A"


def test_score_never_below_zero():
    r = calculate_score({"sqli": [{"vulnerable": True} for _ in range(10)]})
    assert r["score"] == 0
    assert r["grade"] == "F"


def test_grade_boundaries():
    assert calculate_score({"headers": [{"severity": "INFO"}]})["grade"] == "A"  # 99
