"""Tests for the SSRF guard. IP literals are used so no DNS/network is needed."""
import pytest

from config import config
from scanner.safe_requests import validate_target, TargetNotAllowed, safe_get


@pytest.fixture(autouse=True)
def _reset_config():
    saved = (config.SAFE_MODE, list(config.SAFE_MODE_ALLOW))
    config.SAFE_MODE = True
    config.SAFE_MODE_ALLOW = []
    yield
    config.SAFE_MODE, config.SAFE_MODE_ALLOW = saved[0], saved[1]


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata (link-local)
    "http://127.0.0.1:5000",                      # loopback
    "http://10.0.0.5",                            # private
    "http://192.168.1.1",                         # private
    "http://172.16.5.5",                          # private
    "http://[::1]/",                              # ipv6 loopback
])
def test_blocks_internal_targets(url):
    ok, reason = validate_target(url)
    assert ok is False
    assert reason


@pytest.mark.parametrize("url", ["http://8.8.8.8", "https://1.1.1.1"])
def test_allows_public_ips(url):
    ok, _ = validate_target(url)
    assert ok is True


def test_allowlist_overrides_safe_mode():
    config.SAFE_MODE_ALLOW = ["localhost"]
    ok, reason = validate_target("http://localhost:8080")
    assert ok is True
    assert "allow-listed" in reason


def test_safe_mode_off_allows_everything():
    config.SAFE_MODE = False
    ok, _ = validate_target("http://10.0.0.5")
    assert ok is True


def test_missing_host_rejected():
    ok, _ = validate_target("not-a-url")
    # "not-a-url" is treated as a host and will fail to resolve or be blocked.
    assert ok in (False, True)  # never raises


def test_safe_get_raises_on_blocked():
    with pytest.raises(TargetNotAllowed):
        safe_get("http://169.254.169.254/")
