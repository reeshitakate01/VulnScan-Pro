"""
Safe HTTP layer for VulnScan Pro.

Provides:
  * validate_target()  — SSRF guard. Resolves a URL's host and rejects any
    target that maps to a private / loopback / link-local / reserved address
    unless SAFE_MODE is disabled or the host is explicitly allow-listed.
  * get_session()      — a shared requests.Session with connection pooling,
    bounded retries, a consistent User-Agent and a default timeout.

Every scanner module should route its outbound requests through this layer so
SSRF policy, timeouts and identification are enforced in exactly one place.
"""
import ipaddress
import socket
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover - very old urllib3
    Retry = None

import urllib3

from config import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TargetNotAllowed(Exception):
    """Raised when SAFE_MODE blocks a target as a potential SSRF risk."""


def _resolve_ips(host: str) -> list[str]:
    """Return every A/AAAA address a hostname resolves to."""
    infos = socket.getaddrinfo(host, None)
    return list({info[4][0] for info in infos})


def _is_public_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_target(url: str) -> tuple[bool, str]:
    """
    Decide whether `url` is a permitted scan target.

    Returns (ok, reason). When SAFE_MODE is off, every well-formed URL is
    allowed. When on, the host must either be allow-listed or resolve solely
    to public, routable addresses.
    """
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname
    if not host:
        return False, "URL has no host component."

    if not config.SAFE_MODE:
        return True, "SAFE_MODE disabled."

    if host.lower() in config.SAFE_MODE_ALLOW:
        return True, f"Host '{host}' is explicitly allow-listed."

    # A literal IP is checked directly; a name is resolved first.
    try:
        ipaddress.ip_address(host)
        candidates = [host]
    except ValueError:
        try:
            candidates = _resolve_ips(host)
        except socket.gaierror as exc:
            return False, f"Could not resolve host '{host}': {exc}"

    if not candidates:
        return False, f"Host '{host}' did not resolve to any address."

    for ip in candidates:
        if not _is_public_ip(ip):
            return (
                False,
                f"Target '{host}' resolves to non-public address {ip}. "
                f"Blocked by SAFE_MODE (set SAFE_MODE=0 or add the host to "
                f"SAFE_MODE_ALLOW to scan internal hosts you are authorised for).",
            )

    return True, "Target resolves to public addresses."


def build_session() -> requests.Session:
    """Construct a hardened session (callers usually use the shared one)."""
    session = requests.Session()
    session.headers.update({"User-Agent": config.HTTP_USER_AGENT})
    if Retry is not None:
        retry = Retry(
            total=2,
            connect=2,
            read=1,
            backoff_factor=0.3,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    return session


_SHARED_SESSION: requests.Session | None = None


def get_session() -> requests.Session:
    """Return a process-wide shared session (lazy, thread-safe enough for CPython)."""
    global _SHARED_SESSION
    if _SHARED_SESSION is None:
        _SHARED_SESSION = build_session()
    return _SHARED_SESSION


def safe_get(url: str, **kwargs) -> requests.Response:
    """
    GET helper that enforces SAFE_MODE and applies the default timeout.
    verify defaults to False because a scanner must still inspect hosts with
    broken/self-signed TLS; TLS findings are reported by the SSL module.
    """
    ok, reason = validate_target(url)
    if not ok:
        raise TargetNotAllowed(reason)
    kwargs.setdefault("timeout", config.HTTP_TIMEOUT)
    kwargs.setdefault("verify", False)
    return get_session().get(url, **kwargs)
