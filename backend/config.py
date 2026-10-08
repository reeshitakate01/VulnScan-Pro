"""
Central configuration for VulnScan Pro.

All tunables are read from environment variables (see .env.example) so the
same codebase runs safely in development and production without edits.
"""
import os

try:
    from dotenv import load_dotenv

    # Load a .env from the project root if present (no-op in production).
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
except Exception:
    # python-dotenv is optional; env vars still work without it.
    pass


def _as_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _as_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class Config:
    # --- Flask ---
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-insecure-key-change-me")
    DEBUG = _as_bool(os.getenv("FLASK_DEBUG"), default=False)

    # --- CORS ---
    # Default: same-origin only (no permissive CORS headers). Set CORS_ORIGINS
    # to a comma-separated allowlist to enable cross-origin API access. The
    # built-in frontend is served same-origin, so it needs no CORS.
    CORS_ORIGINS = [
        o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()
    ]

    # --- Database ---
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///scans.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Scan orchestration ---
    # Bounded worker pool prevents unbounded thread creation under load.
    MAX_CONCURRENT_SCANS = _as_int(os.getenv("MAX_CONCURRENT_SCANS"), 3)
    # Hard ceiling on a single scan's wall-clock time (seconds) so the SSE
    # stream and worker thread can never loop forever.
    SCAN_MAX_DURATION = _as_int(os.getenv("SCAN_MAX_DURATION"), 600)

    # --- HTTP client ---
    HTTP_TIMEOUT = _as_int(os.getenv("HTTP_TIMEOUT"), 8)
    HTTP_USER_AGENT = os.getenv(
        "HTTP_USER_AGENT", "VulnScanPro/2.1 (+https://github.com/)"
    )

    # --- SSRF protection ---
    # When SAFE_MODE is on (default), the scanner refuses targets that resolve
    # to private, loopback, link-local or reserved IP ranges. This stops the
    # tool from being abused to reach internal services or cloud metadata.
    SAFE_MODE = _as_bool(os.getenv("SAFE_MODE"), default=True)
    # Comma-separated hostnames explicitly allowed even in SAFE_MODE (e.g. a
    # deliberately-vulnerable lab host for demos).
    SAFE_MODE_ALLOW = [
        h.strip().lower()
        for h in os.getenv("SAFE_MODE_ALLOW", "").split(",")
        if h.strip()
    ]

    # --- CVE enrichment ---
    OSV_ENABLED = _as_bool(os.getenv("OSV_ENABLED"), default=True)
    OSV_API = os.getenv("OSV_API", "https://api.osv.dev/v1/query")
    OSV_TIMEOUT = _as_int(os.getenv("OSV_TIMEOUT"), 6)

    # --- Notifications ---
    SMTP_SERVER = os.getenv("SMTP_SERVER", "localhost")
    SMTP_PORT = _as_int(os.getenv("SMTP_PORT"), 1025)
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASS = os.getenv("SMTP_PASS", "")


config = Config()
