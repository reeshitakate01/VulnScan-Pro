# Changelog

All notable changes to this project are documented here.

## [2.2.0] — 2026-10-08

### Added
- **User accounts** (register / login / logout) via Flask-Login with hashed
  passwords; scans are owned by the creating user.
- **Per-user scan history** and a **score-trend chart** over time.
- **gunicorn** production server for the Docker image (gthread, single worker).

### Changed
- Scan APIs and pages now require authentication; results/reports are scoped to
  the owner.
- Hardened the session cookie (HttpOnly, SameSite=Lax).
- Moved legacy slide decks / prototypes into `archive/` to tidy the repo root.

## [2.1.0] — 2026-10-08

### Added
- **SSRF guard** (`SAFE_MODE`) blocking private/loopback/link-local/reserved
  targets; wired into the scan API.
- Environment-driven configuration layer (`config.py`) + `.env.example`.
- New non-destructive scanner modules: **CORS misconfiguration**,
  **HTTP methods / TRACE (XST)**, and **recon (security.txt)**.
- **Live CVE lookup** via OSV.dev for client-side libraries (offline fallback).
- **JSON** and **SARIF 2.1.0** report exports + endpoints.
- **Scan history** dashboard (`/history`, `/api/scans`).
- Docker + docker-compose, GitHub Actions CI, Makefile, ruff config.
- pytest suite (49 tests) and comprehensive documentation.

### Changed
- Flask debug now **off by default** (gated by `FLASK_DEBUG`).
- Bounded scan concurrency + SSE max-duration guard.
- Replaced the compiled `mmh3` dependency with a pure-Python MurmurHash3
  (byte-identical), removing the build-tools requirement.
- Cleaned and pinned dependencies.

### Security
- Self-audit documented in [`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md).
- CORS is now off by default (was permissive `CORS(app)`); opt-in via `CORS_ORIGINS`.
- Removed destructive SQLi payloads (`DROP TABLE` / `INSERT` / `xp_cmdshell`).
- Validate scan IDs as UUIDs and confine the report path to `reports/`.
- Defensive request-body parsing; fixed a concurrency-semaphore leak.

### Fixed
- False "Missing SPF" on every DNS scan (checked the wrong field); missing
  DMARC now also appears as a report finding.

### Removed
- Tracking of secrets (`*.pem`), databases (`*.db`) and generated PDF reports.

## [2.0.0] — prior
- Initial VulnScan Pro: crawler, core scanner modules, scoring, OWASP mapping,
  PDF reports, live SSE dashboard.
