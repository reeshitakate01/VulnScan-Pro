# Changelog

All notable changes to this project are documented here.

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
- pytest suite (42 tests) and comprehensive documentation.

### Changed
- Flask debug now **off by default** (gated by `FLASK_DEBUG`).
- Bounded scan concurrency + SSE max-duration guard.
- Replaced the compiled `mmh3` dependency with a pure-Python MurmurHash3
  (byte-identical), removing the build-tools requirement.
- Cleaned and pinned dependencies.

### Removed
- Tracking of secrets (`*.pem`), databases (`*.db`) and generated PDF reports.

## [2.0.0] — prior
- Initial VulnScan Pro: crawler, core scanner modules, scoring, OWASP mapping,
  PDF reports, live SSE dashboard.
