# VulnScan-Pro — Overnight Build Report

**Built for:** reeshitakate01 (final-year B.Tech interview/portfolio project)
**Night of:** 2026-10-07 → 2026-10-08 (IST)
**Repo:** https://github.com/reeshitakate01/VulnScan-Pro (private)
**Working copy used by the build:** `C:\Users\Reeshita\vulnscan-pro` (clean ASCII path — see note below)

> ⚠️ **Note on your local folder:** your original clone is at
> `C:\Users\Reeshita\OneDrive\Tài liệu\Vulnscan`. The accented characters +
> OneDrive sync break the code editing tools, so the build was done in a
> clean copy and pushed to GitHub. To get everything on your machine, just run
> `git pull` in your OneDrive folder, **or** clone fresh to a simpler path.

This file is updated as each batch completes, so it always reflects the
current state.

---

## ✅ Completed

### Batch A — Security hardening, config & tests (pushed: commit `bc77e1a`)
- **Config layer** (`backend/config.py`) driven by environment variables +
  `.env.example`. Flask **debug is now OFF by default** (was `debug=True`,
  an RCE risk) and gated behind `FLASK_DEBUG`.
- **SSRF guard** (`backend/scanner/safe_requests.py`): the scanner now refuses
  targets resolving to private / loopback / link-local / reserved IPs
  (e.g. `169.254.169.254` cloud metadata, `localhost`, `10.x`) unless
  `SAFE_MODE=0` or the host is allow-listed. Wired into `POST /api/scan`.
  Great interview talking point ("I made my own security tool safe against
  SSRF abuse").
- **Bounded scan concurrency** (semaphore, `MAX_CONCURRENT_SCANS`) and an
  **SSE max-duration guard** so progress streams/threads can't loop forever.
- **Removed the compiled `mmh3` dependency** — replaced with a pure-Python
  MurmurHash3 that is byte-for-byte identical (verified against known test
  vectors). The project now installs with **no C++ build tools** required
  (this was blocking install on your machine).
- **requirements.txt** cleaned: versions pinned, stdlib `uuid` removed, unused
  `playwright`/`python-whois`/`concurrent-log-handler` dropped, missing
  `python-dotenv` added. Added `requirements-dev.txt`.
- **Repo hygiene:** expanded `.gitignore`; stopped tracking secrets (`*.pem`),
  databases (`*.db`) and generated `reports/*.pdf`.
- **Test suite:** 23 pytest tests (SSRF guard, scoring engine, murmur hash,
  API endpoints). All green.

---

## 🚧 In progress / planned tonight
- [ ] New read-only scanner modules: CORS misconfig, HTTP methods, cookie
      analysis, security.txt/recon.
- [ ] Real CVE lookup via the OSV.dev API (replacing the ~6-entry hardcoded dict).
- [ ] Machine-readable exports: JSON + SARIF (for CI / GitHub code scanning).
- [ ] Dockerfile + docker-compose for one-command setup.
- [ ] GitHub Actions CI (lint + tests).
- [ ] Rewritten README with architecture, features, screenshots placeholders,
      and an ethical-use disclaimer.
- [ ] Scan history + trends (stretch).

---

## ❓ Open questions / decisions for you (answer when awake)
_(none yet — will be filled in as they come up)_

---

## ▶️ How to run (updated as tooling lands)
```bash
git clone https://github.com/reeshitakate01/VulnScan-Pro.git
cd VulnScan-Pro
python -m venv venv && venv\Scripts\activate   # Windows
pip install -r requirements.txt
cd backend && python app.py
# open http://127.0.0.1:5000
```
