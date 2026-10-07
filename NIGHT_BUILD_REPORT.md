# VulnScan-Pro — Overnight Build Report

**Built for:** reeshitakate01 (final-year B.Tech interview/portfolio project)
**Night of:** 2026-10-07 → 2026-10-08 (IST)
**Repo:** https://github.com/reeshitakate01/VulnScan-Pro (private)

---

## TL;DR

Good morning! The project is in a much stronger, interview-ready state.

- ✅ **8 batches shipped**, each committed and pushed to `main`.
- ✅ **42 unit/API tests — all green.**
- ✅ **GitHub Actions CI** (lint + tests) is set up and **passing**.
- ✅ **End-to-end verified:** a live scan of `example.com` ran the full
  pipeline and produced a score (21/F), a PDF, and JSON + SARIF exports.
- ✅ Installs with **no C++ build tools** (removed the `mmh3` blocker that was
  stopping installation on your machine).
- ✅ The scanner is now **SSRF-safe by default** — a strong talking point.

---

## ✅ What was built (with commit hashes)

### Batch A — Security hardening, config & tests — `bc77e1a`
- Env-driven config (`backend/config.py`) + `.env.example`. **Flask debug is
  now OFF by default** (it was `debug=True`, a remote-code-execution risk).
- **SSRF guard** (`backend/scanner/safe_requests.py`): refuses targets that
  resolve to private / loopback / link-local / reserved IPs (e.g. cloud
  metadata `169.254.169.254`, `localhost`, `10.x`) unless `SAFE_MODE=0` or the
  host is allow-listed. Wired into `POST /api/scan`.
- Bounded scan concurrency (semaphore) + SSE max-duration guard.
- Replaced the compiled `mmh3` dependency with a pure-Python MurmurHash3
  (verified byte-identical to `mmh3`).
- Cleaned/pinned `requirements.txt`; added `requirements-dev.txt`.
- Repo hygiene: expanded `.gitignore`; stopped tracking secrets (`*.pem`),
  databases (`*.db`) and generated `reports/*.pdf`.
- 23-test pytest suite.

### Batch B — New scanner modules — `d0e90ef`
Three **non-destructive** modules (GET/OPTIONS/TRACE only — never send
PUT/DELETE/PATCH):
- **CORS misconfiguration** (reflected-Origin = HIGH, wildcard = LOW).
- **HTTP methods / TRACE (XST)**.
- **Recon** (RFC 9116 `security.txt`).
Fully wired into the orchestrator, scoring, OWASP mapping, time estimator and
the UI. Also fixed the time estimator, which referenced modules that didn't exist.

### Batch C — Live CVE lookup — `672e2b9`
`scanner/cve_lookup.py` queries **OSV.dev** for advisories on detected
client-side libraries (jQuery, React, …). Fails open (no network / disabled /
unknown ecosystem ⇒ falls back to the offline table), so scans still work offline.

### Batch D — JSON + SARIF exports — `71d46de`
`report/exporters.py` + endpoints `/api/report/<id>/json` and `.../sarif`.
**SARIF 2.1.0** means a scan can be uploaded to GitHub code scanning to annotate
pull requests — a genuinely impressive, enterprise-grade feature.

### Batch E — Docker, CI & tooling — `fea33d0`
`Dockerfile` + `docker-compose.yml` (one-command run), GitHub Actions CI,
`ruff.toml`, `Makefile`, `.gitattributes`, `.dockerignore`.

### Batch F — Documentation — `f1befcc`
Rewrote `README.md` (features, mermaid architecture diagram, quickstart, config
table, API reference, responsible-use disclaimer, roadmap, CI badge) and fixed
`STARTUP.md` (removed hardcoded `e:\Projects\Nessus 2.0` paths and mojibake).

### Batch G — Scan history dashboard — `fbd4064`
`GET /api/scans` + a `/history` page listing past scans (date, target, score,
grade) with links to each result. History links added to home & results pages.

### Batch H — Test coverage & community docs — `64c9fcc`
Mocked tests for the http_methods/recon modules and the OWASP mapper (now
**42 tests**), plus `SECURITY.md`, `CONTRIBUTING.md` and `CHANGELOG.md`.

---

## 🔬 Verification done
- `pytest` → **42 passed**.
- `ruff check .` → clean.
- GitHub Actions CI → passing on `main`.
- Live end-to-end scan of `https://example.com` (benign modules only):
  completed, scored, PDF generated (~6.7 KB), JSON + SARIF endpoints returned 200.

---

## ▶️ How to run

**Docker (easiest):**
```bash
docker compose up --build       # then open http://localhost:5000
```

**Local Python:**
```bash
python -m venv venv
venv\Scripts\activate            # Windows
pip install -r requirements.txt
cd backend && python app.py      # open http://127.0.0.1:5000
```

**Tests:** `pip install -r requirements-dev.txt && pytest`

---

## 💻 About your local copy (please read)

Your original clone is at `C:\Users\Reeshita\OneDrive\Tài liệu\Vulnscan`. The
**accented characters + OneDrive** break the code-editing tools and even caused
file-write errors, so the entire build was done in a clean copy at
`C:\Users\Reeshita\vulnscan-pro` and pushed to GitHub. **I deliberately did not
touch your OneDrive folder** (nothing of yours was at risk, and I didn't want to
force changes while you slept).

👉 **Recommended:** get the finished project with a fresh clone to a simple path:
```bash
git clone https://github.com/reeshitakate01/VulnScan-Pro.git C:\Users\Reeshita\VulnScan-Pro
```
(Working from a non-OneDrive, ASCII path will also make future edits smoother.)

---

## ❓ Open questions / decisions for you
1. **User accounts & auth** — I built scan *history* (shared, no login). Do you
   want full multi-user login + per-user history? It's a bigger feature; I held
   off to avoid half-implementing it. Say the word and I'll add it.
2. **Repo cleanup** — I left your presentation/report files (`*.pptx`, `*.docx`,
   `docs/`, `generate_*presentation*.py`) and the `frontend_backup/` and `mock/`
   folders untouched. Want me to move them into a `docs/`/`archive/` folder to
   tidy the repo root, or leave them for your PBL submission?
3. **Demo certs** — I stopped tracking `vulnerable-webapp/{cert.pem,key.pem}`
   (a committed private key is bad practice). They regenerate via
   `vulnerable-webapp/generate_cert.py`. OK?
4. **Production server** — currently the Flask dev server (fine for the demo).
   Want me to add gunicorn for a more "production" story?

## 🗺️ Still pending (candidates for the next session)
- Multi-user auth + per-user history and **trend charts** (score over time).
- Scheduled / recurring scans.
- Authenticated scanning (inject a session cookie/login).
- Async engine (httpx + asyncio) + gunicorn.
- More modules: subdomain takeover, directory brute-force, clickjacking PoC.

---

## 📊 By the numbers
- 9 commits (1 initial + 8 feature batches).
- +4 new scanner modules (CORS, HTTP methods, recon) and a CVE-lookup module.
- +2 new export formats (JSON, SARIF).
- 42 automated tests, CI pipeline, Docker, and a full README.

_This file was written by the overnight build and reflects the final state._
