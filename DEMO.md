# VulnScan Pro — Interview Demo Guide

## One-command demo

From the repo root, with the virtualenv Python:

```bash
# Windows
venv\Scripts\python.exe demo.py

# macOS / Linux
venv/bin/python demo.py
```

This will:
1. Start the bundled **vulnerable lab app** on `http://127.0.0.1:5001`
2. Start the **scanner** on `http://127.0.0.1:5000`
3. Create a demo account and run **2 scans** against the lab (so History +
   the score-trend chart are already populated)
4. Print the URL, login, and a per-screen script

Then open **http://127.0.0.1:5000** and log in with
**`demo@vulnscan.local` / `demopass123`**.

Press **Ctrl+C** in the terminal to stop both servers.

> The scanner's SSRF guard blocks internal hosts by default; the demo
> explicitly allow-lists the lab via `SAFE_MODE_ALLOW=127.0.0.1,localhost`.
> That's a feature, and a good talking point.

---

## 30-second pitch

> "VulnScan Pro is a full-stack web vulnerability scanner — Flask backend, 15
> scanner modules, live dashboard. It crawls a target, tests for SQLi, XSS,
> CSRF, open redirect and misconfigurations, maps every finding to
> OWASP/CWE/CVSS, scores it A–F, and exports PDF/JSON/SARIF. It has user
> accounts, runs in Docker with CI, and 58 tests. The part I'm proudest of is
> that I secured the scanner itself — it's SSRF-guarded so it can't be turned
> against internal infrastructure."

## Demo flow (4–5 min)

| Screen | What to say |
|--------|-------------|
| **Login** | Multi-user, hashed passwords, rate-limited against brute-force. |
| **Dashboard** | 15 modules, live time estimate, bounded concurrent worker pool. *(Scan `http://127.0.0.1:5001` live.)* |
| **Live log** | Progress streams over Server-Sent Events as each module finishes. |
| **Results** | A–F score, severity breakdown, every finding mapped to OWASP Top-10 + CWE + CVSS. *(Expand the SQL Injection / XSS finding to show evidence + remediation.)* |
| **Exports** | Click **SARIF** — the format GitHub code-scanning ingests, so a scan can annotate a PR. Also PDF + JSON. |
| **History** | Per-user history + a score-trend chart over time. |

## Standout points
- **"I secured my own security tool"** — SSRF guard, removed destructive SQLi
  payloads, rate limiting, per-user access scoping. See `docs/SECURITY_REVIEW.md`.
- **Real engineering** — bounded concurrency, CI, Docker + gunicorn, 58 tests,
  env-driven config, OSV.dev live CVE lookup.
- **Found & fixed real bugs** in the inherited codebase (e.g. a scoring bug that
  reported "Missing SPF" on every scan).

## Likely questions
- **Scoring?** Weighted deductions per severity, floored at 0, mapped to A–F; a
  detected WAF gives a small bonus.
- **False positives?** XSS checks reflected-unescaped payloads; CSRF skips GET
  forms and recognises token fields; open-redirect only tests redirect-named params.
- **Is it safe to run?** SAFE_MODE SSRF guard, non-destructive payloads, an
  authorisation checkbox, and a responsible-use disclaimer.
- **What next?** Async engine, authenticated scanning, scheduled scans (README roadmap).
