# VulnScan Pro — Security Review

A self-assessment of **the scanner's own attack surface** (not the targets it
scans). Reviewed: the Flask API, the background scan orchestration, the HTTP
layer, and the injection modules.

_Last updated: 2026-10-08._

## Summary

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1 | Flask `debug=True` in production path (Werkzeug console → RCE) | Critical | ✅ Fixed |
| 2 | SSRF: scanner would fetch internal / metadata URLs | High | ✅ Fixed |
| 3 | Permissive `CORS(app)` — any origin could drive the API | Medium | ✅ Fixed |
| 4 | Destructive SQLi payloads (`DROP TABLE`, `xp_cmdshell`, `INSERT`) | High | ✅ Fixed |
| 5 | Semaphore leak on the scan error path (resource exhaustion) | Medium | ✅ Fixed |
| 6 | Report endpoint built a filesystem path from user input | Medium | ✅ Fixed |
| 7 | Malformed request body caused a 500 | Low | ✅ Fixed |
| 8 | Secrets committed to the repo (private key, DB) | High | ✅ Fixed |
| 9 | Unbounded scan concurrency + non-terminating SSE loop | Medium | ✅ Fixed |
| 10 | No authentication on API / results | Medium | ✅ Fixed |
| 11 | No rate limiting (auth brute-force / scan abuse) | Medium | ✅ Fixed |
| A | SSRF guard is resolve-time (DNS-rebinding TOCTOU) | Low | 📝 Documented |
| C | Reflection-only XSS detection (possible false positives) | Low | 📝 Documented |
| D | Time-based blind SQLi uses a large `randomblob` on SQLite | Low | 📝 Documented |

## Fixed

**1. Debug mode / RCE.** `app.run(debug=True)` exposes the Werkzeug debugger,
which allows arbitrary code execution if ever reachable. Debug is now **off by
default** and gated behind `FLASK_DEBUG`.

**2. SSRF (CWE-918).** The scanner makes server-side requests to a user-supplied
URL. Without controls it could be pointed at `http://localhost`, `10.x`, or the
cloud metadata endpoint `169.254.169.254`. `SAFE_MODE` (on by default) resolves
the target and refuses private / loopback / link-local / reserved addresses
unless the host is explicitly allow-listed.

**3. Permissive CORS (CWE-942).** `CORS(app)` sent `Access-Control-Allow-Origin`
for any origin, so any website could script the API through a victim's browser.
CORS is now **disabled by default** (the bundled UI is same-origin) and opt-in
via `CORS_ORIGINS`.

**4. Destructive injection payloads (CWE-89).** The SQLi module shipped stacked
payloads including `DROP TABLE users`, `INSERT INTO users …` and
`EXEC xp_cmdshell('whoami')`. Against a genuinely vulnerable target these could
destroy data or execute commands — and they added **no** detection value, since
the module confirms injection via SQL error messages / timing, never by
verifying the destructive action. They were replaced with harmless stacked
probes (`'; SELECT 1--`).

**5. Semaphore leak.** The concurrency semaphore was acquired before the
`try`/`finally`, so an exception between acquire and the try (e.g. in the first
log write) would leak a permit and permanently shrink the worker pool. Acquire
now sits immediately before the `try` whose `finally` releases it.

**6. Report path handling (CWE-22).** `/api/report/<id>` built a file path from
the URL segment. Scan IDs are now validated as UUIDs and the resolved path is
confirmed to stay within `reports/` before serving.

**7. Robust input.** `POST` handlers used `request.json`, which 500s on a
missing/!JSON body. They now use `request.get_json(silent=True) or {}`.

**8. Committed secrets.** A private key (`vulnerable-webapp/key.pem`), a SQLite
DB and generated PDFs were tracked. They are now git-ignored and untracked; the
demo cert regenerates via `generate_cert.py`.

**9. Resource limits.** Scans run in a bounded worker pool (`MAX_CONCURRENT_SCANS`)
and the SSE progress stream has a hard `SCAN_MAX_DURATION` ceiling, so a stuck
scan can't loop forever or exhaust threads.

**10. Authentication & access control.** The app now requires login
(Flask-Login, hashed passwords). Every scan is owned by its creator, and
results / reports / history are scoped to the owner (404 otherwise), so one user
cannot read another's data even with a scan ID.

**11. Rate limiting (CWE-307).** Flask-Limiter throttles login/register
(10/min) and scan starts (30/hour) to blunt credential brute-force and scan
abuse.

## Documented (accepted for now / roadmap)

**A. DNS-rebinding TOCTOU.** `SAFE_MODE` validates at request time, but each
scanner module re-resolves the host when it connects. An attacker controlling
DNS could pass validation and then rebind to an internal IP. A full fix pins the
resolved IP and forces connections to it. Low risk for the intended use (you
scan hosts you own), but noted.

**C. Reflection-only XSS.** The XSS module flags a payload reflected unescaped;
it does not confirm script execution, so false positives are possible. A
headless-browser verifier is a planned enhancement.

**D. Time-based blind SQLi `randomblob`.** The SQLite time-based payload uses a
large `randomblob(...)` to induce latency, which is briefly resource-intensive
on the target. Kept for detection efficacy; flagged for awareness.

## Responsible use

This is an active security tool. Only scan systems you own or are explicitly
authorised to test. `SAFE_MODE` is a safety net, not permission.
