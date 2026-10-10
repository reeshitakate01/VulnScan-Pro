#!/usr/bin/env python
"""
VulnScan Pro — one-command interview demo.

Boots the bundled vulnerable lab app + the scanner, creates a demo account,
and runs two scans against the lab so History and the score-trend chart are
already populated. Then it prints the URL, credentials and a short script of
what to say at each step.

Run it with the project's virtualenv Python, from the repo root:

    Windows :  venv\\Scripts\\python.exe demo.py
    macOS/Linux:  venv/bin/python demo.py

Press Ctrl+C to stop both servers when you're done.
"""
import os
import sys
import time
import signal
import subprocess

try:
    import requests
except ImportError:
    sys.exit("requests is not installed. Activate the venv / pip install -r requirements.txt first.")

ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(ROOT, "backend")
VULN = os.path.join(ROOT, "vulnerable-webapp")
INSTANCE_DB = os.path.join(BACKEND, "instance", "demo_scans.db")

SCANNER_PORT = os.getenv("DEMO_PORT", "5000")
SCANNER = f"http://127.0.0.1:{SCANNER_PORT}"
LAB = "http://127.0.0.1:5001"          # the vulnerable lab's HTTP endpoint

DEMO_EMAIL = "demo@vulnscan.local"
DEMO_PASS = "demopass123"

# Full, finding-rich suite for the local lab (where injection findings live).
# Port Scan + DNS Recon are omitted to keep the demo snappy.
MODULES_FULL = [
    "WAF Detection", "Security Headers", "SSL/TLS", "Tech Fingerprinting",
    "Crawler", "XSS", "SQL Injection", "Open Redirect", "CSRF Detection",
    "CORS", "HTTP Methods", "Recon", "JavaScript Analysis",
]
# Non-intrusive posture checks only — used for the public warm-up scan so we
# never send attack-like payloads to a third-party host.
MODULES_POSTURE = [
    "Security Headers", "SSL/TLS", "Tech Fingerprinting",
    "CORS", "HTTP Methods", "Recon",
]

# Two scans so History + the trend chart show two distinct points. The lab
# scan runs last, so it's the newest entry — the one you open for live findings.
DEMO_SCANS = [
    ("https://example.com", MODULES_POSTURE, "example.com (posture)"),
    (LAB, MODULES_FULL, "vulnerable lab (full suite)"),
]

procs = []


def log(msg):
    print(f"  {msg}", flush=True)


def wait_for(url, label, tries=40):
    for _ in range(tries):
        try:
            requests.get(url, timeout=3, verify=False)
            return True
        except Exception:
            time.sleep(1)
    print(f"[!] {label} did not come up at {url}")
    return False


def start_servers():
    print("\n[1/4] Starting the vulnerable lab app (127.0.0.1:5001)...", flush=True)
    # Fresh lab DB with seeded users/guestbook.
    subprocess.run([sys.executable, "db.py"], cwd=VULN, check=True)
    procs.append(subprocess.Popen([sys.executable, "app.py"], cwd=VULN,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    print("[2/4] Starting the scanner (" + SCANNER + ")...", flush=True)
    # Clean demo DB so History/trend start empty each run.
    try:
        if os.path.exists(INSTANCE_DB):
            os.remove(INSTANCE_DB)
    except OSError:
        pass
    env = dict(os.environ)
    env.update({
        "PORT": SCANNER_PORT,
        "HOST": "127.0.0.1",
        "FLASK_DEBUG": "0",
        "SECRET_KEY": "demo-secret",
        "SAFE_MODE": "1",
        # The SSRF guard blocks internal hosts by default; we explicitly
        # allow-list the local lab for this authorised demo.
        "SAFE_MODE_ALLOW": "127.0.0.1,localhost",
        "DATABASE_URI": "sqlite:///demo_scans.db",
    })
    procs.append(subprocess.Popen([sys.executable, "app.py"], cwd=BACKEND, env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    ok = wait_for(LAB, "Lab app") and wait_for(SCANNER + "/login", "Scanner")
    if not ok:
        shutdown()
        sys.exit(1)


def run_demo_scans():
    print("[3/4] Creating demo account + running 2 scans (this takes ~1-2 min)...", flush=True)
    s = requests.Session()
    s.post(f"{SCANNER}/register", data={"email": DEMO_EMAIL, "password": DEMO_PASS},
           timeout=20, allow_redirects=True)

    for i, (target, modules, label) in enumerate(DEMO_SCANS, 1):
        r = s.post(f"{SCANNER}/api/scan", json={"url": target, "modules": modules}, timeout=20)
        if r.status_code != 202:
            log(f"scan {i} ({label}) could not start: HTTP {r.status_code} {r.text[:120]}")
            continue
        scan_id = r.json()["scan_id"]
        status = "running"
        for _ in range(150):
            try:
                status = s.get(f"{SCANNER}/api/scan/{scan_id}/results", timeout=20).json()["status"]
            except Exception:
                pass
            if status in ("completed", "error"):
                break
            time.sleep(1)
        try:
            d = s.get(f"{SCANNER}/api/scan/{scan_id}/results", timeout=20).json()
            log(f"scan {i} [{label}]: {status} — score {d.get('score')}/100, grade {d.get('grade')}")
        except Exception:
            log(f"scan {i} [{label}]: {status}")


def print_cheatsheet():
    print("\n[4/4] Demo is ready!  ──────────────────────────────────────────────\n")
    print(f"  Open:      {SCANNER}")
    print(f"  Login:     {DEMO_EMAIL}  /  {DEMO_PASS}")
    print(f"  Lab target to scan live:  {LAB}\n")
    print("  WHAT TO SAY, screen by screen:")
    print("   1. Login page  — 'Multi-user, hashed passwords, rate-limited against brute-force.'")
    print("   2. Dashboard   — '15 modules, live time estimate, bounded concurrent worker pool.'")
    print(f"                    Scan {LAB} live.")
    print("   3. Live log    — 'Progress streams over Server-Sent Events as each module finishes.'")
    print("   4. Results     — 'A-F score, severity breakdown, every finding mapped to")
    print("                     OWASP Top-10 + CWE + CVSS.' Expand the SQL Injection / XSS finding.")
    print("   5. Exports     — click SARIF: 'This is what GitHub code-scanning ingests — plugs into CI.'")
    print("   6. History     — 'Per-user history + a score-trend chart over time.' (2 scans pre-loaded)")
    print("\n  Best line: 'The part I'm proudest of is that I secured the scanner itself —")
    print("              it's SSRF-guarded so it can't be turned against internal infrastructure.'")
    print("\n  Press Ctrl+C here to stop both servers.\n")
    print("  ────────────────────────────────────────────────────────────────────\n")
    sys.stdout.flush()


def shutdown(*_):
    print("\n[*] Stopping servers...", flush=True)
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    for p in procs:
        try:
            p.wait(timeout=8)
        except Exception:
            p.kill()
    print("[*] Done. Ports freed.")


def main():
    signal.signal(signal.SIGINT, lambda *a: (shutdown(), sys.exit(0)))
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass
    start_servers()
    run_demo_scans()
    print_cheatsheet()
    # Keep running so the user can demo in the browser.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
