# 🛡️ VulnScan Pro — Complete Viva & Presentation Guide
> **Team of 6 | PBL Project | B.Tech Cybersecurity**
> Read this file before your viva/presentation. Each person should focus on their own section but understand the overview.

---

## 📌 PROJECT OVERVIEW (Everyone Must Know This)

### What is VulnScan Pro?
VulnScan Pro is an **automated web vulnerability scanner** — a tool that automatically scans any website and finds security weaknesses (vulnerabilities), similar to how professional tools like Nessus, Burp Suite, or OWASP ZAP work. It was built entirely from scratch using Python.

### How does it work? (Say this in viva)
> *"The user enters a target URL on the web frontend. The frontend sends this to our Flask backend API. The backend then runs multiple scanning modules in sequence — crawling, header analysis, XSS testing, SQL injection, port scanning, and more. All results are scored using our custom scoring engine, mapped to the OWASP Top 10 framework, and a PDF report is generated. The user can view results in real-time through the dashboard."*

### Tech Stack
| Layer | Technology |
|---|---|
| Backend | Python 3, Flask, SQLAlchemy, SQLite |
| Frontend | HTML5, Vanilla CSS, Vanilla JS, Chart.js |
| Scanning | Python `requests`, `socket`, `ssl`, `dnspython` |
| Reporting | ReportLab (PDF generation) |
| Notifications | Slack Webhooks, SMTP Email |
| Testing | Custom backtest runner (97–100% accuracy) |

### Architecture Flow
```
User (Browser)
    ↓  enters URL
Frontend (index.html)
    ↓  POST /api/scan
Flask Backend (app.py)
    ↓  spawns background thread
Orchestration Engine (bg_run_scan)
    ↓  runs each module
[Crawler → Headers → SSL → DNS → Ports → Tech → XSS → SQLi → CSRF → Open Redirect → WAF → JS Analyzer]
    ↓
Score Engine → OWASP Mapper → PDF Generator
    ↓
SQLite Database (stores scan + events)
    ↓
Frontend polls /api/scan/{id}/stream (SSE) → shows real-time logs
    ↓
Results Dashboard (/results/{scan_id})
```

---
---

# 👤 PERSON 1 — PROJECT LEAD / BACKEND ARCHITECT
### Modules: `app.py` (Flask Backend) + `score_engine.py` + Overall Project Architecture

---

## Your Role
You own the **entire backend orchestration** — the brain that connects all modules together, the API, and the scoring system.

---

## 1. Flask Backend (`app.py`)

### What it does
- It is the main Python web server file.
- It defines all the API endpoints (routes) that the frontend calls.
- It spawns scanning threads so scans run in the background without freezing the server.
- It stores scan results in a SQLite database.

### Key API Endpoints (Know all of these)
| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Serves the main index.html page |
| `/results/<scan_id>` | GET | Serves the results page |
| `/api/scan` | POST | Starts a new scan (main entry point) |
| `/api/scan/<id>/stream` | GET | Server-Sent Events — real-time log stream |
| `/api/scan/<id>/results` | GET | Returns full JSON results |
| `/api/report/<id>` | GET | Downloads PDF report |
| `/api/estimate` | POST | Estimates scan duration |

### How a scan starts (Explain this step by step)
```python
# 1. Frontend sends POST /api/scan with {"url": "...", "modules": [...]}
# 2. Backend creates a ScanTask record in DB with status = 'running'
# 3. A new background thread is spawned: bg_run_scan(scan_id, url, modules)
# 4. Backend returns {"scan_id": "abc123", "status": "running"} immediately
# 5. Frontend starts listening to /api/scan/abc123/stream for live logs
```

### Database Models
```python
ScanTask  → stores: id, url, status, score, grade, results_json, created_at
ScanEvent → stores: scan_id, timestamp, message   (these become the live log lines)
```

### Real-time Streaming (SSE — Server-Sent Events)
- The frontend connects to `/api/scan/{id}/stream`
- The backend polls the DB every 1 second for new `ScanEvent` rows
- It streams them as `data: {...}\n\n` events to the browser
- When the scan is `completed` or `error`, it sends a final event and closes the stream

---

## 2. Score Engine (`score_engine.py`)

### What it does
Takes the raw scan results from all modules and calculates a **security score out of 100** and a **letter grade (A–F)**.

### How scoring works
- Each finding has a severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Points are deducted based on severity:
  - CRITICAL → heavy deduction
  - HIGH → significant deduction
  - MEDIUM → moderate deduction
  - LOW → small deduction
  - INFO → no deduction
- Score starts at 100, deductions are applied, floored at 0
- Grade:
  - A = 90–100 | B = 75–89 | C = 60–74 | D = 45–59 | F = below 45

### Expected Viva Questions
**Q: Why did you build a custom scoring engine instead of using an existing one?**
> "Existing tools have proprietary scoring systems we cannot customize. Our scoring engine is tailored to our modules — each scanner returns structured findings, and the score engine knows how to weight findings from each module based on research into their real-world impact."

**Q: How is the grade determined?**
> "The score starts at 100. We deduct points for each finding based on its severity. Critical vulnerabilities like SQLi or XSS cost the most points. The final score maps to a letter grade — A is 90+, B is 75+, and so on."

---

## 3. General Architecture Questions
**Q: Why Flask and not Django?**
> "Flask is a micro-framework — lightweight and flexible. Our project doesn't need Django's ORM or admin interface complexity. Flask gives us full control over the API structure."

**Q: Why SQLite?**
> "SQLite is a serverless, file-based database — perfect for a portable academic project. In production, this would be easily swapped for PostgreSQL."

**Q: How do modules run without blocking?**
> "Python's `threading.Thread` is used. The scan runs entirely in a background thread. The Flask server remains responsive to other requests."

---
---

# 👤 PERSON 2 — CRAWLER + JAVASCRIPT ANALYZER
### Modules: `crawler.py` + `js_analyzer.py`

---

## Your Role
You own the **reconnaissance phase** — discovering all pages and scripts on the target before any vulnerability testing begins.

---

## 1. Web Crawler (`crawler.py`)

### What it does
- Visits the target URL and follows all internal links up to a configurable depth.
- Collects: all visited pages, all HTML forms (with their inputs), all external JS script URLs, email addresses, HTML comments, and hidden fields.

### How it works (Step by step)
```
1. Start at the target URL
2. Download the HTML using requests
3. Parse HTML using BeautifulSoup
4. Find all <a href> links → add internal ones to a queue
5. Find all <form> elements → extract action URL, method, and all input fields
6. Find all <script src> tags → collect external JS URLs
7. Find HTML comments → scan for sensitive keywords (password, secret, key, TODO)
8. Find email addresses using regex
9. Repeat for each discovered URL up to max_depth=2
```

### Why crawling is important
> "Before we can test for XSS or SQLi, we need to know WHERE the forms are and what parameters they accept. The crawler discovers this attack surface automatically."

### Data it returns
```python
{
  "pages_visited": [...],
  "forms": [{"action_url": "...", "method": "post", "inputs": [...]}],
  "external_scripts": [...],
  "emails": [...],
  "sensitive_comments": [...],
  "hidden_fields": [...]
}
```

---

## 2. JavaScript Analyzer (`js_analyzer.py`)

### What it does
Downloads each external JS file found by the crawler and scans its contents for **hardcoded secrets and insecure patterns** using regex.

### What it detects
| Pattern | Example |
|---|---|
| AWS Access Keys | `AKIAIOSFODNN7EXAMPLE` |
| GitHub Tokens | `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabc` |
| Generic Secrets/Passwords | `password = "SuperSecret123"` |
| Internal IP addresses | `http://192.168.1.100:8080` |
| Localhost references | `http://localhost:3000/api` |
| API Endpoints | `/api/v1/admin/users` |
| TODO/FIXME comments | `// TODO: remove this key before release` |
| Commented-out credentials | `// username: admin, password: admin123` |

### Why this matters
> "Developers often accidentally leave API keys and passwords in JavaScript files that are publicly accessible. Our analyzer catches these before attackers do. This directly maps to the Authentication & Identity Management subject — exposed credentials are a top attack vector."

### Expected Viva Questions
**Q: How do you detect secrets vs normal code?**
> "We use carefully crafted regular expressions. For example, AWS keys always follow the pattern `AKIA[0-9A-Z]{16}`. GitHub tokens start with `ghp_` followed by 36+ alphanumeric characters. For generic secrets, we look for variable names like `password`, `secret`, `api_key` assigned to string values."

**Q: What if the JS is minified/obfuscated?**
> "We currently detect patterns via regex even in minified code since AWS keys and tokens have distinctive patterns. Full de-obfuscation is a future enhancement."

---
---

# 👤 PERSON 3 — VULNERABILITY SCANNERS (XSS + SQL INJECTION)
### Modules: `xss_scanner.py` + `sql_injection.py`

---

## Your Role
You own the two most well-known and dangerous web vulnerabilities — XSS and SQLi. Both map directly to **OWASP A03: Injection**.

---

## 1. XSS Scanner (`xss_scanner.py`)

### What is XSS?
**Cross-Site Scripting (XSS)** — an attacker injects malicious JavaScript into a website. When another user visits the vulnerable page, the malicious script runs in their browser, potentially:
- Stealing session cookies (account takeover)
- Redirecting users to phishing pages
- Logging keystrokes

### How our scanner works
```
1. Receive all forms from the crawler
2. For each form, try injecting XSS payloads into each text input
3. Submit the form (GET or POST)
4. Check if the payload appears UNESCAPED in the response HTML
5. If yes → vulnerability confirmed and reported
```

### Payload Categories (Know these)
| Category | Example Payload |
|---|---|
| Basic Script Tag | `<script>alert(1)</script>` |
| Event Handler | `<img src=x onerror=alert(1)>` |
| Case Bypass | `<ScRiPt>alert(1)</sCrIpT>` |
| URL Encoding | `%3Cscript%3Ealert(1)%3C%2Fscript%3E` |
| HTML5 Tags | `<video><source onerror=alert(1)>` |
| Attribute Injection | `" onmouseover=alert(1) ` |
| Polyglot | Multiple bypass techniques combined |

### False Positive Prevention
> "A naive XSS scanner would flag everything that reflects input. We only report a vulnerability if the payload contains HTML special characters (`<`, `>`, `"`, `'`) AND they appear in the response without being HTML-escaped (converted to `&lt;`, `&gt;`, etc.)."

---

## 2. SQL Injection Scanner (`sql_injection.py`)

### What is SQL Injection?
**SQL Injection (SQLi)** — an attacker puts SQL code into a form field. If the site doesn't sanitize input, the attacker's SQL runs on the database, allowing them to:
- Dump all usernames and passwords
- Bypass login
- Delete or modify data
- Take over the server (in severe cases)

### How our scanner works
```
1. Receive all forms from the crawler
2. For each text input, inject SQLi test payloads
3. Submit the form
4. Analyze the response for:
   a. Error-Based: Database error messages (MySQL, PostgreSQL, ORA- errors)
   b. Boolean-Based: Different responses for TRUE vs FALSE conditions
   c. Time-Based: Delays caused by SLEEP() or WAITFOR DELAY commands
5. If any method confirms injection → report the vulnerability
```

### Three Detection Methods (Very important to know!)
| Method | How it works | Example Payload |
|---|---|---|
| **Error-Based** | Injects special chars; server returns DB error | `'` or `"` or `1'` |
| **Boolean-Based** | Two payloads with TRUE/FALSE; compares response length | `' OR '1'='1` vs `' OR '1'='2` |
| **Time-Based** | Injects a SLEEP command; checks if response was delayed | `'; WAITFOR DELAY '0:0:5'--` |

### Expected Viva Questions
**Q: What is the difference between error-based and blind SQLi?**
> "Error-based SQLi is visible — the database error message appears on the page. Blind SQLi has no visible output — we use boolean or time-based techniques to infer if the injection worked by comparing responses or measuring response times."

**Q: How can SQLi be prevented?**
> "Use parameterized queries / prepared statements. Never concatenate user input directly into SQL strings. Also use ORM frameworks like SQLAlchemy which handle this automatically."

---
---

# 👤 PERSON 4 — NETWORK & PROTOCOL SCANNERS
### Modules: `port_scanner.py` + `ssl_scanner.py` + `dns_scanner.py`

---

## Your Role
You own the **network-level reconnaissance** — scanning ports, checking SSL/TLS certificates, and analyzing DNS records. This maps to **SIEM/SOAR** (attack surface monitoring) and **Blockchain & Cryptography** (SSL/TLS).

---

## 1. Port Scanner (`port_scanner.py`)

### What it does
Scans a list of commonly important ports on the target host and checks which ones are open and what service is running.

### How it works
```python
socket.connect_ex((host, port))  # Returns 0 if port is open
```
- Uses Python's `socket` library (no Nmap required)
- Tests ~30 well-known ports: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 8080 (Alt HTTP), etc.
- Each open port gets a **risk level** (CRITICAL/HIGH/MEDIUM/INFO) based on the service

### Risk Level Logic (Port-based)
| Risk | Ports |
|---|---|
| CRITICAL | 23 (Telnet), 3389 (RDP exposed) |
| HIGH | 21 (FTP), 3306 (MySQL), 5432 (Postgres), 6379 (Redis) |
| MEDIUM | 25 (SMTP), 8080 (Alt HTTP), 8443 |
| INFO | 80 (HTTP), 443 (HTTPS) — expected and normal |

### IoT Connection (Subject Link)
> "IoT devices expose web admin panels on non-standard ports like 8080, 8443, or 9000. Our port scanner maps these open management interfaces, making it directly applicable to IoT security."

---

## 2. SSL/TLS Scanner (`ssl_scanner.py`)

### What it does
Analyzes the HTTPS configuration of the target — checking if their certificate is valid, what cipher suites they use, and what protocols (TLS 1.0, 1.2, 1.3) are supported.

### What it checks
| Check | Why it matters |
|---|---|
| Certificate validity | Expired certs cause browser warnings or MITM attacks |
| Self-signed check | Self-signed = untrusted, easy to spoof |
| Expiry date | Warn if cert expires in < 30 days |
| Protocol version | TLS 1.0 and 1.1 are deprecated and insecure |
| Weak ciphers | RC4, DES, 3DES — broken cipher suites |
| Subject/Issuer info | Verifies cert belongs to the domain |

### Cryptography Subject Link (MUST say in viva)
> "SSL/TLS is the most critical cryptographic protocol on the web. It ensures **Confidentiality** (encryption), **Integrity** (MACs), and **Authentication** (certificates). Our SSL scanner directly audits this cryptographic layer — validating certificate chains, detecting deprecated algorithms, and checking for weak cipher suites like RC4 which are cryptographically broken."

### Expected Viva Questions
**Q: What is the difference between SSL and TLS?**
> "SSL (Secure Sockets Layer) is the older, deprecated protocol. TLS (Transport Layer Security) is its successor. TLS 1.2 and 1.3 are the current secure standards. When people say 'SSL certificate' they usually mean a TLS certificate."

**Q: What is a man-in-the-middle attack?**
> "If a site has an invalid or self-signed certificate, an attacker can position themselves between the user and server, intercept all traffic, and read/modify it. Valid certificates from trusted Certificate Authorities prevent this."

---

## 3. DNS Recon (`dns_scanner.py`)

### What it does
Enumerates DNS (Domain Name System) records for the target domain to discover:
- **A records** — IP addresses the domain resolves to
- **MX records** — Mail servers
- **NS records** — Name servers (authoritative DNS servers)
- **TXT records** — SPF, DKIM, DMARC email security policies
- **CNAME records** — Domain aliases

### Security Findings from DNS
| Finding | Security Impact |
|---|---|
| Missing SPF record | Domain can be used for email spoofing/phishing |
| Missing DMARC | No email authentication enforcement |
| Exposed mail servers | Can be targeted for spam/attacks |
| Multiple A records | Load balancers — useful for mapping infrastructure |

### Expected Viva Question
**Q: What is an SPF record and why does it matter?**
> "SPF (Sender Policy Framework) is a DNS TXT record that specifies which mail servers are authorized to send email on behalf of a domain. Without SPF, attackers can forge emails that appear to come from your domain — a phishing technique called email spoofing."

---
---

# 👤 PERSON 5 — ADVANCED VULNERABILITY DETECTION
### Modules: `csrf_scanner.py` + `open_redirect.py` + `waf_detector.py`

---

## Your Role
You own three specialized vulnerability scanners that were **added by this team** as original contributions beyond the base project. This shows your team's initiative.

---

## 1. CSRF Scanner (`csrf_scanner.py`)

### What is CSRF?
**Cross-Site Request Forgery (CSRF)** — An attacker tricks a logged-in user's browser into making an unauthorized request to a website. The site thinks the request came from the real user.

**Classic Example:**
```
User is logged into their bank.
Attacker sends them an email with:
<img src="https://yourbank.com/transfer?to=attacker&amount=50000">
When the email loads, the bank transfer executes — with the user's cookies!
```

### How our scanner works
- Scans all POST forms discovered by the crawler
- Checks if any form has a CSRF token hidden input field (`csrf_token`, `_token`, `authenticity_token`, etc.)
- If a POST form lacks ANY CSRF token → flagged as vulnerable
- GET forms are excluded (they should NOT change server state)

### Expected Viva Questions
**Q: How does a CSRF token prevent the attack?**
> "A CSRF token is a unique, secret, random value embedded in every form. The server generates it and validates it on form submission. An attacker's malicious website cannot read this token due to the browser's Same-Origin Policy — so they cannot forge a valid request."

**Q: Are GET requests vulnerable to CSRF?**
> "GET requests should never perform state-changing actions (like transfers or deletions). Our scanner correctly ignores GET forms. Only POST/PUT/DELETE forms need CSRF protection."

---

## 2. Open Redirect Scanner (`open_redirect.py`)

### What is an Open Redirect?
When a website redirects users to a URL specified by a parameter without validation:
`https://trusted-site.com/login?next=https://evil-site.com`

The user sees `trusted-site.com` in the URL → trusts it → clicks → gets sent to the attacker's phishing site.

### How our scanner works
```
1. For each URL, check query parameters for redirect-like names:
   next, redirect, url, return, goto, destination, callback, redir
2. Inject a test value: https://evil-redirect-test.example.com
3. Follow the response (allow_redirects=True)
4. If the final URL is on a different domain → Open Redirect confirmed
5. Also tests forms with redirect-parameter inputs
```

### Real-World Impact
> "Open Redirects are classified as OWASP A01: Broken Access Control. Attackers use them in phishing campaigns — they craft URLs on legitimate domains to bypass spam filters and trick users into visiting malicious sites."

---

## 3. WAF Detector (`waf_detector.py`)

### What is a WAF?
A **Web Application Firewall (WAF)** sits in front of a web server and blocks malicious requests (like XSS payloads or SQLi strings) before they reach the application.
Examples: Cloudflare, AWS WAF, ModSecurity, Akamai.

### How our scanner detects WAFs
```
1. Send known malicious probes: XSS payloads, SQLi strings, path traversal (../../etc/passwd)
2. Analyze the response for WAF signatures:
   - HTTP status codes: 403, 406, 429, 503
   - Response body keywords: "blocked", "access denied", "security"
   - WAF-specific headers: cf-ray (Cloudflare), X-Sucuri-ID
   - Server header patterns
3. Match against a database of known WAF fingerprints
```

### Why WAF detection matters
> "Knowing whether a WAF exists changes the attack strategy entirely. If a WAF is detected, standard payloads will be blocked and bypass techniques are needed. If there's NO WAF, we flag it as a MEDIUM risk — the site has no additional layer of defense."

### Subject Link (SIEM/SOAR)
> "WAF detection integrates with SIEM because WAF logs are a key data source for security operations. A SOAR system can automatically trigger firewall rule updates based on WAF alerts — this is the modern security operations workflow."

---
---

# 👤 PERSON 6 — FRONTEND + REPORTING + TECH FINGERPRINTING
### Modules: `tech_fingerprint.py` + Frontend (HTML/CSS/JS) + PDF Report + OWASP Mapper

---

## Your Role
You own **what the user sees** — the entire frontend dashboard, the PDF reports, and the technology detection module. You're the person who can demo the application during the presentation.

---

## 1. Tech Fingerprinting (`tech_fingerprint.py`)

### What it does
Identifies what software stack the target website is running — CMS, web server, programming language, JavaScript frameworks, and checks for known CVEs (vulnerabilities) in outdated versions.

### How it detects technologies
| Signal | What we detect | Example |
|---|---|---|
| `Server` HTTP header | Web server + version | `nginx/1.18.0` |
| `X-Powered-By` header | Language/framework | `PHP/7.4.0` |
| `meta[name=generator]` tag | CMS | `WordPress 5.8.2` |
| HTML/JS signatures | Frontend frameworks | `wp-content/` → WordPress |
| Script URLs | JS libraries + versions | `jquery-1.12.4.min.js` |
| Cookie names | Frameworks | `PHPSESSID` → PHP |
| Favicon hash | Framework fingerprint | Default WordPress favicon |

### CVE Lookup
- After detecting a technology with a version, we check our **knowledge base** for known CVEs.
- Example: `nginx 1.18.0` → `CVE-2021-23017`, `CVE-2022-41741`
- This tells the target owner their server software has **known public vulnerabilities**.

### Expected Viva Questions
**Q: How do you match CVEs to detected technologies?**
> "We maintain a local knowledge base — a dictionary mapping technology names and versions to their known CVEs. After detection, we look up the technology name and compare the version to see if it falls in the vulnerable range. In production, this would be connected to the National Vulnerability Database (NVD) API."

---

## 2. Frontend (HTML/CSS/JS)

### Overview
The frontend is a glassmorphism-themed, dark-mode, single-page-like application with:
- **index.html** — Scan configuration form (module selection, URL input, ETA calculator)
- **results.html** — Results dashboard (score ring, severity chart, findings tab, OWASP mapping tab, modules tab)
- **main.js** — Handles form submission, SSE streaming log, ETA calculation
- **results.js** — Fetches and renders all scan data dynamically from the API
- **styles.css / results.css** — Full custom dark-themed CSS with glassmorphism effects

### Key UI Features to Demo
1. **Module toggles** — user selects which scanners to run
2. **ETA Calculator** — estimates scan time based on selected modules
3. **Real-time terminal log** — live scan events stream into the terminal UI
4. **Score ring animation** — animates from 0 to the final score on load
5. **Severity chart** — Chart.js doughnut chart of finding distribution
6. **Filter pills** — click CRITICAL/HIGH/MEDIUM to filter findings instantly
7. **Expandable findings** — click any finding to see Description, Parameter, Payload, Remediation

### How live logs work (Explain simply)
> "When a scan starts, the frontend opens an EventSource connection to `/api/scan/{id}/stream`. This is called Server-Sent Events (SSE). As the backend completes each module, it writes a log message to the database. The SSE endpoint polls the DB every second and streams new messages to the browser. This is how we achieve real-time updates without WebSockets."

---

## 3. OWASP Mapper (`owasp_mapper.py`)

### What is OWASP Top 10?
The **Open Web Application Security Project** publishes a list of the 10 most critical web security risks every few years. It is the global standard for web security.

| OWASP ID | Risk |
|---|---|
| A01 | Broken Access Control |
| A02 | Cryptographic Failures |
| A03 | Injection (XSS, SQLi) |
| A04 | Insecure Design |
| A05 | Security Misconfiguration |
| A06 | Vulnerable and Outdated Components |
| A07 | Identification & Authentication Failures |
| A08 | Software and Data Integrity Failures |
| A09 | Security Logging & Monitoring Failures |
| A10 | Server-Side Request Forgery |

### What our mapper does
- After all modules finish, the mapper goes through every finding
- It assigns each finding to the relevant OWASP category
- The OWASP dashboard tab shows how many findings map to each category
- This makes the report professionally aligned with the global security standard

### PDF Report
- Generated using **ReportLab** (Python PDF library)
- Contains: target URL, scan date, score, grade, executive summary, all module findings, OWASP mapping
- Downloaded via the "EXPORT PDF" button on the results page

---
---

# 🎯 COMMON VIVA QUESTIONS (ALL MEMBERS MUST KNOW)

**Q: What is the OWASP Top 10?**
> "It is an industry-standard list of the 10 most critical web application security risks, maintained by the Open Web Application Security Project. Our tool maps all findings to this framework."

**Q: What makes your project different from existing tools like Nessus?**
> "Nessus is a commercial product costing thousands of dollars annually. Our tool is open-source, lightweight, runs on any machine, and was built from scratch in Python. It integrates all major scanning modules in a single unified dashboard with real-time updates and automated PDF reporting."

**Q: How did you test your scanner?**
> "We built a deliberately vulnerable Flask test server (`vuln_target.py`) that contains intentional XSS, SQLi, open redirects, CSRF flaws, and missing headers. We wrote a comprehensive backtest runner that runs all modules against this server and verifies each detection. We achieved **100% test accuracy** across 47 test cases."

**Q: Is it legal to scan any website?**
> "No. Unauthorized scanning is illegal under cybersecurity laws (like the IT Act in India). Our tool is intended for authorized security testing only — penetration testers with client permission, bug bounty programs, and testing your own infrastructure."

**Q: What are the limitations of your tool?**
> "Currently, we cannot scan websites that require login (authenticated scanning) or handle JavaScript-rendered content (SPAs built with React/Angular). These are planned improvements. Time-based blind SQLi detection can also produce false positives on slow networks."

**Q: What would you add next?**
> "1. Login/session support for authenticated scans. 2. Nuclei template-based scanning. 3. API for integration with CI/CD pipelines. 4. Scheduled recurring scans with email alerts."

---

# 📊 ACCURACY RESULTS (Mention in presentation)

| Module | Tests | Pass | Accuracy |
|---|---|---|---|
| Header Scanner | 9 | 9 | 100% |
| XSS Scanner | 2 | 2 | 100% |
| SQL Injection | 2 | 2 | 100% |
| Crawler | 6 | 6 | 100% |
| Tech Fingerprint | 5 | 5 | 100% |
| JS Analyzer | 7 | 7 | 100% |
| Port Scanner | 1 | 1 | 100% |
| DNS Recon | 3 | 3 | 100% |
| SSL Scanner | 4 | 4 | 100% |
| WAF Detector | 2 | 2 | 100% |
| Open Redirect | 3 | 3 | 100% |
| CSRF Scanner | 3 | 3 | 100% |
| **TOTAL** | **47** | **47** | **100%** |

---

# 🔑 KEY TERMS GLOSSARY

| Term | Simple Definition |
|---|---|
| XSS | Injecting JavaScript into a webpage to attack users |
| SQLi | Injecting SQL code into forms to attack the database |
| CSRF | Tricking a browser into making unauthorized requests |
| Open Redirect | Abusing redirect parameters to send users to malicious sites |
| WAF | Firewall that blocks malicious web requests |
| CSP | Content Security Policy — header that restricts what JS can run |
| HSTS | Forces HTTPS connections — prevents downgrade attacks |
| SSL/TLS | Encryption protocol for HTTPS connections |
| CVE | Common Vulnerabilities and Exposures — public vulnerability IDs |
| OWASP | Open Web Application Security Project |
| SSE | Server-Sent Events — one-way real-time data from server to browser |
| Crawler | Bot that automatically visits and maps all pages of a website |
| Payload | Attack string injected to test for vulnerabilities |
| False Positive | Scanner incorrectly flags something safe as vulnerable |
| True Positive | Scanner correctly identifies a real vulnerability |
| SPF | Email DNS record that prevents domain spoofing |
| Penetration Testing | Authorized simulated attack to find vulnerabilities |

---

*Good luck in your viva! Remember: speak confidently, know your own section deeply, and understand the project flow.*
