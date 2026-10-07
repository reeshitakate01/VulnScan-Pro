# VulnScan Pro — Scanner Modules Reference Guide

This document explains every scanner module inside VulnScan Pro in plain English. It covers what the module does, how it works internally, why it matters in the real world, and what it looks for.

---

## Table of Contents
1. [Crawler](#1-crawler)
2. [Header Scanner](#2-header-scanner)
3. [XSS Scanner](#3-xss-scanner-cross-site-scripting)
4. [SQL Injection Scanner](#4-sql-injection-scanner)
5. [DNS Recon](#5-dns-recon)
6. [SSL/TLS Scanner](#6-ssltls-scanner)
7. [Tech Fingerprinter](#7-tech-fingerprinter)
8. [Port Scanner](#8-port-scanner)
9. [JavaScript Analyzer](#9-javascript-analyzer)

---

## 1. Crawler
**File:** `crawler.py`

### What It Does
The Crawler is the **foundation of the entire scanner**. Before any vulnerability can be tested, VulnScan Pro needs to know what pages, forms, and scripts exist on the target website. That's the Crawler's job.

Think of it like a tourist entering a building and methodically mapping every room, window, and door before reporting what's suspicious.

### How It Works
1. You give it a starting URL (e.g., `http://example.com`).
2. Before crawling, it performs two pre-flight recon passes:
   - **`robots.txt` parsing:** It reads the site's robot access rules and harvests any `Disallow` paths as high-value recon targets (hidden admin panels, backup directories, etc.).
   - **Sensitive path probing:** It blindly knocks on common secret doors like `/.env`, `/.git/config`, `/backup.zip`, and `/phpinfo.php` to check if they're exposed.
3. It fetches the starting page, reads all the HTML links, and adds every new same-domain link to a high-performance `deque` queue.
4. It visits each queued link in turn, repeating step 3 on each new page.
5. It continues until it either runs out of new pages, hits `max_pages` (default: 100), or exceeds `max_depth` (default: 3).

While visiting each page, it simultaneously harvests:
- All forms and their input fields, including `<button>` elements (passed to XSS and SQLi scanners)
- External script URLs (passed to the JS Analyzer)
- Inline `<script>` blocks scanned for hardcoded secrets (`api_key`, `token`, `password`, `secret`)
- HTML comments scanned for sensitive info the developer forgot
- Email addresses embedded in the page text
- Security headers present or missing per page (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`)
- `<meta>` tags for tech-stack fingerprinting hints (`generator`, `author`, `framework`)

### Why It Stands Out
Most basic scanners just check the homepage. VulnScan Pro's Crawler intelligently walks the entire site surface before testing anything — this means it catches vulnerabilities on secondary pages like `/profile`, `/search`, and `/admin/login` that a shallow scanner would completely miss.

**Key Technical Features:**
- Uses `collections.deque` (not a list) for O(1) efficient queue performance — critical for large sites with thousands of URLs
- Uses a `queued` tracking set to prevent duplicate URL fetching before they're even visited, preventing memory bloat
- `normalize_url()` strips trailing slashes and `#fragments` using `urllib.parse`, so `/page/` and `/page#section` are correctly treated as the same URL
- Rate limiting via configurable `delay` parameter (with randomized jitter) to avoid triggering anti-bot WAF systems
- Respects `max_pages` to prevent runaway scans on huge, flat sites
- Robust error handling — `Timeout`, `ConnectionError`, and generic exceptions are caught and reported in a structured `errors` array instead of being silently swallowed

**Function Signature:**
```python
def run_crawler(start_url, max_depth=3, max_pages=100, delay=0, respect_robots=False, probe_paths=True)
```

---

## 2. Header Scanner
**File:** `header_scanner.py`

### What It Does
The Header Scanner checks whether the target website is sending the right **security instructions** to your browser. These instructions are called HTTP security headers, and most modern browsers enforce them to protect users.

### How It Works
It makes a single HTTP `GET` request to the target URL and inspects the response headers. For each key security header, it checks whether it's present, and if present, whether its value is configured correctly.

**Headers it checks:**
| Header | What It Does |
|---|---|
| `Content-Security-Policy` | Prevents XSS by controlling which scripts can execute |
| `Strict-Transport-Security` | Forces browsers to use HTTPS only |
| `X-Frame-Options` | Blocks clickjacking attacks |
| `X-Content-Type-Options` | Prevents MIME-type sniffing |
| `X-XSS-Protection` | Legacy XSS filter for older browsers |
| `Referrer-Policy` | Controls what URL info is shared on navigation |
| `Permissions-Policy` | Restricts access to camera, mic, geolocation |
| `Cache-Control` | Prevents caching of sensitive pages |

It also checks cookies — specifically whether session cookies are missing the `Secure` and `HttpOnly` flags (which would expose them to script theft).

### Why It Stands Out
This is one of the cheapest fixes in all of web security, yet the vast majority of websites get it wrong. A missing `Content-Security-Policy` alone makes XSS attacks far easier to execute. This scanner catches every single misconfiguration in one request.

---

## 3. XSS Scanner (Cross-Site Scripting)
**File:** `xss_scanner.py`

### What It Does
The XSS Scanner tries to trick a website into **rendering malicious JavaScript** that was submitted through a form. If it succeeds, it means a real attacker could steal user session cookies, deface the page, or redirect victims to phishing sites.

### How It Works
1. It receives a list of forms discovered by the Crawler.
2. For each form, it identifies the most likely "victim" input field (the one that is probably reflected back in the page).
3. It submits each of its **32 carefully crafted XSS payloads** one at a time through those inputs.
4. It reads the response and checks whether the payload survived HTML encoding — meaning the characters `<`, `>`, `"`, `'` are still literally present in the page rather than being converted to safe HTML entities like `&lt;` or `&gt;`.

**Payload categories it tests:**
- Classic `<script>alert(1)</script>` tags
- Event handler injections (`<img onerror=alert(1)>`, `<svg onload=...>`)
- Case bypass tricks (`<ScRiPt>`, `<IMG OnErRoR=...>`)
- Quote & encoding bypasses
- JavaScript URI injections (`javascript:alert(1)`)
- HTML5 vector exploits
- Polyglot payloads (trigger across multiple contexts)

### Why It Stands Out
The key improvement over basic scanners is the **intelligence of the detection logic**. A naive scanner just checks "is the payload string in the response?" — which triggers false positives constantly when websites echo back your input inside a safe escaping context. VulnScan Pro's scanner specifically verifies that the HTML-special characters remained unescaped, meaning actual code injection could occur.

---

## 4. SQL Injection Scanner
**File:** `sql_injection.py`

### What It Does
The SQLi Scanner is a **multi-vector SQL injection detection engine** that attempts to inject SQL commands into every testable parameter on a website. If the website passes these inputs directly into a database query (without sanitizing them), the query can be manipulated — potentially exposing all user records, passwords, or even allowing the attacker to delete the database.

### How It Works
The scanner operates in three distinct phases for every testable parameter:

**Phase A — Error-Based Detection:**
1. It receives the list of forms from the Crawler, plus any URL with query parameters.
2. For each input field in each form, it **individually isolates** that parameter by filling all other fields with safe mock data (`"test"`).
3. It submits payloads from three categories (error-based, union-based, stacked queries) and checks if the response contains database error strings.
4. It scans against a comprehensive `SQL_ERRORS` dictionary covering **6 database engines**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and Generic patterns.
5. HTTP 500 errors are **only** flagged if the response body also contains SQL-related keywords (e.g., `syntax`, `query`, `database`) — preventing false positives from generic server crashes.

**Phase B — Time-Based Blind Detection:**
1. When the application hides all error messages (which most production apps do), the scanner injects `SLEEP()` commands (e.g., `1' AND SLEEP(6)-- -` for MySQL, `pg_sleep(6)` for PostgreSQL).
2. It measures the response time using `time.time()`. A normal request takes ~100ms. If the response takes exactly 6 seconds, the database executed our command.
3. The detection threshold is set to `>= 5.5 seconds` (6s sleep minus 0.5s network tolerance) to eliminate false positives from slow networks.

**Phase C — Boolean-Based Blind Detection:**
1. When neither errors nor timing anomalies work, the scanner sends paired conditions: a TRUE statement (`1' AND '1'='1`) and a FALSE statement (`1' AND '1'='2`).
2. It compares the `len()` of both HTML responses. If the TRUE condition returns significantly more content (>50 character difference), the database is responding to our boolean logic.

**URL Parameter Testing:**
Beyond HTML forms, the scanner also independently fuzzes standard GET query parameters (e.g., `?id=1&category=books`) through its dedicated `test_url_params()` function.

### Why It Stands Out
SQL Injection remains the #1 most exploited web vulnerability (OWASP Top 10 for over a decade). VulnScan Pro's scanner goes far beyond basic error-grepping:

- **Per-parameter isolation:** Tests every single input independently, pinpointing exactly which field is vulnerable
- **6 detection techniques:** Error-based, Union-based, Stacked queries, Time-based Blind, Boolean Blind, and URL parameter fuzzing
- **Multi-database awareness:** Recognizes error patterns from MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and generic SQL engines
- **Rich metadata:** Every finding includes the detection `type`, inferred `db_type`, exact `payload`, `evidence`, HTTP `status_code`, and `response_length`
- **Smart 500 handling:** Generic HTTP 500 crashes are NOT automatically flagged — only when the response body contains database-related syntax hints

**Function Signature:**
```python
def run_sqli_scan(forms, url=None, blind=True, boolean_blind=True, timeout=8, test_all_params=True)
```

---

## 5. DNS Recon
**File:** `dns_scanner.py`

### What It Does
The DNS Recon module performs **deep investigation of a domain's DNS configuration**. DNS (Domain Name System) is like the internet's phone book — it translates `example.com` into a server's IP address. But DNS records contain far more than just IPs, and understanding them reveals a huge amount about a target's infrastructure.

### How It Works
The module uses a centralized `build_resolver(timeout)` to create a single, timeout-enforced DNS resolver shared across all queries, preventing any individual lookup from hanging indefinitely.

It queries both the `www.` variant and the bare domain simultaneously, merging results to ensure no records are missed. For each record type, it captures both the values and the **TTL** (Time-To-Live), which reveals caching behavior and can hint at CDN or failover usage.

**Records it queries:**

| Record | What It Reveals |
|---|---|
| `A` / `AAAA` | IPv4 and IPv6 addresses of the server (with TTL) |
| `MX` | Mail server hostnames — **automatically resolved to their IPs** |
| `NS` | Authoritative name servers (with fallback to parent domain) |
| `TXT` | SPF, DKIM, DMARC email security policies |
| `CNAME` | Alias records pointing to other domains |
| `SOA` | Primary nameserver and admin email |
| `CAA` | Which Certificate Authorities are allowed to issue SSL certs |
| `SRV` | Services running (LDAP, SIP, XMPP) |

Beyond basic records, it performs several advanced recon steps:
- **Reverse DNS (PTR):** Takes discovered `A` record IPs and performs reverse lookups using `dns.reversename.from_address()` — can reveal shared hosting, CDN providers, or internal server names.
- **Subdomain Enumeration:** Brute-forces 22 common prefixes (`admin`, `dev`, `api`, `staging`, `vpn`, `cdn`, `beta`, etc.) to discover unlisted portals via `A` record resolution.
- **SPF Analysis Engine:** Doesn't just store the raw SPF string — it runs `analyze_spf()` which flags `+all` (CRITICAL: anyone can spoof), `~all` (WARN: softfail not enforced), `?all` (WARN: neutral), and checks for strict `-all` enforcement.
- **DKIM Probing:** Iterates through 9 common selector names (`default`, `google`, `mail`, `selector1`, `k1`, etc.) to actively locate valid DKIM signing records.
- **MX Resolution:** For every MX hostname discovered, it performs a secondary `A` record lookup to map the physical IP address of each mail server.
- **Zone Transfer Test (AXFR):** Checks if any discovered NS server accidentally allows a full zone transfer, exposing the entire DNS database. Uses the shared resolver's strict timeout to prevent hanging.

### Why It Stands Out
DNS recon is typically siloed into separate tools (Amass for subdomains, dig for records, mail-tester for SPF). VulnScan Pro combines passive record gathering, active subdomain fuzzing, email security auditing (SPF/DKIM/DMARC), reverse DNS correlation, and zone transfer testing all in one unified module with tight timeout controls so it never hangs.

**Additional differentiators:**
- Queries both `www.` and base domain, merging results to prevent missed records
- Captures TTL values alongside records to reveal infrastructure patterns
- NS fallback logic correctly placed outside the query loop (not re-checked on every record type)
- All DNS operations share a single configured resolver with strict lifetime/timeout enforcement

**Function Signature:**
```python
def run_dns_recon(url, timeout=3, enumerate_subs=True, attempt_zone_transfer=True, probe_dkim=True)
```

---

## 6. SSL/TLS Scanner
**File:** `ssl_scanner.py`

### What It Does
The SSL/TLS Scanner checks the health, validity, and configuration of the target's HTTPS certificate. HTTPS is what puts the padlock in your browser and encrypts traffic so it cannot be snooped or tampered with in transit.

### How It Works
1. It uses Python's `ssl.create_default_context()` — the same mechanism your browser uses — to verify the certificate chain against the system's trusted Certificate Authority (CA) store.
2. If the certificate passes this check, it is marked **valid**. If it fails (expired, self-signed, hostname mismatch), it's marked **invalid**.
3. In a separate pass using an inspection-only context (`CERT_NONE`), it extracts metadata like the expiry date, issuer, subject, and supported cipher suites — even from bad certificates.

### Why It Stands Out
Previous naive implementations manually compared certificate strings, which caused false positives on every valid certificate from trusted CAs like Let's Encrypt. By delegating validation to Python's system-level SSL context, VulnScan Pro uses the exact same validation logic your browser does — zero false positives.

---

## 7. Tech Fingerprinter
**File:** `tech_fingerprint.py`

### What It Does
The Tech Fingerprinter identifies **what software and frameworks power the target website**, then cross-references those versions against a built-in CVE (Common Vulnerabilities and Exposures) database to find known security flaws.

### How It Works
It looks in several places simultaneously:
- **Response Headers:** `Server: nginx/1.18.0`, `X-Powered-By: PHP/7.4.3`
- **HTML Meta Tags:** `<meta name="generator" content="WordPress 5.8.2">`
- **JavaScript Patterns:** Looking for version strings in jQuery, React, Angular, etc.
- **Favicon Hash:** Calculates the hash of `/favicon.ico` and compares it against a dictionary of known framework favicons (e.g., default WordPress, Laravel, Tomcat icons).

After identifying a technology, it checks its internal database to find officially published CVEs for that exact version.

### Why It Stands Out
A website might be perfectly coded from scratch, but if it's running on an outdated version of nginx or WordPress, a publicly known exploit might be usable against it. This module catches those "supply chain" vulnerabilities that the application developer can't even fix themselves — they need to update their dependencies.

---

## 8. Port Scanner
**File:** `port_scanner.py`

### What It Does
The Port Scanner checks which **network ports are accepting connections** on the target server. Every internet service runs on a specific port — web traffic uses port 80 and 443, databases might use 3306 (MySQL) or 5432 (Postgres), Redis uses 6379, etc.

### How It Works
It attempts a TCP connection to a curated list of commonly exposed ports on the target's IP address. If the connection succeeds, the port is "open." It then maps the port number to a known service name and assigns a risk level based on whether that service type should be exposed to the public internet.

**Risk assessment logic:**
- High-risk open ports: Redis (6379), MongoDB (27017), Elasticsearch (9200) — databases that are frequently left unprotected
- Medium-risk: FTP (21), Telnet (23), SMB (445) — legacy protocols known for vulnerabilities
- Info: standard web ports (80, 443, 8080)

### Why It Stands Out
A common real-world breach scenario is not vulnerabilities in the web app itself — it's a developer accidentally leaving a database port open to the internet. The port scanner specifically prioritizes those "forgotten" service ports and flags them at high severity.

---

## 9. JavaScript Analyzer
**File:** `js_analyzer.py`

### What It Does
The JavaScript Analyzer downloads and scans all the `.js` files discovered by the Crawler, hunting for **accidentally hardcoded secrets** — API keys, tokens, passwords, and internal infrastructure references that were never meant to be public.

### How It Works
It fetches each JavaScript URL, then runs a bank of `regex` patterns against the source code, looking for:

| Pattern | Example Match |
|---|---|
| AWS Access Keys | `AKIAIOSFODNN7EXAMPLE` |
| GitHub Tokens | `ghp_AbCdEfGhIjKlMnOpQrSt` |
| Generic Secrets | `password = "SuperSecret123"` |
| API Endpoints | `/api/v1/internal/users` |
| Internal IPs | `192.168.1.100`, `10.0.0.1` |
| Localhost References | `http://localhost:5432` |
| TODO Comments | `// TODO: remove this token before prod!` |

### Why It Stands Out
Hardcoded credentials in JavaScript files are one of the most common findings in real-world bug bounties. Since `.js` files are sent directly to every single visitor's browser, any secret inside them is fully public — even if the page itself requires a login. This scanner finds those secrets before attackers do.

---

## How They Work Together

VulnScan Pro runs these modules in a deliberate pipeline:

```
URL Input
    ↓
Crawler (maps the entire site surface)
    ↓
  ┌───────────────────────────────────────────────┐
  │ Forms → XSS Scanner                           │
  │ Forms → SQLi Scanner                          │
  │ JS URLs → JavaScript Analyzer                 │
  └───────────────────────────────────────────────┘
    ↓ (parallel, independent)
  ┌───────────────────────────────────────────────┐
  │ Header Scanner                                │
  │ SSL/TLS Scanner                               │
  │ DNS Recon                                     │
  │ Tech Fingerprinter                            │
  │ Port Scanner                                  │
  └───────────────────────────────────────────────┘
    ↓
Score Engine (aggregates all findings into a security score / grade)
    ↓
PDF Report Generator
```

No single module gives you the full picture. The power of VulnScan Pro is in their **synchronized, orchestrated execution** — every vulnerability class gets tested simultaneously so you receive a complete, actionable security assessment in a single report.
