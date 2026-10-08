import os
import uuid
import threading
import json
import time
from datetime import datetime
from flask import (
    Flask, request, jsonify, Response, send_file, render_template,
    send_from_directory, redirect, url_for, flash,
)
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
import logging

from config import config
from scanner.safe_requests import validate_target

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
app = Flask(__name__,
            template_folder=os.path.join(base_dir, 'frontend'),
            static_folder=os.path.join(base_dir, 'frontend', 'static'))
app.secret_key = config.SECRET_KEY

# CORS is OFF by default (same-origin). Previously `CORS(app)` allowed ANY
# origin to call the API, letting any website drive scans via a victim's
# browser. Enable explicitly with the CORS_ORIGINS env var when needed.
if config.CORS_ORIGINS:
    CORS(app, origins=config.CORS_ORIGINS)

app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Harden the session cookie (defence-in-depth against CSRF/theft).
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Bounded worker pool: cap simultaneous scans so a burst of requests cannot
# exhaust threads/sockets. Acquired by each scan thread, released when done.
scan_semaphore = threading.BoundedSemaphore(config.MAX_CONCURRENT_SCANS)

# Ensure the reports directory exists at import time too, so it is created
# under gunicorn (which never runs the __main__ block below).
os.makedirs(os.path.join(base_dir, 'reports'), exist_ok=True)

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@login_manager.unauthorized_handler
def _unauthorized():
    # API callers get a clean 401; browsers are redirected to the login page.
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Authentication required'}), 401
    return redirect(url_for('login', next=request.path))


class ScanTask(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    status = db.Column(db.String(50), default='pending') # pending, running, completed, error
    score = db.Column(db.Integer, nullable=True)
    grade = db.Column(db.String(5), nullable=True)
    summary = db.Column(db.Text, nullable=True)
    results_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)

class ScanEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey('scan_task.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    message = db.Column(db.String(1024), nullable=False)

with app.app_context():
    db.create_all()

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

def log_event(app_context, scan_id, message):
    with app_context:
        event = ScanEvent(scan_id=scan_id, message=message)
        db.session.add(event)
        db.session.commit()

# --- Orchestration ---
def bg_run_scan(scan_id, url, selected_modules, webhook_url=None, email=None):
    from scanner.port_scanner import run_port_scan
    from scanner.header_scanner import run_header_scan
    from scanner.dns_scanner import run_dns_recon
    from scanner.crawler import run_crawler
    from scanner.xss_scanner import run_xss_scan
    from scanner.sql_injection import run_sqli_scan
    from scanner.ssl_scanner import run_ssl_scan
    from scanner.tech_fingerprint import run_tech_fingerprint
    from scanner.waf_detector import run_waf_detection
    from scanner.open_redirect import run_open_redirect_scan
    from scanner.csrf_scanner import run_csrf_scan
    from scanner.score_engine import calculate_score
    from scanner.owasp_mapper import OWASPMapper
    from scanner.time_estimator import TimeEstimator
    from report.pdf_generator import generate_pdf
    app_context = app.app_context()

    # Acquire immediately before the try so the finally-release always pairs
    # with it (nothing that can raise sits between acquire and try).
    scan_semaphore.acquire()
    try:
        log_event(app_context, scan_id, f"Started scanning {url}")
        results = {}

        # ── WAF Detection (always runs first so other modules can note it) ──
        if "WAF Detection" in selected_modules:
            log_event(app_context, scan_id, "Detecting WAF / CDN...")
            results["waf"] = run_waf_detection(url)
            waf_name = results["waf"].get("waf_name") or "None detected"
            log_event(app_context, scan_id, f"WAF detection complete. WAF: {waf_name}")

        # Ports
        if "Port Scan" in selected_modules:
            log_event(app_context, scan_id, "Scanning ports...")
            results["port_scan"] = run_port_scan(url)
            log_event(app_context, scan_id, "Port scan complete.")
            
        # Headers
        if "Security Headers" in selected_modules:
            log_event(app_context, scan_id, "Scanning security headers...")
            results["headers"] = run_header_scan(url)
            log_event(app_context, scan_id, "Header scan complete.")
            
        # SSL
        if "SSL/TLS" in selected_modules:
            log_event(app_context, scan_id, "Scanning SSL/TLS config...")
            results["ssl"] = run_ssl_scan(url)
            log_event(app_context, scan_id, "SSL scan complete.")
            
        # DNS
        if "DNS Recon" in selected_modules:
            log_event(app_context, scan_id, "Enumerating DNS records...")
            results["dns"] = run_dns_recon(url)
            log_event(app_context, scan_id, "DNS recon complete.")
            
        # Tech Fingerprint
        if "Tech Fingerprinting" in selected_modules:
            log_event(app_context, scan_id, "Fingerprinting technologies...")
            results["tech"] = run_tech_fingerprint(url)
            log_event(app_context, scan_id, "Tech fingerprinting complete.")
            
        # Crawler (Dependency for XSS and SQLi and JS Analyzer)
        forms_found = []
        js_urls = []
        if any(m in selected_modules for m in ["Crawler", "XSS", "SQL Injection", "JavaScript Analysis"]):
            log_event(app_context, scan_id, "Crawling website...")
            crawler_res = run_crawler(url, max_depth=2)
            if "Crawler" in selected_modules:
                results["crawler"] = crawler_res
            forms_found = crawler_res.get("forms", [])
            js_urls = crawler_res.get("external_scripts", [])
            log_event(app_context, scan_id, f"Crawling complete. Found {len(forms_found)} forms, {len(js_urls)} scripts.")
            
        # XSS
        if "XSS" in selected_modules and forms_found:
            log_event(app_context, scan_id, "Testing for XSS...")
            results["xss"] = run_xss_scan(forms_found)
            log_event(app_context, scan_id, "XSS testing complete.")
            
        # SQLi
        if "SQL Injection" in selected_modules and forms_found:
            log_event(app_context, scan_id, "Testing for SQL Injection...")
            results["sqli"] = run_sqli_scan(forms_found)
            log_event(app_context, scan_id, "SQL Injection testing complete.")
            
        # JS Analysis
        if "JavaScript Analysis" in selected_modules and js_urls:
            log_event(app_context, scan_id, "Analyzing JavaScript files...")
            from scanner.js_analyzer import JSAnalyzer
            analyzer = JSAnalyzer()
            results["js_analysis"] = analyzer.analyze(js_urls, url)
            log_event(app_context, scan_id, "JavaScript analysis complete.")

        # Open Redirect (reuses crawler data)
        if "Open Redirect" in selected_modules:
            log_event(app_context, scan_id, "Testing for Open Redirect vulnerabilities...")
            crawled_urls = []
            if "crawler" in results:
                crawled_urls = [results["crawler"].get("start_url", url)]
            results["open_redirect"] = run_open_redirect_scan(
                urls=crawled_urls if crawled_urls else [url],
                forms=forms_found,
            )
            or_count = len(results["open_redirect"])
            log_event(app_context, scan_id, f"Open Redirect scan complete. {or_count} finding(s).")

        # CSRF (reuses crawler data)
        if "CSRF Detection" in selected_modules:
            log_event(app_context, scan_id, "Testing for CSRF vulnerabilities...")
            results["csrf"] = run_csrf_scan(forms=forms_found, base_url=url)
            csrf_count = len(results["csrf"])
            log_event(app_context, scan_id, f"CSRF scan complete. {csrf_count} finding(s).")

        # CORS Misconfiguration (read-only cross-origin probe)
        if "CORS" in selected_modules:
            log_event(app_context, scan_id, "Checking CORS configuration...")
            from scanner.cors_scanner import run_cors_scan
            results["cors"] = run_cors_scan(url)
            log_event(app_context, scan_id, "CORS check complete.")

        # HTTP Methods / XST (OPTIONS + TRACE only, non-destructive)
        if "HTTP Methods" in selected_modules:
            log_event(app_context, scan_id, "Enumerating HTTP methods...")
            from scanner.http_methods_scanner import run_http_methods_scan
            results["http_methods"] = run_http_methods_scan(url)
            log_event(app_context, scan_id, "HTTP methods check complete.")

        # Recon / best-practice files (security.txt)
        if "Recon" in selected_modules:
            log_event(app_context, scan_id, "Running recon checks...")
            from scanner.recon_scanner import run_recon_scan
            results["recon"] = run_recon_scan(url)
            log_event(app_context, scan_id, "Recon checks complete.")

        # Scoring Let's score all modules uniformly
        log_event(app_context, scan_id, "Calculating security score...")
        score_data = calculate_score(results)
        
        # Format for PDF
        pdf_data = {
            "url": url,
            "date": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            "score": score_data["score"],
            "grade": score_data["grade"],
            "summary": score_data["summary_text"],
            "modules": {}
        }
        
        # Flatten findings for PDF
        all_flattened_findings = []
        for mod, mod_res in results.items():
            mod_findings = []
            if mod in ("cors", "http_methods", "recon") and isinstance(mod_res, list):
                # Unified shape: {title, severity, description, recommendation,
                # vulnerable, finding_key}. Skip purely-informational "all clear"
                # rows so they don't pollute the findings/OWASP views.
                for item in mod_res:
                    if not item.get("vulnerable") and not item.get("finding_key"):
                        continue
                    mod_findings.append({
                        "Finding": item.get("title", "Finding"),
                        "Severity": item.get("severity", "INFO"),
                        "Description": item.get("description", ""),
                        "Recommendation": item.get("recommendation", ""),
                        "finding_key": item.get("finding_key"),
                    })
            elif isinstance(mod_res, list):
                for item in mod_res:
                    if "port" in item:
                        mod_findings.append({
                            "Finding": f"Port {item.get('port')} open",
                            "Severity": item.get('risk_level', 'INFO'),
                            "Description": f"Service: {item.get('service')}",
                            "Recommendation": "Close port if not needed." if item.get('risk_level') != 'INFO' else ""
                        })
                    elif "header" in item:
                        mod_findings.append({
                            "Finding": item.get('header'),
                            "Severity": item.get('severity', 'INFO'),
                            "Description": "Present" if item.get('present') else "Missing",
                            "Recommendation": item.get('recommendation', '')
                        })
                    elif "vulnerable" in item: # XSS / SQLi / Open Redirect / CSRF
                        vuln_type = item.get("type", "")
                        if "Open Redirect" in vuln_type:
                            sev = item.get("severity", "HIGH")
                            mod_findings.append({
                                "Finding": f"Open Redirect at {item.get('url')}",
                                "Severity": sev,
                                "Description": f"Param '{item.get('parameter')}' redirects to external domain. {item.get('evidence', '')}",
                                "Recommendation": item.get("recommendation", "Validate redirect targets against an allowlist.")
                            })
                        elif "CSRF" in vuln_type:
                            sev = item.get("severity", "HIGH")
                            mod_findings.append({
                                "Finding": f"CSRF vulnerability at {item.get('url')}",
                                "Severity": sev,
                                "Description": item.get("evidence", "POST form lacks CSRF token."),
                                "Recommendation": item.get("recommendation", "Add CSRF tokens to all state-changing forms.")
                            })
                        else:
                            mod_findings.append({
                                "Finding": f"Vuln at {item.get('url')}",
                                "Severity": "CRITICAL" if "SQL" in str(item.get('evidence')) else "HIGH",
                                "Description": f"Param {item.get('parameter')} vulnerable to payload {item.get('payload')}",
                                "Recommendation": "Sanitize inputs and use prepared statements."
                            })
            else: # Dictionary results
                if mod == "ssl":
                    if not mod_res.get("cert_valid"):
                        mod_findings.append({"Finding": "Invalid Cert", "Severity": "HIGH", "Description": "Cert is expired or invalid", "Recommendation": "Renew cert"})
                    if mod_res.get("weak_ciphers"):
                        mod_findings.append({"Finding": "Weak Ciphers", "Severity": "MEDIUM", "Description": "Server supports weak ciphers", "Recommendation": "Upgrade cipher suites"})
                elif mod == "tech":
                    for t in mod_res.get("technologies", []):
                        if t.get("cves_found"):
                            mod_findings.append({
                                "Finding": f"Vulnerable component {t.get('name')} {t.get('version')}",
                                "Severity": "HIGH",
                                "Description": f"CVEs: {', '.join(t.get('cves_found'))}",
                                "Recommendation": "Update component"
                            })
                    favicon = mod_res.get("favicon", {})
                    if favicon.get("match"):
                        mod_findings.append({
                            "Finding": f"Default Favicon: {favicon['match']}",
                            "Severity": "LOW",
                            "Description": f"Hash: {favicon['hash']}",
                            "Recommendation": "Replace default favicon to prevent fingerprinting"
                        })
                    elif favicon.get("hash"):
                        mod_findings.append({
                            "Finding": "Favicon Hash info",
                            "Severity": "INFO",
                            "Description": f"Hash: {favicon['hash']} (Unknown match)",
                            "Recommendation": ""
                        })
                elif mod == "dns":
                    if not (mod_res.get("spf_analysis") or {}).get("exists"):
                        mod_findings.append({"Finding": "Missing SPF", "Severity": "MEDIUM", "Description": "No SPF record found", "Recommendation": "Add SPF record"})
                    if not mod_res.get("dmarc"):
                        mod_findings.append({"Finding": "Missing DMARC", "Severity": "MEDIUM", "Description": "No DMARC record found", "Recommendation": "Add a DMARC policy record"})
                elif mod == "waf":
                    if mod_res.get("waf_detected"):
                        mod_findings.append({
                            "Finding": f"WAF Detected: {mod_res.get('waf_name', 'Unknown')}",
                            "Severity": "INFO",
                            "Description": f"Confidence: {mod_res.get('confidence')}. {'; '.join(mod_res.get('evidence', [])[:2])}",
                            "Recommendation": "A WAF is a positive control. Ensure it is correctly tuned and bypass-resistant."
                        })
                    else:
                        mod_findings.append({
                            "Finding": "No WAF Detected",
                            "Severity": "MEDIUM",
                            "Description": "No Web Application Firewall was detected in front of this application.",
                            "Recommendation": "Consider deploying a WAF (e.g. Cloudflare, AWS WAF, ModSecurity) for an additional layer of defence."
                        })
                elif mod == "js_analysis":
                    if "findings" in mod_res:
                        for f in mod_res["findings"]:
                            mod_findings.append({
                                "Finding": f.get("Finding", "JS Insight"),
                                "Severity": f.get("Severity", "INFO"),
                                "Description": f.get("Description", ""),
                                "Recommendation": f.get("Recommendation", "")
                            })
            
            all_flattened_findings.extend(mod_findings)
            pdf_data["modules"][mod] = mod_findings
            
        log_event(app_context, scan_id, "Enriching findings with OWASP mapping...")
        mapper = OWASPMapper()
        mapper.enrich_all(all_flattened_findings) # Modifies dicts in-place
        pdf_data["owasp_summary"] = mapper.generate_owasp_summary(all_flattened_findings)
            
        log_event(app_context, scan_id, "Generating PDF report...")
        generate_pdf(scan_id, pdf_data)
        
        # Save to DB
        with app_context:
            task = ScanTask.query.get(scan_id)
            task.status = 'completed'
            task.score = score_data['score']
            task.grade = score_data['grade']
            task.summary = score_data['summary_text']
            task.results_json = json.dumps({
                "raw_results": results,
                "score_data": score_data,
                "pdf_data": pdf_data
            })
            db.session.commit()
            
        log_event(app_context, scan_id, "Scan Complete.")
        
        if webhook_url or email:
            from notifier import ScanNotifier
            notifier = ScanNotifier()
            log_event(app_context, scan_id, "Sending notifications...")
            if webhook_url:
                notifier.send_slack_webhook(webhook_url, scan_id, url, score_data['score'], score_data['grade'])
            if email:
                notifier.send_email_report(email, scan_id, url, score_data['score'], score_data['grade'], score_data["summary_text"])
        
    except Exception as e:
        with app_context:
            task = ScanTask.query.get(scan_id)
            task.status = 'error'
            task.summary = f"Scan failed due to an internal error: {str(e)}"
            db.session.commit()
        log_event(app_context, scan_id, f"Error: {str(e)}")
    finally:
        scan_semaphore.release()

# --- Auth ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        if not email or not password:
            flash('Email and password are required.', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
        elif User.query.filter_by(email=email).first():
            flash('An account with that email already exists.', 'error')
        else:
            user = User(email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            nxt = request.args.get('next')
            # Only allow local redirects (open-redirect guard).
            if nxt and nxt.startswith('/') and not nxt.startswith('//'):
                return redirect(nxt)
            return redirect(url_for('index'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# --- Pages ---
@app.route('/')
@login_required
def index():
    return render_template('index.html', user_email=current_user.email)

@app.route('/results/<scan_id>')
@login_required
def results_page(scan_id):
    scan = ScanTask.query.get_or_404(scan_id)
    if scan.user_id is not None and scan.user_id != current_user.id:
        return jsonify({'error': 'Not found'}), 404
    return render_template('results.html', scan_id=scan_id)

@app.route('/preview')
@login_required
def preview_page():
    return render_template('preview.html')

@app.route('/history')
@login_required
def history_page():
    return render_template('history.html', user_email=current_user.email)


def _owned_scan_or_404(scan_id):
    """Fetch a scan and enforce that it belongs to the current user."""
    scan = ScanTask.query.get_or_404(scan_id)
    if scan.user_id is not None and scan.user_id != current_user.id:
        return None
    return scan


@app.route('/api/scans')
@login_required
def list_scans():
    """The current user's scans, newest first — powers the history dashboard."""
    scans = (ScanTask.query
             .filter_by(user_id=current_user.id)
             .order_by(ScanTask.created_at.desc())
             .limit(100).all())
    return jsonify([{
        'id': s.id,
        'url': s.url,
        'status': s.status,
        'score': s.score,
        'grade': s.grade,
        'created_at': s.created_at.isoformat() if s.created_at else None,
    } for s in scans])

@app.route('/api/scan', methods=['POST'])
@login_required
def start_scan():
    data = request.get_json(silent=True) or {}
    url = data.get('url')
    modules = data.get('modules', [])
    webhook_url = data.get('webhook_url')
    email = data.get('email')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    # SSRF guard: refuse internal/reserved targets unless explicitly allowed.
    ok, reason = validate_target(url)
    if not ok:
        return jsonify({'error': f'Target not allowed: {reason}'}), 400

    scan_id = str(uuid.uuid4())

    new_scan = ScanTask(id=scan_id, url=url, status='running', user_id=current_user.id)
    db.session.add(new_scan)
    db.session.commit()

    threading.Thread(target=bg_run_scan, args=(scan_id, url, modules, webhook_url, email)).start()

    return jsonify({'scan_id': scan_id, 'status': 'running'}), 202

@app.route('/api/estimate', methods=['POST'])
@login_required
def estimate_time():
    data = request.get_json(silent=True) or {}
    selected_modules = data.get('modules', [])
    from scanner.time_estimator import TimeEstimator
    estimator = TimeEstimator()
    estimate = estimator.estimate(selected_modules)
    return jsonify(estimate)

@app.route('/api/scan/<scan_id>/stream')
@login_required
def stream_scan(scan_id):
    if _owned_scan_or_404(scan_id) is None:
        return jsonify({'error': 'Not found'}), 404
    def generate():
        last_event_id = 0
        start_ts = time.time()
        while True:
            if time.time() - start_ts > config.SCAN_MAX_DURATION:
                data = json.dumps({"status": "error", "message": "Scan timed out."})
                yield f"data: {data}\n\n"
                break
            with app.app_context():
                # Poll DB for new events
                events = ScanEvent.query.filter_by(scan_id=scan_id).filter(ScanEvent.id > last_event_id).order_by(ScanEvent.id).all()
                new_events = [(e.id, e.message) for e in events]
                
                # Check if task is done
                task = ScanTask.query.get(scan_id)
                task_status = task.status if task else None
                task_summary = task.summary if task else None
                
            for eid, msg in new_events:
                data = json.dumps({"status": "running", "message": msg})
                yield f"data: {data}\n\n"
                last_event_id = eid
                
            if task_status in ['completed', 'error']:
                msg = "Scan Complete" if task_status == 'completed' else task_summary
                data = json.dumps({"status": task_status, "message": msg})
                yield f"data: {data}\n\n"
                break
                
            time.sleep(1) # Poll interval
            
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/scan/<scan_id>/results')
@login_required
def get_results(scan_id):
    scan = _owned_scan_or_404(scan_id)
    if scan is None:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({
        'id': scan.id,
        'url': scan.url,
        'status': scan.status,
        'score': scan.score,
        'grade': scan.grade,
        'summary': scan.summary,
        'results_json': json.loads(scan.results_json) if scan.results_json else None
    })

def _valid_scan_id(scan_id):
    """Scan IDs are UUID4 strings. Reject anything else so a crafted id can
    never be used to build an unexpected filesystem path."""
    try:
        uuid.UUID(str(scan_id))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


@app.route('/api/report/<scan_id>')
@login_required
def download_report(scan_id):
    if not _valid_scan_id(scan_id):
        return jsonify({'error': 'Invalid scan id'}), 400
    if _owned_scan_or_404(scan_id) is None:
        return jsonify({'error': 'Not found'}), 404
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports'))
    filepath = os.path.join(reports_dir, f"{scan_id}.pdf")
    # Defence in depth: ensure the resolved path stays inside reports/.
    if not os.path.abspath(filepath).startswith(reports_dir + os.sep):
        return jsonify({'error': 'Invalid scan id'}), 400
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return jsonify({'error': 'Report not found'}), 404


def _scan_to_dict(scan):
    return {
        'url': scan.url,
        'score': scan.score,
        'grade': scan.grade,
        'summary': scan.summary,
        'results_json': json.loads(scan.results_json) if scan.results_json else {},
    }


@app.route('/api/report/<scan_id>/json')
@login_required
def download_report_json(scan_id):
    """Structured JSON export for programmatic use."""
    scan = _owned_scan_or_404(scan_id)
    if scan is None:
        return jsonify({'error': 'Not found'}), 404
    from report.exporters import build_json_export
    return jsonify(build_json_export(_scan_to_dict(scan)))


@app.route('/api/report/<scan_id>/sarif')
@login_required
def download_report_sarif(scan_id):
    """SARIF 2.1.0 export (ingestible by GitHub code scanning / CI)."""
    scan = _owned_scan_or_404(scan_id)
    if scan is None:
        return jsonify({'error': 'Not found'}), 404
    from report.exporters import build_sarif
    payload = json.dumps(build_sarif(_scan_to_dict(scan)), indent=2)
    return Response(
        payload,
        mimetype='application/sarif+json',
        headers={'Content-Disposition': f'attachment; filename={scan_id}.sarif'},
    )

if __name__ == '__main__':
    os.makedirs(os.path.join(os.path.dirname(__file__), '..', 'reports'), exist_ok=True)
    app.run(
        debug=config.DEBUG,
        threaded=True,
        host=os.getenv('HOST', '127.0.0.1'),
        port=int(os.getenv('PORT', '5000')),
    )
