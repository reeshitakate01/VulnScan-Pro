"""
Deliberately Vulnerable Flask Test Server for Backtesting VulnScan Pro.
Runs on 127.0.0.1:9999. DO NOT EXPOSE TO THE INTERNET.
"""
from flask import Flask, request, make_response
import html as html_mod
import threading
import logging

# Suppress Flask/werkzeug output
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

# ─── HOMEPAGE ────────────────────────────────────────────────────────────────
# - No security headers (CSP, HSTS, X-Frame-Options, etc.)
# - Insecure cookie (no Secure, no HttpOnly)
# - Links, forms, HTML comments with sensitive keywords, external JS ref
# - Meta generator tag for tech fingerprinting
# - jQuery 1.12.4 script tag
@app.route('/')
def index():
    resp = make_response(f'''<!DOCTYPE html>
<html>
<head>
    <meta name="generator" content="WordPress 5.8.2">
    <script src="/static/jquery-1.12.4.min.js"></script>
    <script src="/secrets.js"></script>
</head>
<body>
    <h1>Test Vulnerable Site</h1>
    <!-- TODO: remove hardcoded password admin123 before production -->
    <!-- secret api_key = AKIAIOSFODNN7EXAMPLE -->
    <p>Contact: admin@vulntest.local</p>

    <h2>Vulnerable Form (XSS + SQLi)</h2>
    <form action="/vulnerable-form" method="post">
        <input type="text" name="query" />
        <input type="hidden" name="csrf_token" value="fake123" />
        <button type="submit">Search</button>
    </form>

    <h2>Safe Form</h2>
    <form action="/safe-form" method="post">
        <input type="text" name="input" />
        <button type="submit">Submit</button>
    </form>

    <h2>SQLi-Only Form</h2>
    <form action="/sqli-form" method="post">
        <input type="text" name="username" />
        <input type="password" name="password" />
        <button type="submit">Login</button>
    </form>

    <a href="/page2">Page 2</a>
    <a href="/page3">Page 3</a>
</body>
</html>''')

    # Set insecure cookie (no Secure, no HttpOnly flags)
    resp.set_cookie('session_id', 'abc123', httponly=False, secure=False)
    # Deliberately NO security headers
    return resp


# ─── VULNERABLE FORM (Reflects input unescaped → XSS detectable) ────────────
@app.route('/vulnerable-form', methods=['GET', 'POST'])
def vulnerable_form():
    query = request.form.get('query', request.args.get('query', ''))
    # Deliberately reflects input WITHOUT escaping → XSS
    return f'''<html><body>
    <h1>Search Results</h1>
    <p>You searched for: {query}</p>
    <form action="/vulnerable-form" method="post">
        <input type="text" name="query" />
        <button type="submit">Search</button>
    </form>
</body></html>'''


# ─── SAFE FORM (HTML-escapes input → no XSS) ────────────────────────────────
@app.route('/safe-form', methods=['GET', 'POST'])
def safe_form():
    user_input = request.form.get('input', request.args.get('input', ''))
    escaped = html_mod.escape(user_input)
    return f'''<html><body>
    <h1>Safe Output</h1>
    <p>Your input: {escaped}</p>
    <form action="/safe-form" method="post">
        <input type="text" name="input" />
        <button type="submit">Submit</button>
    </form>
</body></html>'''


# ─── SQLI FORM (Returns SQL error strings on malicious input) ────────────────
@app.route('/sqli-form', methods=['GET', 'POST'])
def sqli_form():
    username = request.form.get('username', request.args.get('username', ''))
    # Simulate SQL error on injection attempt
    sqli_indicators = ["'", '"', '--', 'OR', 'UNION', 'SELECT', 'DROP']
    if any(indicator in username.upper() for indicator in sqli_indicators):
        return f'''<html><body>
        <h1>Error</h1>
        <p>You have an error in your SQL syntax; check the manual that corresponds 
        to your MySQL server version for the right syntax to use near 
        '{username}' at line 1</p>
        <p>mysql_fetch_array() expects parameter 1 to be resource</p>
    </body></html>''', 500
    return '<html><body><h1>Login OK</h1></body></html>'


# ─── ADDITIONAL PAGES (for crawler to discover) ─────────────────────────────
@app.route('/page2')
def page2():
    return '''<html><body>
    <h1>Page 2</h1>
    <a href="/">Home</a>
    <a href="/page3">Page 3</a>
    <form action="/vulnerable-form" method="get">
        <input type="search" name="query" />
        <button>Go</button>
    </form>
</body></html>'''


@app.route('/page3')
def page3():
    return '''<html><body>
    <h1>Page 3</h1>
    <a href="/">Home</a>
    <p>Contact: support@vulntest.local</p>
</body></html>'''


# ── OPEN REDIRECT (blindly follows the `next` parameter) ─────────────────────
@app.route('/login')
def login_redirect():
    """Simulates a login page that performs an open redirect via `next` param."""
    next_url = request.args.get('next', '/')
    # Deliberately does NOT validate the redirect target
    from flask import redirect
    return redirect(next_url, code=302)


# ── CSRF-LESS FORM (POST form with no CSRF token) ─────────────────────────────
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    """Simulates a sensitive state-changing action with no CSRF protection."""
    if request.method == 'POST':
        amount = request.form.get('amount', '')
        account = request.form.get('account', '')
        return f'<html><body><p>Transferred {amount} to {account}</p></body></html>'
    return '''<html><body>
    <h1>Transfer Funds</h1>
    <form action="/transfer" method="post">
        <input type="text" name="amount" placeholder="Amount" />
        <input type="text" name="account" placeholder="Account" />
        <button type="submit">Transfer</button>
    </form>
</body></html>'''


# ── CSRF-PROTECTED FORM (has a proper CSRF token) ─────────────────────────────
@app.route('/secure-transfer', methods=['GET', 'POST'])
def secure_transfer():
    """Same action but with a CSRF token — should NOT be flagged."""
    return '''<html><body>
    <h1>Secure Transfer</h1>
    <form action="/secure-transfer" method="post">
        <input type="hidden" name="csrf_token" value="a3f5b2c1d4e6a7b8c9d0e1f2a3b4c5d6" />
        <input type="text" name="amount" placeholder="Amount" />
        <input type="text" name="account" placeholder="Account" />
        <button type="submit">Transfer</button>
    </form>
</body></html>'''



# ─── SECRETS.JS (Planted secrets for JS Analyzer) ───────────────────────────
@app.route('/secrets.js')
def secrets_js():
    js_content = '''
// Application configuration
// TODO: clean up this file before release
var config = {
    // AWS credentials (test)
    awsKey: "AKIAIOSFODNN7EXAMPLE1",
    
    // GitHub token
    ghToken: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12",
    
    // API endpoint
    apiBase: "/api/v1/users/profile",
    
    // Internal reference
    debugServer: "http://192.168.1.100:8080/debug",
    localApi: "http://localhost:3000/api",
    
    // password = "SuperSecret123!"
    secret: "hardcoded_api_key_value_1234567890"
};
'''
    return js_content, 200, {'Content-Type': 'application/javascript'}


# ─── STATIC FILE STUBS ──────────────────────────────────────────────────────
@app.route('/static/jquery-1.12.4.min.js')
def jquery_stub():
    return '/* jQuery v1.12.4 stub */', 200, {'Content-Type': 'application/javascript'}


# ─── SERVER CONFIG ───────────────────────────────────────────────────────────
@app.after_request
def set_server_header(response):
    # Fake nginx header for tech fingerprinting
    response.headers['Server'] = 'nginx/1.18.0'
    response.headers['X-Powered-By'] = 'PHP/8.1.0'
    # Deliberately remove all security headers
    for h in ['Content-Security-Policy', 'Strict-Transport-Security',
              'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
              'Referrer-Policy', 'Permissions-Policy']:
        response.headers.pop(h, None)
    return response


def start_server():
    """Start the test server in a background thread."""
    app.run(host='127.0.0.1', port=9999, debug=False, use_reloader=False)


def start_server_thread():
    """Start server in a daemon thread and return the thread."""
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    return t


if __name__ == '__main__':
    print("[*] Starting vulnerable test server on http://127.0.0.1:9999")
    print("[!] DO NOT EXPOSE TO THE INTERNET")
    app.run(host='127.0.0.1', port=9999, debug=False)
