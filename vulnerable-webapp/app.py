import os
import sqlite3
import threading
from flask import Flask, request, make_response, render_template, redirect, session

app = Flask(__name__)
# Secret key for session, deliberately weak
app.secret_key = 'super_secret_key_123'

DB_PATH = os.path.join(os.path.dirname(__file__), 'vulnapp.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ─── MIDDLEWARE (Headers) ───────────────────────────────────────────────────
@app.after_request
def set_headers(response):
    # Missing all security headers natively, but intentionally deleting any that Flask adds
    for h in ['Content-Security-Policy', 'Strict-Transport-Security',
              'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
              'Referrer-Policy', 'Permissions-Policy']:
        response.headers.pop(h, None)
    
    # Intentionally add some tech fingerprints
    response.headers['Server'] = 'VulnerableServer/1.0'
    response.headers['X-Powered-By'] = 'Python/Flask 0.1'
    return response

# ─── ROUTES ─────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    resp = make_response(render_template('index.html'))
    resp.set_cookie('tracking_id', '123456789', httponly=False, secure=False)
    return resp

# 1. XSS Vectors
@app.route('/vulnerable-form', methods=['GET', 'POST'])
def xss_reflected():
    query = request.form.get('query', request.args.get('query', ''))
    return render_template('xss_reflected.html', query=query)

@app.route('/xss-stored', methods=['GET', 'POST'])
def xss_stored():
    conn = get_db()
    
    if request.method == 'POST':
        name = request.form.get('name', 'Anonymous')
        message = request.form.get('message', '')
        # Vuln: Storing without sanitization
        conn.execute('INSERT INTO guestbook (name, message) VALUES (?, ?)', (name, message))
        conn.commit()
        return redirect('/xss-stored')
        
    messages = conn.execute('SELECT * FROM guestbook ORDER BY id DESC').fetchall()
    return render_template('xss_stored.html', messages=messages)

@app.route('/xss-dom')
def xss_dom():
    return render_template('xss_dom.html')

# 2. SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        conn = get_db()
        try:
            # Vuln: String concatenation SQLi
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            user = conn.execute(query).fetchone()
            
            if user:
                return f"Welcome, {user['username']}! Your role is {user['role']}."
            else:
                return "Invalid credentials."
        except sqlite3.Error as e:
            # Vuln: Direct error reflection (helps scanner find SQLi)
            error_msg = str(e)
            # Simulate exactly what the scanner looks for
            if "syntax error" in error_msg.lower():
                return f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{username}' at line 1", 500
            if "unrecognized token" in error_msg.lower():
                return f"sqlite3.OperationalError: unrecognized token: '{username}'", 500
            
            return f"Database Error: {e}", 500
            
    return render_template('login.html')

# 3. CSRF & State Changing
@app.route('/csrf', methods=['GET', 'POST'])
def csrf():
    if request.method == 'POST':
        action = request.form.get('action')
        return f"Action '{action}' executed successfully without a CSRF token."
    return render_template('csrf.html')

# 4. Open Redirect
@app.route('/open-redirect')
def open_redirect():
    url = request.args.get('next')
    if url:
        # Vuln: No validation of redirect URL
        return redirect(url)
    return "Please provide a ?next= URL parameter to redirect."

# 5. File Upload
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file part"
        file = request.files['file']
        if file.filename == '':
            return "No selected file"
        
        # Vuln: Saving immediately without validating extension or type
        upload_dir = os.path.join(os.path.dirname(__file__), 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        save_path = os.path.join(upload_dir, file.filename)
        file.save(save_path)
        return f"File {file.filename} successfully uploaded and executed."
        
    return render_template('upload.html')

# 6. Headers
@app.route('/headers')
def no_headers():
    return "This route intentionally deletes all security headers via the middleware."

# 7. Info Leaks
@app.route('/info-leak')
def info_leak():
    return "Directory listing enabled (simulated). <br><a href='/server-info'>server-info</a><br><a href='/.git/config'>.git/config</a><br><a href='/backup.zip'>backup.zip</a>"

@app.route('/server-info')
def server_info():
    return "SERVER_O.S: Linux, VERSION: 5.4.0-x, APACHE: 2.4.41", 404

@app.route('/.git/config')
def git_config():
    return "[core]\n\trepositoryformatversion = 0\n\tfilemode = true", 404

@app.route('/backup.zip')
def backup_zip():
    return "PK\x03\x04...", 404

# ─── SERVER STARTUP ────────────────────────────────────────────────────────
def run_http():
    print("[*] Starting VulnApp HTTP on port 5001...")
    # debug=False inside threads. Threading handles it gracefully.
    app.run(host='127.0.0.1', port=5001, debug=False, use_reloader=False)

def run_https():
    cert_path = os.path.join(os.path.dirname(__file__), 'cert.pem')
    key_path = os.path.join(os.path.dirname(__file__), 'key.pem')
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print("[-] Missing cert.pem/key.pem. Generating them now...")
        import generate_cert
        generate_cert.generate_self_signed_cert()
        
    print("[*] Starting VulnApp HTTPS on port 5002...")
    context = (cert_path, key_path)
    app.run(host='127.0.0.1', port=5002, ssl_context=context, debug=False, use_reloader=False)

if __name__ == '__main__':
    t1 = threading.Thread(target=run_http)
    t2 = threading.Thread(target=run_https)
    
    t1.start()
    t2.start()
    
    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("\nShutting down.")
