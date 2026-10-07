import requests

HEADERS_TO_CHECK = {
    'Content-Security-Policy': {'severity': 'HIGH', 'recommendation': 'Implement CSP to prevent XSS.'},
    'Strict-Transport-Security': {'severity': 'HIGH', 'recommendation': 'Enforce HTTPS connections using HSTS.'},
    'X-Frame-Options': {'severity': 'MEDIUM', 'recommendation': 'Prevent clickjacking by setting to DENY or SAMEORIGIN.'},
    'X-Content-Type-Options': {'severity': 'MEDIUM', 'recommendation': 'Set to nosniff to prevent MIME confusion attacks.'},
    'X-XSS-Protection': {'severity': 'MEDIUM', 'recommendation': 'Enable browser built-in XSS protection (though CSP is preferred).'},
    'Referrer-Policy': {'severity': 'LOW', 'recommendation': 'Control referrer information sent to other sites.'},
    'Permissions-Policy': {'severity': 'LOW', 'recommendation': 'Restrict access to browser features like camera, microphone.'},
    'Cache-Control': {'severity': 'INFO', 'recommendation': 'Ensure sensitive pages are not cached.'}
}

def run_header_scan(url):
    results = []
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        
        for header, info in HEADERS_TO_CHECK.items():
            if header in headers:
                results.append({
                    "header": header,
                    "present": True,
                    "value": headers[header],
                    "severity": "INFO",
                    "recommendation": "Well configured."
                })
            else:
                results.append({
                    "header": header,
                    "present": False,
                    "value": None,
                    "severity": info["severity"],
                    "recommendation": info["recommendation"]
                })
                
        # Check Cookies
        for cookie in response.cookies:
            # We must inspect the cookie flags by looking at the raw Morsel or utilizing reqeusts cookie attributes config
            # Requests cookiejar doesn't expose all flags trivially in a single hit, but we can check the secure/httponly attributes
            c_name = cookie.name
            c_secure = cookie.secure
            c_httponly = cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly')
            # SameSite is tricky to parse from requests cookie object directly, we often have to look at the raw Set-Cookie header
            
            missing_flags = []
            if not c_secure: missing_flags.append('Secure')
            if not c_httponly: missing_flags.append('HttpOnly')
            
            if missing_flags:
                results.append({
                    "header": f"Cookie ({c_name})",
                    "present": False,
                    "value": f"Missing: {', '.join(missing_flags)}",
                    "severity": "MEDIUM",
                    "recommendation": f"Add {', '.join(missing_flags)} flag to cookie {c_name}."
                })
                
        # Parse Set-Cookie for SameSite specifically
        if 'Set-Cookie' in headers:
            if 'SameSite' not in headers['Set-Cookie']:
                results.append({
                    "header": "Cookie (SameSite)",
                    "present": False,
                    "value": None,
                    "severity": "LOW",
                    "recommendation": "Add SameSite attribute to cookies to protect against CSRF."
                })
                
    except Exception as e:
        results.append({
            "header": "Error connecting",
            "present": False,
            "value": str(e),
            "severity": "INFO",
            "recommendation": "Ensure target is reachable."
        })
        
    return results

if __name__ == "__main__":
    # Disable insecure request warning for testing
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print(run_header_scan("http://scanme.nmap.org"))
