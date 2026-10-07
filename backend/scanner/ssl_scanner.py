import ssl
import socket
import datetime
from urllib.parse import urlparse
import requests

def get_hsts(url):
    try:
        res = requests.get(url, timeout=5, verify=False)
        return 'strict-transport-security' in (k.lower() for k in res.headers.keys())
    except Exception:
        return False

def check_tls_version(domain, port, version):
    context = ssl.SSLContext(version)
    try:
        with socket.create_connection((domain, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return True
    except Exception:
        return False

def run_ssl_scan(url):
    results = {
        "cert_valid": False,
        "expiry_date": None,
        "days_until_expiry": 0,
        "self_signed": False,
        "tls_versions": {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": False, "TLSv1.3": False},
        "weak_ciphers": False, # Naive check
        "hsts_enabled": False,
        "error": None
    }
    
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        results["error"] = "Not an HTTPS URL"
        return results
        
    domain = parsed.hostname or url
    port = parsed.port or 443
    
    # HSTS Check
    results["hsts_enabled"] = get_hsts(url)
    
    # First, validate the cert with a standard secure context
    secure_context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with secure_context.wrap_socket(sock, server_hostname=domain) as ssock:
                results["cert_valid"] = True
    except (ssl.SSLError, ssl.CertificateError) as e:
        results["cert_valid"] = False
        results["error"] = str(e)
    except Exception as e:
        results["cert_valid"] = False
        results["error"] = str(e)

    # Second, inspect the certificate details using an unverified context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE # We want to inspect the cert even if invalid
    
    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_dict = ssock.getpeercert()
                
                # Expiry check
                if cert_dict and 'notAfter' in cert_dict:
                    expiry = datetime.datetime.strptime(cert_dict['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    results["expiry_date"] = expiry.strftime("%Y-%m-%d %H:%M:%S")
                    results["days_until_expiry"] = (expiry - datetime.datetime.utcnow()).days
                    
                # Self-signed naive check: Issuer == Subject
                issuer = dict(x[0] for x in cert_dict.get('issuer', []))
                subject = dict(x[0] for x in cert_dict.get('subject', []))
                if issuer == subject:
                    results["self_signed"] = True
                    
                # Cipher suite
                cipher = ssock.cipher()
                if cipher:
                    # Very naive check for weak ciphers
                    if any(weak in cipher[0].upper() for weak in ['RC4', 'MD5', 'DES', '3DES', 'EXPORT']):
                        results["weak_ciphers"] = True
                        
    except Exception as e:
        if not results["error"]:
            results["error"] = str(e)
        
    # Check TLS versions using specifically configured contexts
    # TLS 1.0 & 1.1 are deprecated and often removed from modern Python/OpenSSL, 
    # making direct testing difficult but we can attempt
    try:
        results["tls_versions"]["TLSv1.2"] = check_tls_version(domain, port, ssl.PROTOCOL_TLSv1_2)
    except AttributeError: pass
    
    try:
        # For python >= 3.6 TLSContext defaults are decent, we can inspect negotiated version
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                version = ssock.version()
                if version in results["tls_versions"]:
                    results["tls_versions"][version] = True
    except Exception:
        pass

    return results

if __name__ == "__main__":
    print(run_ssl_scan("https://scanme.nmap.org"))
