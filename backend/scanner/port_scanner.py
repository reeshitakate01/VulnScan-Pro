import socket
import concurrent.futures
from urllib.parse import urlparse

# A representative list of common ports to scan (abbreviated for the top ~100)
# A full 1000 list would be massive here, so we'll use a strong subset.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
    110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP", 
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

# Add more ports to reach a larger number conceptually
for p in range(8000, 8010): COMMON_PORTS.setdefault(p, "HTTP-Alt")
for p in range(27018, 27020): COMMON_PORTS.setdefault(p, "MongoDB-Alt")

DANGEROUS_PORTS = {21, 23, 3306, 5432, 6379, 27017}

def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                risk_level = "HIGH" if port in DANGEROUS_PORTS else "INFO"
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "risk_level": risk_level
                }
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None

def run_port_scan(url):
    results = []
    try:
        parsed = urlparse(url)
        host = parsed.hostname or url

        # Resolve IP to avoid multiple DNS lookups
        host_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return [{"error": f"Could not resolve host: {str(e)}"}]
        
    ports_to_scan = list(COMMON_PORTS.keys())
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, host_ip, port): port for port in ports_to_scan}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
                
    return sorted(results, key=lambda x: x['port'])

if __name__ == "__main__":
    print(run_port_scan("http://scanme.nmap.org"))
