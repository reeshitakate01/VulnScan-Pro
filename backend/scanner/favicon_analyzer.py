import requests
import mmh3
import base64
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class FaviconAnalyzer:

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.timeout = 5
        
        # Extended Favicon Hash DB
        self.favicon_hashes = {
            "116323821": "Spring Framework Default",
            "-1875150244": "Apache Tomcat",
            "2011270213": "XAMPP Default",
            "14506385": "Flask Default Development",
            "-1580220268": "phpMyAdmin",
            "1398055326": "Jenkins",
            "1088998712": "WordPress Default",
            "-431427521": "Kibana",
            "-244067125": "Grafana Default",
            "276413289": "Laravel Default",
            "17855365": "Django Default"
        }

    def analyze(self, base_url: str) -> dict:
        result = {
            "favicon_url": None,
            "hash": None,
            "match": None
        }
        
        try:
            # 1. Try to find the favicon link in HTML
            resp = self.session.get(base_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            icon_link = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
            
            if icon_link and icon_link.get('href'):
                favicon_url = urljoin(base_url, icon_link.get('href'))
            else:
                favicon_url = urljoin(base_url, '/favicon.ico')
                
            result["favicon_url"] = favicon_url
            
            # 2. Download and compute hash
            r = self.session.get(favicon_url, timeout=self.timeout, verify=False)
            if r.status_code == 200:
                favicon_bytes = r.content
                
                # Shodan style murmurhash computation
                favicon_b64 = base64.encodebytes(favicon_bytes)
                hash_val = mmh3.hash(favicon_b64)
                
                result["hash"] = str(hash_val)
                result["match"] = self.favicon_hashes.get(str(hash_val))
                
        except Exception:
            pass
            
        return result
