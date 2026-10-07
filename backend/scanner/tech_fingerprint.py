import requests
from bs4 import BeautifulSoup
import re

# Small dictionary of known CVEs
CVE_DICT = {
    "nginx": {"1.18.0": ["CVE-2021-23017", "CVE-2022-41741"]},
    "apache": {"2.4.49": ["CVE-2021-41773", "CVE-2021-42013"]},
    "wordpress": {"5.8.2": ["CVE-2022-21661", "CVE-2022-21662"]},
    "php": {"8.1.0": ["CVE-2021-21703"]},
    "jquery": {"1.12.4": ["CVE-2015-9251"]},
    "react": {"16.0.0": ["CVE-2018-6341"]}
}

def identify_from_headers(headers):
    techs = []
    
    server = headers.get('Server', '').lower()
    if 'nginx' in server:
        version = server.split('/')[-1] if '/' in server else "unknown"
        techs.append({"name": "nginx", "version": version})
    elif 'apache' in server:
        version = server.split('/')[-1].split(' ')[0] if '/' in server else "unknown"
        techs.append({"name": "apache", "version": version})
    elif 'iis' in server:
        version = server.split('/')[-1] if '/' in server else "unknown"
        techs.append({"name": "iis", "version": version})
        
    x_powered_by = headers.get('X-Powered-By', '').lower()
    if 'php' in x_powered_by:
        version = x_powered_by.split('/')[-1] if '/' in x_powered_by else "unknown"
        techs.append({"name": "php", "version": version})
    elif 'asp.net' in x_powered_by:
        techs.append({"name": "asp.net", "version": "unknown"})
        
    return techs

def identify_from_html(html):
    techs = []
    soup = BeautifulSoup(html, 'html.parser')
    
    # Meta generator
    generator = soup.find('meta', attrs={'name': 'generator'})
    if generator and generator.get('content'):
        content = generator['content'].lower()
        if 'wordpress' in content:
            version = content.split(' ')[-1] if ' ' in content else "unknown"
            techs.append({"name": "wordpress", "version": version})
        elif 'joomla' in content:
            techs.append({"name": "joomla", "version": "unknown"})
        elif 'drupal' in content:
            techs.append({"name": "drupal", "version": "unknown"})
            
    # Known JS framework signatures
    if 'react' in html.lower() or 'data-reactroot' in html.lower():
        # Version extraction is hard without executing JS, assume unknown
        techs.append({"name": "react", "version": "unknown"})
        
    # Script src checking
    script_tags = soup.find_all('script', src=True)
    for tag in script_tags:
        src = tag['src'].lower()
        if 'jquery' in src:
            # Naive version extraction like jquery-3.6.0.min.js
            match = re.search(r'jquery[.-]([\d.]+)\.min\.js', src)
            version = match.group(1) if match else "unknown"
            techs.append({"name": "jquery", "version": version.rstrip('.')})
            
    return techs

def run_tech_fingerprint(url):
    results = {"technologies": []}
    
    try:
        res = requests.get(url, timeout=10, verify=False)
        
        techs = identify_from_headers(res.headers)
        techs.extend(identify_from_html(res.text))
        
        # Deduplicate and check CVEs
        unique_techs = {}
        for t in techs:
            name = t["name"]
            version = t["version"]
            
            cves = []
            if name in CVE_DICT and version in CVE_DICT[name]:
                cves = CVE_DICT[name][version]
                
            t["cves_found"] = cves
            
            if name not in unique_techs or unique_techs[name]["version"] == "unknown":
                unique_techs[name] = t
                
        results["technologies"] = list(unique_techs.values())
        
        from scanner.favicon_analyzer import FaviconAnalyzer
        fav_analyzer = FaviconAnalyzer()
        results["favicon"] = fav_analyzer.analyze(url)
        
    except Exception as e:
        results["error"] = str(e)
        
    return results

if __name__ == "__main__":
    print(run_tech_fingerprint("http://scanme.nmap.org"))
