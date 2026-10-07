import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser
from collections import deque
import re
import time
import urllib3

urllib3.disable_warnings()

def is_same_domain(url1, url2):
    return urlparse(url1).netloc == urlparse(url2).netloc

def normalize_url(url):
    parsed = urlparse(url)
    # Remove fragment, normalize path trailing slash
    normalized = parsed._replace(
        fragment='',
        path=parsed.path.rstrip('/') or '/'
    )
    return urlunparse(normalized)

def get_robots_paths(base_url):
    rp = RobotFileParser()
    rp.set_url(urljoin(base_url, "/robots.txt"))
    try:
        rp.read()
        # Disallowed paths are goldmines for recon
        return True, list(rp.entries) if rp.entries else []
    except Exception:
        return False, []

SENSITIVE_PATHS = [
    "/.git/config", "/backup.zip", "/.env",
    "/phpinfo.php", "/admin", "/wp-admin",
    "/api/v1/users", "/config.json", "/debug"
]

def probe_sensitive_paths(base_url):
    found = []
    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(urljoin(base_url, path), timeout=3, verify=False)
            if r.status_code in [200, 403]:  # 403 = exists but forbidden
                found.append({"path": path, "status": r.status_code})
        except Exception:
            pass
    return found

def run_crawler(start_url, max_depth=3, max_pages=100, delay=0, respect_robots=False, probe_paths=True):
    start_url = normalize_url(start_url)
    visited = set()
    queued = {start_url}
    queue = deque([(start_url, 0)])
    
    results = {
        "start_url": start_url,
        "pages_crawled": 0,
        "forms": [],
        "hidden_fields": 0,
        "file_uploads": 0,
        "emails_found": [],
        "sensitive_comments": [],
        "external_scripts": [],
        "inline_script_secrets": [],
        "meta_info": [],
        "missing_headers_by_page": [],
        "sensitive_paths_probed": [],
        "robots_disallowed": [],
        "errors": []
    }
    
    email_regex = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    sensitive_keywords = ["password", "token", "secret", "api_key", "jdbc", "mysql", "todo", "key"]
    security_headers = ["content-security-policy", "x-frame-options", 
                        "strict-transport-security", "x-content-type-options"]
    
    # 1. Robots Exploration
    if respect_robots:
        # Note: If respect_robots is True, we actually use it mostly to harvest data rather than strictly blocking it
        parsed_ok, entries = get_robots_paths(start_url)
        if parsed_ok:
            results["robots_disallowed"] = [str(e) for e in entries]

    # 2. Sensitive Path Probing
    if probe_paths:
        base_parsed = urlparse(start_url)
        base = f"{base_parsed.scheme}://{base_parsed.netloc}"
        results["sensitive_paths_probed"] = probe_sensitive_paths(base)

    while queue:
        current_url, depth = queue.popleft()
        
        if current_url in visited:
            continue
            
        if depth > max_depth or results["pages_crawled"] >= max_pages:
            continue
            
        visited.add(current_url)
        results["pages_crawled"] += 1
        
        if delay > 0:
            time.sleep(delay)
            
        try:
            response = requests.get(current_url, timeout=5, verify=False)
            
            # Extract headers for all responses
            response_headers_lower = {k.lower(): v for k, v in response.headers.items()}
            missing = [h for h in security_headers if h not in response_headers_lower]
            if missing:
                results["missing_headers_by_page"].append({
                    "url": current_url,
                    "missing": missing
                })
            
            if 'text/html' not in response.headers.get('Content-Type', ''):
                continue
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                if name in ['generator', 'author', 'framework', 'viewport']:
                    content = meta.get('content', '')
                    if content:
                        results["meta_info"].append({
                            "url": current_url,
                            "name": name,
                            "content": content
                        })
            
            # Extract Emails
            emails = email_regex.findall(response.text)
            for email in set(emails):
                if email not in results["emails_found"]:
                    results["emails_found"].append(email)
                    
            # Extract Comments
            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
            for comment in comments:
                lower_comment = comment.lower()
                if any(kw in lower_comment for kw in sensitive_keywords):
                    results["sensitive_comments"].append(comment.strip())
                    
            # Extract Scripts (External and Inline)
            for script in soup.find_all('script'):
                if script.has_attr('src'):
                    src = script.get('src')
                    script_url = urljoin(current_url, src)
                    if script_url not in results["external_scripts"]:
                        results["external_scripts"].append(script_url)
                else:
                    # Inline script extraction
                    content = script.string
                    if content:
                        if any(kw in content.lower() for kw in sensitive_keywords):
                            snippet = content[:300].strip()
                            if snippet not in results["inline_script_secrets"]:
                                results["inline_script_secrets"].append(snippet)
                    
            # Extract Forms
            for form in soup.find_all('form'):
                form_action = form.get('action')
                form_method = form.get('method', 'get').lower()
                action_url = urljoin(current_url, form_action) if form_action else current_url
                action_url = normalize_url(action_url)
                
                inputs = []
                for input_tag in form.find_all(['input', 'textarea', 'select', 'button']):
                    type_ = input_tag.get('type', 'text') if input_tag.name != 'button' else 'submit'
                    name = input_tag.get('name')
                    
                    if not name:
                        continue
                        
                    inputs.append({"name": name, "type": type_})
                    
                    if type_.lower() == 'hidden':
                        results["hidden_fields"] += 1
                    elif type_.lower() == 'file':
                        results["file_uploads"] += 1
                        
                results["forms"].append({
                    "action_url": action_url,
                    "method": form_method,
                    "inputs": inputs,
                    "source_url": current_url
                })
                
            # Extract Links to crawl
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if not href:
                    continue
                next_url = urljoin(current_url, href)
                
                # Keep within the same domain
                if is_same_domain(start_url, next_url):
                    next_url = normalize_url(next_url)
                    
                    if next_url not in visited and next_url not in queued:
                        queue.append((next_url, depth + 1))
                        queued.add(next_url)
                        
        except requests.exceptions.Timeout:
            results["errors"].append({"url": current_url, "reason": "timeout"})
        except requests.exceptions.ConnectionError:
            results["errors"].append({"url": current_url, "reason": "connection_error"})
        except Exception as e:
            results["errors"].append({"url": current_url, "reason": str(e)})
            
    # Deduplicate forms based on action and method + inputs to avoid bloating
    unique_forms = {}
    for form in results["forms"]:
        sig = f"{form['action_url']}|{form['method']}|{','.join([i['name'] for i in form['inputs']])}"
        if sig not in unique_forms:
            unique_forms[sig] = form
    results["forms"] = list(unique_forms.values())
    
    # Deduplicate meta info
    unique_meta = []
    seen_meta = set()
    for m in results["meta_info"]:
        sig = f"{m['name']}:{m['content']}"
        if sig not in seen_meta:
            seen_meta.add(sig)
            unique_meta.append(m)
    results["meta_info"] = unique_meta
            
    return results

if __name__ == "__main__":
    import json
    res = run_crawler("http://testphp.vulnweb.com", max_depth=1, max_pages=10, delay=0, respect_robots=True, probe_paths=True)
    print(json.dumps(res, indent=2))
