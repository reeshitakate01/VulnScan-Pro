def calculate_score(scan_results):
    score = 100
    deductions = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 1
    }

    findings_count = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    # Port Scanner
    if "port_scan" in scan_results:
        for port in scan_results["port_scan"]:
            risk = port.get("risk_level")
            if risk in deductions:
                score -= deductions[risk]
                findings_count[risk] += 1

    # Headers
    if "headers" in scan_results:
        for header in scan_results["headers"]:
            severity = header.get("severity")
            if severity in deductions:
                score -= deductions[severity]
                findings_count[severity] += 1

    # XSS
    if "xss" in scan_results:
        for xss in scan_results["xss"]:
            if xss.get("vulnerable"):
                score -= deductions["HIGH"]
                findings_count["HIGH"] += 1

    # SQLi
    if "sqli" in scan_results:
        for sqli in scan_results["sqli"]:
            if sqli.get("vulnerable"):
                score -= deductions["CRITICAL"]
                findings_count["CRITICAL"] += 1

    # SSL — define ssl_res here so it is always in scope for the JS block below
    ssl_res = None
    if "ssl" in scan_results and not isinstance(scan_results["ssl"], list):
        ssl_res = scan_results["ssl"]
        if not ssl_res.get("cert_valid", True):
            score -= deductions["HIGH"]
            findings_count["HIGH"] += 1
        if ssl_res.get("self_signed"):
            score -= deductions["HIGH"]
            findings_count["HIGH"] += 1
        if ssl_res.get("weak_ciphers"):
            score -= deductions["MEDIUM"]
            findings_count["MEDIUM"] += 1

    # JS Analysis  (BUG FIX: ssl_res is now guaranteed to be defined above)
    if "js_analysis" in scan_results and isinstance(scan_results["js_analysis"], dict):
        js_res = scan_results["js_analysis"]
        for jsf in js_res.get("findings", []):
            sev = jsf.get("Severity", "INFO")
            if sev in deductions:
                score -= deductions[sev]
                findings_count[sev] += 1
        # Only check TLS versions if the SSL module also ran
        if ssl_res is not None:
            tls = ssl_res.get("tls_versions", {})
            if tls.get("TLSv1.0") or tls.get("TLSv1.1"):
                score -= deductions["MEDIUM"]
                findings_count["MEDIUM"] += 1

    # DNS
    if "dns" in scan_results and not isinstance(scan_results["dns"], list):
        dns_res = scan_results["dns"]
        if dns_res.get("zone_transfer_vulnerable"):
            score -= deductions["CRITICAL"]
            findings_count["CRITICAL"] += 1
        if not dns_res.get("spf"):
            score -= deductions["MEDIUM"]
            findings_count["MEDIUM"] += 1
        if not dns_res.get("dmarc"):
            score -= deductions["MEDIUM"]
            findings_count["MEDIUM"] += 1

    # Tech
    if "tech" in scan_results and not isinstance(scan_results["tech"], list):
        for tech in scan_results["tech"].get("technologies", []):
            if tech.get("cves_found"):
                # Cap per-tech deduction at 2 CVEs max to prevent score floor at 0
                cve_count = min(len(tech["cves_found"]), 2)
                score -= deductions["HIGH"] * cve_count
                findings_count["HIGH"] += cve_count

    # Open Redirect
    if "open_redirect" in scan_results:
        for finding in scan_results["open_redirect"]:
            if finding.get("vulnerable"):
                sev = finding.get("severity", "HIGH")
                score -= deductions.get(sev, deductions["HIGH"])
                findings_count[sev] += 1

    # CSRF
    if "csrf" in scan_results:
        for finding in scan_results["csrf"]:
            if finding.get("vulnerable"):
                sev = finding.get("severity", "HIGH")
                score -= deductions.get(sev, deductions["HIGH"])
                findings_count[sev] += 1

    # Config-posture modules with a unified finding shape
    # (CORS, HTTP methods, recon). Deduct by severity for vulnerable items.
    for modname in ("cors", "http_methods", "recon"):
        if modname in scan_results and isinstance(scan_results[modname], list):
            for item in scan_results[modname]:
                if item.get("vulnerable"):
                    sev = item.get("severity", "LOW")
                    if sev in deductions:
                        score -= deductions[sev]
                        findings_count[sev] += 1

    # WAF Detection — a WAF is a positive security control; small bonus
    if "waf" in scan_results:
        waf_res = scan_results["waf"]
        if isinstance(waf_res, dict) and waf_res.get("waf_detected"):
            score = min(score + 5, 100)

    # Enforce bounds
    score = max(0, min(100, score))

    # Grade
    if score >= 90:   grade = "A"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 60: grade = "D"
    else:             grade = "F"

    # Summary
    summary = f"Security score is {score}/100. "
    if findings_count["CRITICAL"] > 0:
        summary += f"Found {findings_count['CRITICAL']} critical vulnerabilities requiring immediate attention. "
    elif findings_count["HIGH"] > 0:
        summary += f"Found {findings_count['HIGH']} high severity issues. "
    else:
        summary += "No critical or high severity issues found. "

    return {
        "score": score,
        "grade": grade,
        "summary_text": summary,
        "findings_count": findings_count
    }
