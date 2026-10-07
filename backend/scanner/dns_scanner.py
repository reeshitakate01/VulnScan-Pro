import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import ipaddress
from urllib.parse import urlparse

DKIM_SELECTORS = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2", "s1", "s2"]
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev",
    "staging", "vpn", "remote", "portal", "cdn",
    "app", "test", "beta", "smtp", "pop", "imap",
    "ns1", "ns2", "blog", "shop", "secure"
]

def build_resolver(timeout=3):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    return resolver

def analyze_spf(spf_record):
    issues = []
    if not spf_record:
        return {"exists": False, "issues": ["No SPF record found"]}
    
    spf_lower = spf_record.lower()
    if "+all" in spf_lower:
        issues.append("CRITICAL: +all allows anyone to send as this domain")
    if "~all" in spf_lower:
        issues.append("WARN: ~all (softfail) is not strictly enforced")
    if "?all" in spf_lower:
        issues.append("WARN: ?all is neutral, provides no protection")
    if "-all" not in spf_lower:
        issues.append("INFO: Strict -all not set")
        
    return {"exists": True, "record": spf_record, "issues": issues}

def reverse_dns(ip_list, resolver):
    ptr_results = {}
    for ip in ip_list:
        try:
            # Quick check if it's a valid IP
            ipaddress.ip_address(ip)
            rev = dns.reversename.from_address(ip)
            ptr = str(resolver.resolve(rev, 'PTR')[0])
            ptr_results[ip] = ptr
        except Exception:
            ptr_results[ip] = None
    return ptr_results

def enumerate_subdomains(domain, resolver):
    found = []
    for sub in COMMON_SUBDOMAINS:
        try:
            target = f"{sub}.{domain}"
            answers = resolver.resolve(target, 'A')
            found.append({
                "subdomain": target,
                "ips": [str(r) for r in answers]
            })
        except Exception:
            continue
    return found

def run_dns_recon(url, timeout=3, enumerate_subs=True, attempt_zone_transfer=True, probe_dkim=True):
    resolver = build_resolver(timeout)
    results = {
        "records": {},
        "zone_transfer_vulnerable": False,
        "spf_analysis": None,
        "dmarc": None,
        "dkim": None,
        "mx_resolved": [],
        "ptr_records": {},
        "subdomains": [],
        "errors": []
    }
    
    try:
        if "://" not in url:
            url = "http://" + url
        parsed = urlparse(url)
        domain = parsed.hostname or url
        
        # 1. Handle www stripping correctly
        base_domain = domain[4:] if domain.startswith("www.") else domain
        domains_to_query = list({domain, base_domain})  # deduplicated list
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA', 'SRV']
        
        # Querying the base_domain as the canonical target for structural records
        canonical_domain = base_domain
        
        # 2. Gather DNS Records over canonical domain and specific domain
        for qtype in record_types:
            merged_values = set()
            lowest_ttl = None
            
            for dom in domains_to_query:
                try:
                    answers = resolver.resolve(dom, qtype)
                    for r in answers:
                        merged_values.add(str(r))
                    # keep the lowest ttl observed
                    if lowest_ttl is None or answers.rrset.ttl < lowest_ttl:
                        lowest_ttl = answers.rrset.ttl
                except Exception:
                    pass
                    
            if merged_values:
                results["records"][qtype] = {
                    "values": list(merged_values),
                    "ttl": lowest_ttl
                }
            else:
                results["records"][qtype] = {"values": [], "ttl": None}
                
        # 3. NS Fallback
        if not results["records"].get("NS", {}).get("values"):
            parts = canonical_domain.split('.')
            if len(parts) > 2:
                parent_domain = '.'.join(parts[-2:])
                try:
                    base_answers = resolver.resolve(parent_domain, 'NS')
                    results["records"]["NS"] = {
                        "values": [str(r) for r in base_answers],
                        "ttl": base_answers.rrset.ttl
                    }
                except Exception:
                    pass
                    
        # 4. Extract TXT records for SPF
        spf_str = None
        txt_records = results["records"].get("TXT", {}).get("values", [])
        for txt in txt_records:
            if "v=spf1" in txt:
                spf_str = txt
                break
                
        # 5. SPF Analysis
        results["spf_analysis"] = analyze_spf(spf_str)
        
        # 6. Check DMARC
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{canonical_domain}", 'TXT')
            results["dmarc"] = [str(r) for r in dmarc_answers][0]
        except Exception:
            pass
            
        # 7. Check DKIM via Common Selectors
        if probe_dkim:
            for selector in DKIM_SELECTORS:
                try:
                    dkim_answers = resolver.resolve(f"{selector}._domainkey.{canonical_domain}", 'TXT')
                    results["dkim"] = {
                        "selector": selector,
                        "record": str(dkim_answers[0])
                    }
                    break  # Found one, stop
                except Exception:
                    continue
                    
        # 8. Resolve MX to IPs
        mx_records = results["records"].get("MX", {}).get("values", [])
        for mx in mx_records:
            # "10 mail.example.com." -> "mail.example.com"
            mx_host = mx.split()[-1].rstrip('.')
            try:
                ip_answers = resolver.resolve(mx_host, 'A')
                ip_str = str(ip_answers[0])
                results["mx_resolved"].append({"host": mx_host, "ip": ip_str})
            except Exception:
                results["mx_resolved"].append({"host": mx_host, "ip": None})
                
        # 9. Reverse DNS (PTR) on discovered A records
        a_records = results["records"].get("A", {}).get("values", [])
        if a_records:
            results["ptr_records"] = reverse_dns(a_records, resolver)
            
        # 10. Subdomain Enumeration
        if enumerate_subs:
            results["subdomains"] = enumerate_subdomains(canonical_domain, resolver)
            
        # 11. Zone Transfer (AXFR) Check
        if attempt_zone_transfer and results["records"].get("NS", {}).get("values"):
            for ns in results["records"]["NS"]["values"]:
                try:
                    # Explicit fast timeout on the NS to A resolution
                    ns_ip = resolver.resolve(ns, 'A')[0].to_text()
                    # 2 second timeout for the axfr block
                    z = dns.zone.from_xfr(dns.query.xfr(ns_ip, canonical_domain, timeout=2))
                    if z:
                        results["zone_transfer_vulnerable"] = True
                        break
                except Exception:
                    pass

    except Exception as e:
        results["errors"].append(str(e))
        
    return results

if __name__ == "__main__":
    import json
    res = run_dns_recon("http://scanme.nmap.org", timeout=3, enumerate_subs=True, attempt_zone_transfer=True, probe_dkim=True)
    print(json.dumps(res, indent=2))
