import json
import os

class OWASPMapper:
    def __init__(self):
        mapping_file = os.path.join(os.path.dirname(__file__), '..', 'knowledge_base', 'owasp_mapping.json')
        if os.path.exists(mapping_file):
            with open(mapping_file, 'r', encoding='utf-8') as f:
                self.mapping = {entry["finding_key"]: entry for entry in json.load(f)}
        else:
            self.mapping = {}

    def enrich_finding(self, finding: dict) -> dict:
        """Add OWASP/CWE/CVSS data to a finding dict in place"""
        # Try to use actual key if provided, else infer it
        key = finding.get("finding_key") or self._infer_key(finding)
        if key in self.mapping:
            finding["owasp_category"] = self.mapping[key]["owasp_category"]
            finding["owasp_name"] = self.mapping[key]["owasp_name"]
            finding["cwe"] = self.mapping[key]["cwe"]
            finding["cwe_name"] = self.mapping[key]["cwe_name"]
            finding["cvss_score"] = self.mapping[key]["cvss_score"]
            finding["cvss_severity"] = self.mapping[key]["cvss_severity"]
            finding["cvss_vector"] = self.mapping[key]["cvss_vector"]
        return finding

    def enrich_all(self, all_findings: list) -> list:
        """Enrich every finding in the full scan results flat list"""
        return [self.enrich_finding(f) for f in all_findings]

    def generate_owasp_summary(self, all_findings: list) -> dict:
        """
        Return a summary grouped by OWASP category.
        Used to render the OWASP table section in the PDF and UI.
        """
        categories = {
            "A01:2021": {"name": "Broken Access Control", "count": 0, "highest_severity": "INFO", "findings": []},
            "A02:2021": {"name": "Cryptographic Failures", "count": 0, "highest_severity": "INFO", "findings": []},
            "A03:2021": {"name": "Injection", "count": 0, "highest_severity": "INFO", "findings": []},
            "A04:2021": {"name": "Insecure Design", "count": 0, "highest_severity": "INFO", "findings": []},
            "A05:2021": {"name": "Security Misconfiguration", "count": 0, "highest_severity": "INFO", "findings": []},
            "A06:2021": {"name": "Vulnerable and Outdated Components", "count": 0, "highest_severity": "INFO", "findings": []},
            "A07:2021": {"name": "Identification and Authentication Failures", "count": 0, "highest_severity": "INFO", "findings": []},
            "A08:2021": {"name": "Software and Data Integrity Failures", "count": 0, "highest_severity": "INFO", "findings": []},
            "A09:2021": {"name": "Security Logging and Monitoring Failures", "count": 0, "highest_severity": "INFO", "findings": []},
            "A10:2021": {"name": "Server-Side Request Forgery", "count": 0, "highest_severity": "INFO", "findings": []},
        }

        severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

        for f in all_findings:
            if "owasp_category" in f:
                cat = f["owasp_category"]
                if cat in categories:
                    categories[cat]["count"] += 1
                    categories[cat]["findings"].append(f)
                    
                    current_highest = categories[cat]["highest_severity"]
                    f_sev = f.get("severity", f.get("Severity", "INFO"))
                    if severity_rank.get(f_sev, 0) > severity_rank.get(current_highest, 0):
                        categories[cat]["highest_severity"] = f_sev

        # Clean empty ones if desired, though the UI requires grey out, so we keep all
        return categories

    def _infer_key(self, finding: dict) -> str:
        """
        Best-effort match a finding to a mapping key
        if finding_key not explicitly set by the individual scanner module.
        """
        title = str(finding.get("Finding", finding.get("Finding Name", finding.get("header", "")))).lower()
        desc = str(finding.get("Description", finding.get("description", ""))).lower()
        full_text = title + " " + desc

        if "x-content-type-options" in full_text: return "missing_xcontent"
        if "x-frame-options" in full_text: return "missing_xframe"
        if "strict-transport-security" in full_text: return "missing_hsts"
        if "content-security-policy" in full_text: return "missing_csp"
        
        if "httponly" in full_text: return "cookie_no_httponly"
        if "secure flag" in full_text: return "cookie_no_secure"
        if "samesite" in full_text: return "cookie_no_samesite"
        if "server" in title and "present" in desc: return "server_version_leak"

        if "invalid cert" in full_text or "expired" in full_text: return "expired_cert"
        if "self signed" in full_text or "self-signed" in full_text: return "self_signed_cert"
        if "tls" in full_text and "v1" in full_text: return "weak_tls_version"
        if "weak cipher" in full_text: return "weak_cipher"
        
        if "xss" in full_text: return "reflected_xss"
        if "sql" in full_text: return "sql_injection"
        
        if "port" in full_text and "open" in full_text:
            if any(p in title for p in ["3306", "5432", "1433", "27017", "6379", "9200", "11211", "1521"]):
                return "database_port_exposed"
            return "dangerous_port_open"

        if "missing spf" in full_text: return "missing_spf"
        if "missing dmarc" in full_text: return "missing_dmarc"
        if "zone transfer" in full_text: return "zone_transfer_enabled"
        
        if "cve" in full_text: return "cve_found"
        
        return "outdated_software" # Default fallback for missing techs or others
