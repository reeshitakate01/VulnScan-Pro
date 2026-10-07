import requests
import re

class JSAnalyzer:

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.timeout = 10
        
        # All regex patterns for secret detection
        self._compiled = {}  # populated after patterns dict is built
        self.patterns = {
            # API Keys & Tokens
            "aws_access_key": {
                "regex": r"AKIA[0-9A-Z]{16}",
                "severity": "CRITICAL",
                "description": "AWS Access Key ID found",
                "cwe": "CWE-312"
            },
            "aws_secret_key": {
                "regex": r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
                "severity": "CRITICAL",
                "description": "AWS Secret Access Key found",
                "cwe": "CWE-312"
            },
            "google_api_key": {
                "regex": r"AIza[0-9A-Za-z\-_]{35}",
                "severity": "HIGH",
                "description": "Google API Key found",
                "cwe": "CWE-312"
            },
            "stripe_live_key": {
                "regex": r"sk_live_[0-9a-zA-Z]{24,}",
                "severity": "CRITICAL",
                "description": "Stripe Live Secret Key found",
                "cwe": "CWE-312"
            },
            "stripe_pub_key": {
                "regex": r"pk_live_[0-9a-zA-Z]{24,}",
                "severity": "MEDIUM",
                "description": "Stripe Live Publishable Key found",
                "cwe": "CWE-312"
            },
            "github_token": {
                "regex": r"ghp_[0-9a-zA-Z]{36}",
                "severity": "CRITICAL",
                "description": "GitHub Personal Access Token found",
                "cwe": "CWE-312"
            },
            "github_oauth": {
                "regex": r"gho_[0-9a-zA-Z]{36}",
                "severity": "CRITICAL",
                "description": "GitHub OAuth Token found",
                "cwe": "CWE-312"
            },
            "slack_token": {
                "regex": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
                "severity": "HIGH",
                "description": "Slack API Token found",
                "cwe": "CWE-312"
            },
            "slack_webhook": {
                "regex": r"https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}",
                "severity": "HIGH",
                "description": "Slack Webhook URL found",
                "cwe": "CWE-312"
            },
            "sendgrid_key": {
                "regex": r"SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}",
                "severity": "HIGH",
                "description": "SendGrid API Key found",
                "cwe": "CWE-312"
            },
            "twilio_sid": {
                "regex": r"AC[0-9a-fA-F]{32}",
                "severity": "HIGH",
                "description": "Twilio Account SID found",
                "cwe": "CWE-312"
            },
            "firebase_key": {
                "regex": r"(?i)firebase[^'\"]*['\"][A-Za-z0-9\-_]{20,}['\"]",
                "severity": "HIGH",
                "description": "Firebase API Key found",
                "cwe": "CWE-312"
            },
            "jwt_token": {
                "regex": r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+",
                "severity": "HIGH",
                "description": "Hardcoded JWT token found",
                "cwe": "CWE-312"
            },
            "basic_auth_url": {
                "regex": r"https?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9\-\.]+",
                "severity": "CRITICAL",
                "description": "Credentials embedded in URL found",
                "cwe": "CWE-312"
            },
            "generic_secret": {
                "regex": r"(?i)(secret|password|passwd|api_key|apikey|token|auth)['\"]?\s*[:=]\s*['\"][A-Za-z0-9!@#$%^&*\-_]{8,}['\"]",
                "severity": "HIGH",
                "description": "Hardcoded secret or password found",
                "cwe": "CWE-798"
            },
            "private_key_block": {
                "regex": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
                "severity": "CRITICAL",
                "description": "Private key material found in JavaScript",
                "cwe": "CWE-312"
            },

            # Internal Endpoints & Infrastructure
            "internal_ip": {
                "regex": r"(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
                "severity": "MEDIUM",
                "description": "Internal IP address reference found",
                "cwe": "CWE-200"
            },
            "localhost_ref": {
                "regex": r"(?:https?://)?localhost[:/]",
                "severity": "LOW",
                "description": "Localhost reference found (dev config?)",
                "cwe": "CWE-200"
            },
            "internal_endpoint": {
                "regex": r"(?:https?://)[a-zA-Z0-9\-]+\.(?:internal|local|corp|intranet|lan)[/:]",
                "severity": "MEDIUM",
                "description": "Internal domain endpoint reference found",
                "cwe": "CWE-200"
            },
            "graphql_endpoint": {
                "regex": r"['\"/]graphql['\"/]|/api/graphql",
                "severity": "INFO",
                "description": "GraphQL endpoint discovered",
                "cwe": "CWE-200"
            },
            "api_endpoint": {
                "regex": r"['\"](?:/api/v[0-9]+/[a-zA-Z0-9/_\-]+)['\"]",
                "severity": "INFO",
                "description": "Internal API endpoint path discovered",
                "cwe": "CWE-200"
            },
            "s3_bucket": {
                "regex": r"[a-z0-9\-]+\.s3\.amazonaws\.com|s3://[a-z0-9\-]+",
                "severity": "MEDIUM",
                "description": "S3 bucket reference found",
                "cwe": "CWE-200"
            },

            # Developer Comments
            "todo_fixme": {
                "regex": r"//\s*(?:TODO|FIXME|HACK|XXX|BUG|VULNERABILITY|INSECURE|TEMP|WORKAROUND).{0,100}",
                "severity": "INFO",
                "description": "Developer comment flagging unresolved issue",
                "cwe": "CWE-546"
            },
            "commented_code_creds": {
                "regex": r"//.*(?:password|secret|key|token|credential).{0,80}",
                "severity": "MEDIUM",
                "description": "Commented-out code containing sensitive keyword",
                "cwe": "CWE-615"
            },
        }

        # Compile every regex once so _analyze_single_file doesn't recompile per file
        self._compiled = {
            name: re.compile(info["regex"])
            for name, info in self.patterns.items()
        }

    def analyze(self, js_urls: list, base_url: str) -> dict:
        """
        Main entry point. Takes list of JS URLs from crawler.
        Returns all findings across all JS files.
        """
        all_findings = []
        files_analyzed = 0
        total_size_bytes = 0

        for url in js_urls[:30]:  # Cap at 30 JS files
            try:
                result = self._analyze_single_file(url)
                if result:
                    all_findings.extend(result["findings"])
                    files_analyzed += 1
                    total_size_bytes += result["size_bytes"]
            except Exception as e:
                pass

        return {
            "files_analyzed": files_analyzed,
            "total_size_kb": round(total_size_bytes / 1024, 1),
            "findings": all_findings,
            "unique_endpoints": self._extract_all_endpoints(all_findings),
            "secrets_found": len([f for f in all_findings 
                                  if f["finding_key"] not in ["api_endpoint", 
                                  "graphql_endpoint", "todo_fixme"]])
        }

    def _analyze_single_file(self, url: str) -> dict:
        """Download, beautify, and scan one JS file"""
        response = self.session.get(url, timeout=self.timeout)
        raw_js = response.text

        # Skip files over 2MB
        if len(raw_js) > 2_000_000:
            return None

        # Deobfuscate minified JS using jsbeautifier
        import jsbeautifier
        options = jsbeautifier.default_options()
        options.unescape_strings = True
        options.eval_code = False  # NEVER eval code
        beautified = jsbeautifier.beautify(raw_js, options)

        findings = []
        for pattern_name, pattern_info in self.patterns.items():
            matches = self._compiled[pattern_name].findall(beautified)
            for match in set(matches):  # deduplicate
                # Redact secrets partially for safe display
                safe_match = self._redact(match, pattern_name)
                findings.append({
                    "Finding": pattern_info["description"],
                    "Severity": pattern_info["severity"],
                    "Description": f"Found in JS file: {url}\\nEvidence: {safe_match}",
                    "Recommendation": self._get_recommendation(pattern_name),
                    "finding_key": pattern_name,
                    "cwe": pattern_info["cwe"],
                    "file_url": url,
                    "evidence": safe_match
                })

        return {
            "url": url,
            "size_bytes": len(raw_js),
            "findings": findings
        }

    def _redact(self, value: str, pattern_type: str) -> str:
        """Partially redact sensitive values before storing"""
        # Show first 6 chars and last 4 chars with *** in middle
        credential_types = [
            "aws_access_key", "aws_secret_key", "github_token",
            "stripe_live_key", "generic_secret", "jwt_token"
        ]
        if pattern_type in credential_types and len(value) > 12:
            return value[:6] + "***REDACTED***" + value[-4:]
        return value

    def _get_recommendation(self, pattern_type: str) -> str:
        """Return fix recommendation for each pattern type"""
        recommendations = {
            "aws_access_key": "Immediately rotate this AWS key. Use IAM roles or environment variables instead of hardcoding credentials.",
            "github_token": "Revoke this token immediately at github.com/settings/tokens. Use CI/CD secrets management.",
            "stripe_live_key": "Rotate this key in the Stripe dashboard immediately. Never expose secret keys in frontend code.",
            "generic_secret": "Move secrets to server-side environment variables. Never include credentials in JavaScript.",
            "internal_ip": "Remove internal IP references from frontend code. Use relative URLs or environment-specific config.",
            "jwt_token": "Never hardcode JWT tokens. Generate tokens server-side and deliver via secure HttpOnly cookies.",
            "todo_fixme": "Review this developer comment and resolve the flagged issue before production deployment.",
            "s3_bucket": "Verify this S3 bucket has proper access controls. Ensure it is not publicly writable.",
        }
        return recommendations.get(
            pattern_type, 
            "Remove sensitive information from client-side JavaScript code."
        )

    def _extract_all_endpoints(self, findings: list) -> list:
        """Pull out all discovered API endpoints as a clean list"""
        return list(set([
            f["evidence"] for f in findings 
            if f["finding_key"] in ["api_endpoint", "graphql_endpoint", 
                             "internal_endpoint"]
        ]))
