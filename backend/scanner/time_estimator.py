MODULE_BASE_TIMES = {
    "port_scanner":       45,   # Top 1000 ports, 50 threads
    "header_scanner":      3,   # Single HTTP request
    "crawler":            20,   # 3 levels, 50 pages max
    "xss_scanner":        30,   # Depends on forms found
    "sql_injection":      30,   # Depends on forms found
    "ssl_scanner":         5,   # Single TLS handshake
    "dns_scanner":         8,   # Multiple DNS queries
    "tech_fingerprint":    4,   # Header + HTML analysis
    "js_analyzer":        15,   # Download + parse JS files
    "dir_bruteforce":     20,   # 200 paths checked
    "cors_check":          3,   # Single request with Origin header
    "robots_parser":       2,   # Fetch /robots.txt + /sitemap.xml
    "whois":               3,   # Local whois library call
}

MODIFIER_NOTES = {
    "port_scanner": "Actual time varies based on network latency and firewall behavior",
    "crawler": "Time scales with site size. Deep sites with 50+ pages take longer.",
    "xss_scanner": "Depends on number of forms found during crawling.",
    "sql_injection": "Depends on number of injectable parameters found.",
    "js_analyzer": "Scales with number and size of JS files on the page.",
}

class TimeEstimator:
    def estimate(self, selected_modules: list) -> dict:
        """
        Given a list of selected module names, return time estimate.
        Modules run concurrently, so total ≈ slowest module + overhead.
        But some modules depend on crawler output (XSS, SQLi, JS) so
        they run after the crawler — add their time sequentially.
        """
        
        # Phase 1: runs in parallel immediately
        phase1_modules = [
            "port_scanner", "header_scanner", "ssl_scanner",
            "dns_scanner", "tech_fingerprint", "robots_parser",
            "cors_check", "whois"
        ]
        
        # Phase 2: runs after crawler completes (depends on crawl output)
        phase2_modules = ["xss_scanner", "sql_injection", "js_analyzer"]
        
        # Crawler runs first, independently
        crawler_time = MODULE_BASE_TIMES.get("crawler", 20) if "crawler" in selected_modules else 0
        
        phase1_selected = [m for m in selected_modules if m in phase1_modules]
        phase2_selected = [m for m in selected_modules if m in phase2_modules]
        
        # Phase 1 runs in parallel — time = max of selected phase 1 modules
        phase1_times = [MODULE_BASE_TIMES.get(m, 0) for m in phase1_selected]
        phase1_time = max(phase1_times) if phase1_times else 0
        
        # Phase 2 runs after crawler — sum their times (they run sequentially logic approx)
        phase2_time = sum(MODULE_BASE_TIMES.get(m, 0) for m in phase2_selected)
        
        # Total = max(parallel phase1, crawler + phase2)
        # Actually crawler starts right away, and phase2 starts after crawler.
        # Phase1 starts right away too.
        # So total time = max(phase1_time, crawler_time + phase2_time)
        total_seconds = max(phase1_time, crawler_time + phase2_time)
        
        # Add 10 second overhead for scan setup, DB writes, PDF generation
        total_seconds += 10

        return {
            "total_seconds": total_seconds,
            "total_minutes": round(total_seconds / 60, 1),
            "display": self._format_time(total_seconds),
            "phase_breakdown": {
                "crawling": crawler_time,
                "parallel_checks": phase1_time,
                "form_analysis": phase2_time
            },
            "module_times": {
                m: MODULE_BASE_TIMES.get(m, 0) for m in selected_modules
            },
            "note": "Estimate assumes average network conditions. Firewalls or large sites may increase duration."
        }

    def _format_time(self, seconds: int) -> str:
        if seconds < 60:
            return f"~{seconds} seconds"
        elif seconds < 120:
            return f"~1-2 minutes"
        else:
            return f"~{round(seconds/60)} minutes"
