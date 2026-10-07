"""
CVE lookup via the OSV.dev API — VulnScan Pro.

Augments the tech fingerprinter's findings with real, current advisory data
instead of relying solely on a tiny hardcoded table. OSV covers open-source
package ecosystems (npm, PyPI, …), so it is most useful for the JavaScript
libraries the fingerprinter detects (jQuery, React, …).

Design:
  * Fails open: any network/parse error, a disabled flag, or an unknown
    ecosystem simply yields no extra CVEs — the caller keeps its offline
    results. A scan is never broken by OSV being unreachable.
  * Results are cached per (ecosystem, name, version) for the process.
"""
from config import config
from scanner.safe_requests import get_session

# Map fingerprint names to OSV ecosystems. Server software (nginx/apache/php)
# is not reliably queryable by name in OSV, so only client-side libs are mapped.
ECOSYSTEM_MAP = {
    "jquery": "npm",
    "react": "npm",
    "angular": "npm",
    "vue": "npm",
    "lodash": "npm",
    "bootstrap": "npm",
    "moment": "npm",
    "axios": "npm",
}

_CACHE: dict[tuple[str, str, str], list[str]] = {}


def query_osv(name: str, version: str) -> list[str]:
    """Return a list of advisory IDs (CVE aliases preferred) for name@version."""
    ecosystem = ECOSYSTEM_MAP.get(name.lower())
    if not config.OSV_ENABLED or not ecosystem or not version or version == "unknown":
        return []

    cache_key = (ecosystem, name.lower(), version)
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    ids: list[str] = []
    try:
        resp = get_session().post(
            config.OSV_API,
            json={
                "version": version,
                "package": {"name": name.lower(), "ecosystem": ecosystem},
            },
            timeout=config.OSV_TIMEOUT,
        )
        if resp.status_code == 200:
            for vuln in resp.json().get("vulns", []):
                cve = next(
                    (a for a in vuln.get("aliases", []) if a.startswith("CVE-")),
                    None,
                )
                ids.append(cve or vuln.get("id"))
    except Exception:  # noqa: BLE001 - fail open
        ids = []

    # Deduplicate while preserving order, cap to keep reports readable.
    seen = set()
    deduped = [i for i in ids if i and not (i in seen or seen.add(i))][:10]
    _CACHE[cache_key] = deduped
    return deduped


def enrich_technologies(technologies: list[dict]) -> list[dict]:
    """Merge OSV results into each tech's `cves_found` list (in place)."""
    for tech in technologies:
        extra = query_osv(tech.get("name", ""), tech.get("version", ""))
        if extra:
            existing = tech.get("cves_found") or []
            merged = list(dict.fromkeys(existing + extra))
            tech["cves_found"] = merged
            tech["cve_source"] = "osv.dev"
    return technologies
