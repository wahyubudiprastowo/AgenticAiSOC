from __future__ import annotations
import base64, hashlib, logging, os, re, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
import httpx
logger = logging.getLogger("threat-intel.providers")
THREAT_INTEL_MOCK_MODE = os.getenv("THREAT_INTEL_MOCK_MODE", "false").lower() == "true"
VT_ENABLED = os.getenv("VT_ENABLED", "true").lower() == "true"; VT_API_KEY = os.getenv("VT_API_KEY", "")
OTX_ENABLED = os.getenv("OTX_ENABLED", "true").lower() == "true"; OTX_API_KEY = os.getenv("OTX_API_KEY", "")
ABUSEIPDB_ENABLED = os.getenv("ABUSEIPDB_ENABLED", "true").lower() == "true"; ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
THREATFOX_ENABLED = os.getenv("THREATFOX_ENABLED", "true").lower() == "true"; THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY", "")
URLHAUS_ENABLED = os.getenv("URLHAUS_ENABLED", "true").lower() == "true"; URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")
CROWDSEC_ENABLED = os.getenv("CROWDSEC_ENABLED", "true").lower() == "true"; CROWDSEC_API_KEY = os.getenv("CROWDSEC_API_KEY", "")
CROWDSEC_CTI_BASE_URL = os.getenv("CROWDSEC_CTI_BASE_URL", "https://cti.api.crowdsec.net/v2")
CYFIRMA_ENABLED = os.getenv("CYFIRMA_ENABLED", "true").lower() == "true"
CYFIRMA_BASE_URL = os.getenv("CYFIRMA_BASE_URL", "https://api.cyfirma.com"); CYFIRMA_API_KEY = os.getenv("CYFIRMA_API_KEY", "")
CYFIRMA_API_KEY_HEADER = os.getenv("CYFIRMA_API_KEY_HEADER", "x-api-key")
CYFIRMA_TAILORED_IOC_PATH = os.getenv("CYFIRMA_TAILORED_IOC_PATH", "/api/ex/v3/da/stix/2.1/indicators/tailored")
CYFIRMA_GLOBAL_IOC_PATH = os.getenv("CYFIRMA_GLOBAL_IOC_PATH", "/api/ex/v3/da/stix/2.1/indicators/all")
CYFIRMA_VERIFY_SSL = os.getenv("CYFIRMA_VERIFY_SSL", "true").lower() == "true"
CYFIRMA_CACHE_TTL = int(os.getenv("CYFIRMA_CACHE_TTL", "1800")); CYFIRMA_MAX_PAGES = int(os.getenv("CYFIRMA_MAX_PAGES", "10"))
CYFIRMA_MAX_SECONDS = int(os.getenv("CYFIRMA_MAX_SECONDS", "90"))
CYFIRMA_ERROR_BACKOFF_SECONDS = int(os.getenv("CYFIRMA_ERROR_BACKOFF_SECONDS", "300"))
NVD_ENABLED = os.getenv("NVD_ENABLED", "true").lower() == "true"; NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_CVE_API_URL = os.getenv("NVD_CVE_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
INTEL_PROVIDER_WORKERS = max(1, int(os.getenv("INTEL_PROVIDER_WORKERS", "6")))
_PROVIDER_EXECUTOR = ThreadPoolExecutor(max_workers=INTEL_PROVIDER_WORKERS, thread_name_prefix="intel-provider")
_cyfirma_feed_cache = {"fetched_at": 0.0, "last_attempt": 0.0, "last_error": None, "indicators": set()}
_cyfirma_refresh_lock = threading.Lock()
_provider_runtime: dict[str, dict] = {}
_provider_runtime_lock = threading.Lock()
_APT_NAME_MARKERS = ("apt", "lazarus", "fancy bear", "cozy bear", "kimsuky", "turla", "sandworm", "volt typhoon",
    "mustang panda", "apt28", "apt29", "apt41", "conti", "fin7", "carbanak", "equation group")
def _deterministic_mock_score(ioc: str) -> float:
    digest = hashlib.sha256(ioc.encode()).hexdigest(); return round((int(digest[:8], 16) % 100) / 100.0, 3)
_KNOWN_BAD_PREFIXES = ("185.220.101.", "45.155.205.", "91.234.36.")
def _mock_provider_result(name, ioc):
    score = _deterministic_mock_score(ioc); forced_malicious = ioc.startswith(_KNOWN_BAD_PREFIXES)
    malicious = forced_malicious or score > 0.75
    if forced_malicious: score = max(score, 0.9)
    return {"name": name, "malicious": malicious, "score": score, "mode": "mock", "detail": f"{name} mock verdict"}
def _unavailable_result(name, detail="provider unavailable"):
    return {"name": name, "malicious": False, "score": 0.0, "mode": "unavailable", "detail": detail}
def _mock_or_unavailable(name, ioc, detail="provider unavailable"):
    return _mock_provider_result(name, ioc) if THREAT_INTEL_MOCK_MODE else _unavailable_result(name, detail)
def _error_detail(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError): return f"HTTP {exc.response.status_code}"
    return type(exc).__name__
def check_virustotal(ioc, ioc_type):
    if not VT_ENABLED: return {"name": "virustotal", "malicious": False, "score": 0.0, "mode": "disabled"}
    if not VT_API_KEY: return _mock_or_unavailable("virustotal", ioc, "API key not configured")
    try:
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        endpoint = {"ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}", "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
                    "hash": f"https://www.virustotal.com/api/v3/files/{ioc}", "url": f"https://www.virustotal.com/api/v3/urls/{url_id}"}.get(ioc_type)
        if not endpoint: return _unavailable_result("virustotal", "unsupported IOC type")
        with httpx.Client(timeout=10) as client:
            resp = client.get(endpoint, headers={"x-apikey": VT_API_KEY}); resp.raise_for_status(); data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0); total = sum(stats.values()) or 1
            score = round(malicious_count / total, 3)
            return {"name": "virustotal", "malicious": malicious_count >= 2 and score >= 0.05,
                    "score": score, "mode": "live", "detections": malicious_count, "engines": total}
    except Exception as exc: return _mock_or_unavailable("virustotal", ioc, _error_detail(exc))
def check_abuseipdb(ioc, ioc_type):
    if not ABUSEIPDB_ENABLED or ioc_type != "ip": return {"name": "abuseipdb", "malicious": False, "score": 0.0, "mode": "disabled"}
    if not ABUSEIPDB_API_KEY: return _mock_or_unavailable("abuseipdb", ioc, "API key not configured")
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ioc, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"})
            resp.raise_for_status(); data = resp.json().get("data", {}); score = round(data.get("abuseConfidenceScore", 0) / 100.0, 3)
            return {"name": "abuseipdb", "malicious": score > 0.5, "score": score, "mode": "live"}
    except Exception as exc: return _mock_or_unavailable("abuseipdb", ioc, _error_detail(exc))
def check_otx(ioc, ioc_type):
    if not OTX_ENABLED: return {"name": "otx", "malicious": False, "score": 0.0, "mode": "disabled"}
    if not OTX_API_KEY: return _mock_or_unavailable("otx", ioc, "API key not configured")
    try:
        section = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url", "cve": "cve"}.get(ioc_type)
        if not section: return _unavailable_result("otx", "unsupported IOC type")
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{ioc}/general"
        with httpx.Client(timeout=10) as client:
            resp = client.get(url, headers={"X-OTX-API-KEY": OTX_API_KEY}); resp.raise_for_status(); data = resp.json()
            pulse_info = data.get("pulse_info", {}); pulse_count = pulse_info.get("count", 0)
            pulse_names = [p.get("name", "") for p in pulse_info.get("pulses", [])[:5] if p.get("name")]
            detail = f"OTX pulses ({pulse_count}): " + "; ".join(pulse_names) if pulse_names else None
            result = {"name": "otx", "malicious": pulse_count >= 2, "score": min(1.0, round(pulse_count / 10.0, 3)),
                      "mode": "live", "pulse_count": pulse_count}
            if detail: result["detail"] = detail
            return result
    except Exception as exc: return _mock_or_unavailable("otx", ioc, _error_detail(exc))
def _nvd_result(ioc: str, payload: dict) -> dict:
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return {"name": "nvd", "malicious": False, "score": 0.0, "mode": "live",
                "detail": "CVE not found in NVD", "record_status": "not_found"}
    cve = (vulnerabilities[0] or {}).get("cve") or {}
    metrics = cve.get("metrics") or {}
    metric = None
    metric_version = None
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                         ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if entries:
            metric = next((entry for entry in entries if entry.get("type") == "Primary"), entries[0])
            metric_version = version
            break
    cvss_data = (metric or {}).get("cvssData") or {}
    cvss_score = cvss_data.get("baseScore")
    severity = ((metric or {}).get("baseSeverity") or cvss_data.get("baseSeverity") or "unknown").lower()
    references = cve.get("references") or []
    patch_reference = any("Patch" in (reference.get("tags") or []) for reference in references)
    weaknesses = []
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = description.get("value")
            if value and value not in weaknesses: weaknesses.append(value)
    cisa_kev = bool(cve.get("cisaExploitAdd"))
    detail_parts = []
    if cvss_score is not None: detail_parts.append(f"CVSS {metric_version} {cvss_score} {severity}")
    if cisa_kev: detail_parts.append("CISA KEV listed")
    if patch_reference: detail_parts.append("NVD patch reference present")
    detail_parts.append(f"status {cve.get('vulnStatus') or 'unknown'}")
    return {"name": "nvd", "malicious": False,
            "score": round(float(cvss_score or 0) / 10.0, 3), "mode": "live",
            "detail": " · ".join(detail_parts), "record_status": "found",
            "cvss_score": cvss_score, "cvss_severity": severity, "cvss_version": metric_version,
            "vuln_status": cve.get("vulnStatus"), "published": cve.get("published"),
            "last_modified": cve.get("lastModified"), "cisa_kev": cisa_kev,
            "cisa_exploit_add": cve.get("cisaExploitAdd"), "patch_reference": patch_reference,
            "weaknesses": weaknesses[:8], "source_url": f"https://nvd.nist.gov/vuln/detail/{ioc.upper()}"}
def check_nvd(ioc, ioc_type):
    if not NVD_ENABLED or ioc_type != "cve":
        return {"name": "nvd", "malicious": False, "score": 0.0, "mode": "disabled"}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        with httpx.Client(timeout=15) as client:
            response = client.get(NVD_CVE_API_URL, params={"cveId": ioc.upper()}, headers=headers)
            response.raise_for_status()
            return _nvd_result(ioc, response.json())
    except Exception as exc:
        return _mock_or_unavailable("nvd", ioc, _error_detail(exc))
def check_threatfox(ioc, ioc_type):
    if not THREATFOX_ENABLED: return {"name": "threatfox", "malicious": False, "score": 0.0, "mode": "disabled"}
    try:
        headers = {"Auth-Key": THREATFOX_API_KEY} if THREATFOX_API_KEY else {}
        with httpx.Client(timeout=10) as client:
            resp = client.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": ioc}, headers=headers)
            resp.raise_for_status(); data = resp.json(); found = data.get("query_status") == "ok" and bool(data.get("data"))
            malware_names = [e["malware_printable"] for e in data.get("data", [])[:3] if e.get("malware_printable")] if found else []
            result = {"name": "threatfox", "malicious": found, "score": 0.95 if found else 0.0, "mode": "live"}
            if malware_names: result["detail"] = "ThreatFox malware family: " + ", ".join(malware_names)
            return result
    except Exception as exc: return _mock_or_unavailable("threatfox", ioc, _error_detail(exc))
def check_urlhaus(ioc, ioc_type):
    if not URLHAUS_ENABLED or ioc_type not in ("url", "domain"): return {"name": "urlhaus", "malicious": False, "score": 0.0, "mode": "disabled"}
    try:
        headers = {"Auth-Key": URLHAUS_API_KEY} if URLHAUS_API_KEY else {}
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/" if ioc_type == "url" else "https://urlhaus-api.abuse.ch/v1/host/"
        field = "url" if ioc_type == "url" else "host"
        with httpx.Client(timeout=10) as client:
            resp = client.post(endpoint, data={field: ioc}, headers=headers)
            resp.raise_for_status(); data = resp.json()
            found = data.get("query_status") == "ok" and (ioc_type == "url" or int(data.get("url_count", 0) or 0) > 0)
            return {"name": "urlhaus", "malicious": found, "score": 0.9 if found else 0.0, "mode": "live"}
    except Exception as exc: return _mock_or_unavailable("urlhaus", ioc, _error_detail(exc))
def check_crowdsec(ioc, ioc_type):
    if not CROWDSEC_ENABLED or ioc_type != "ip": return {"name": "crowdsec", "malicious": False, "score": 0.0, "mode": "disabled"}
    if not CROWDSEC_API_KEY: return _mock_or_unavailable("crowdsec", ioc, "API key not configured")
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(f"{CROWDSEC_CTI_BASE_URL.rstrip('/')}/smoke/{ioc}", headers={"x-api-key": CROWDSEC_API_KEY})
            if resp.status_code == 404: return {"name": "crowdsec", "malicious": False, "score": 0.0, "mode": "live"}
            resp.raise_for_status(); data = resp.json()
            bn = data.get("background_noise_score", 0); ag = data.get("scores", {}).get("overall", {}).get("aggressiveness", 0)
            score = round(min(1.0, max(bn, ag) / 5.0), 3); malicious = data.get("reputation") == "malicious" or ag >= 3
            return {"name": "crowdsec", "malicious": malicious, "score": score, "mode": "live"}
    except Exception as exc: return _mock_or_unavailable("crowdsec", ioc, _error_detail(exc))
def check_crowdsec_watchlist(ioc):
    watchlist = [ip.strip() for ip in os.getenv("CROWDSEC_WATCHLIST_IPS", "").split(",") if ip.strip()]
    if ioc in watchlist: return {"name": "crowdsec_watchlist", "malicious": True, "score": 0.99, "mode": "live", "detail": "IP in watchlist"}
    return None
_STIX_VALUE_RE = re.compile(r"=\s*'((?:\\.|[^'])*)'")
def _cyfirma_headers() -> dict[str, str]:
    if CYFIRMA_API_KEY_HEADER.lower() == "authorization":
        return {"Authorization": f"Bearer {CYFIRMA_API_KEY}"}
    return {CYFIRMA_API_KEY_HEADER: CYFIRMA_API_KEY}
def _extract_stix_pattern_values(pattern: str) -> set[str]:
    """Extract every literal from a STIX pattern, including compound OR patterns."""
    return {value.replace("\\'", "'").replace("\\\\", "\\").strip()
            for value in _STIX_VALUE_RE.findall(pattern or "") if value.strip()}
def _fetch_cyfirma_indicators(path, deadline):
    indicators = set(); url = f"{CYFIRMA_BASE_URL.rstrip('/')}{path}"; params = {}; page = 0
    with httpx.Client(timeout=30, verify=CYFIRMA_VERIFY_SSL) as client:
        while page < CYFIRMA_MAX_PAGES and time.time() < deadline:
            resp = client.get(url, headers=_cyfirma_headers(), params=params)
            resp.raise_for_status(); data = resp.json()
            for obj in data.get("objects", []):
                indicators.update(_extract_stix_pattern_values(obj.get("pattern", "")))
            page += 1; next_cursor = data.get("next") or data.get("more")
            if not next_cursor: break
            params = {"next": next_cursor}
    return indicators
def _refresh_cyfirma_feed():
    if not _cyfirma_refresh_lock.acquire(blocking=False): return _cyfirma_feed_cache["indicators"]
    try:
        return _refresh_cyfirma_feed_locked()
    finally:
        _cyfirma_refresh_lock.release()
def _refresh_cyfirma_feed_locked():
    now = time.time()
    if _cyfirma_feed_cache["indicators"] and (now - _cyfirma_feed_cache["fetched_at"]) < CYFIRMA_CACHE_TTL: return _cyfirma_feed_cache["indicators"]
    if not CYFIRMA_API_KEY: return _cyfirma_feed_cache["indicators"]
    if (now - float(_cyfirma_feed_cache["last_attempt"] or 0)) < CYFIRMA_ERROR_BACKOFF_SECONDS:
        return _cyfirma_feed_cache["indicators"]
    _cyfirma_feed_cache["last_attempt"] = now
    deadline = now + CYFIRMA_MAX_SECONDS; merged = set()
    errors = []
    try: merged |= _fetch_cyfirma_indicators(CYFIRMA_TAILORED_IOC_PATH, deadline)
    except Exception as exc: errors.append(f"tailored: {_error_detail(exc)}")
    try:
        if time.time() < deadline: merged |= _fetch_cyfirma_indicators(CYFIRMA_GLOBAL_IOC_PATH, deadline)
    except Exception as exc: errors.append(f"global: {_error_detail(exc)}")
    if merged:
        _cyfirma_feed_cache["indicators"] = merged
        _cyfirma_feed_cache["fetched_at"] = now
        _cyfirma_feed_cache["last_error"] = None
    elif errors:
        _cyfirma_feed_cache["last_error"] = "; ".join(errors)
    return _cyfirma_feed_cache["indicators"]
def warm_cyfirma_feed() -> None:
    if CYFIRMA_ENABLED and CYFIRMA_API_KEY: _refresh_cyfirma_feed()
def check_cyfirma(ioc, ioc_type):
    if not CYFIRMA_ENABLED: return {"name": "cyfirma", "malicious": False, "score": 0.0, "mode": "disabled"}
    if not CYFIRMA_API_KEY: return _mock_or_unavailable("cyfirma", ioc, "API key not configured")
    try:
        indicators = _cyfirma_feed_cache["indicators"]
        age = time.time() - float(_cyfirma_feed_cache["fetched_at"] or 0)
        if not indicators:
            threading.Thread(target=warm_cyfirma_feed, daemon=True).start()
            return _unavailable_result("cyfirma", _cyfirma_feed_cache.get("last_error") or "IOC feed is warming")
        if age >= CYFIRMA_CACHE_TTL:
            threading.Thread(target=warm_cyfirma_feed, daemon=True).start()
        found = ioc in indicators
        return {"name": "cyfirma", "malicious": found, "score": 0.95 if found else 0.0,
                "mode": "live" if age < CYFIRMA_CACHE_TTL else "stale_cache",
                "detail": None if age < CYFIRMA_CACHE_TTL else f"cached feed age {round(age)}s"}
    except Exception as exc: return _mock_or_unavailable("cyfirma", ioc, _error_detail(exc))
PROVIDERS_BY_TYPE = {
    "ip": [check_virustotal, check_abuseipdb, check_otx, check_threatfox, check_crowdsec, check_cyfirma],
    "domain": [check_virustotal, check_otx, check_urlhaus, check_cyfirma],
    "hash": [check_virustotal, check_otx, check_cyfirma],
    "url": [check_virustotal, check_urlhaus, check_threatfox, check_cyfirma],
    "cve": [check_nvd, check_otx],
}
def run_all_providers(ioc, ioc_type):
    results = []
    if ioc_type == "ip":
        w = check_crowdsec_watchlist(ioc)
        if w: results.append(w)
    checks = PROVIDERS_BY_TYPE.get(ioc_type, PROVIDERS_BY_TYPE["ip"])
    ordered: list[dict | None] = [None] * len(checks)
    futures = {_PROVIDER_EXECUTOR.submit(check, ioc, ioc_type): index for index, check in enumerate(checks)}
    for future in as_completed(futures):
        index = futures[future]
        try: ordered[index] = future.result()
        except Exception as exc: ordered[index] = _unavailable_result(checks[index].__name__, _error_detail(exc))
    for result in ordered:
        if not result: continue
        if result.get("mode") != "disabled":
            results.append(result)
            checked_at = time.time()
            name = result.get("name", "unknown")
            with _provider_runtime_lock:
                runtime = _provider_runtime.setdefault(name, {"by_ioc_type": {}})
                runtime["by_ioc_type"][ioc_type] = {
                    "mode": result.get("mode", "unknown"), "last_checked": checked_at,
                    "detail": result.get("detail"),
                }
    return results
def provider_statuses() -> dict:
    configured = {
        "virustotal": (VT_ENABLED, bool(VT_API_KEY)), "abuseipdb": (ABUSEIPDB_ENABLED, bool(ABUSEIPDB_API_KEY)),
        "otx": (OTX_ENABLED, bool(OTX_API_KEY)), "threatfox": (THREATFOX_ENABLED, bool(THREATFOX_API_KEY)),
        "urlhaus": (URLHAUS_ENABLED, bool(URLHAUS_API_KEY)), "crowdsec": (CROWDSEC_ENABLED, bool(CROWDSEC_API_KEY)),
        "cyfirma": (CYFIRMA_ENABLED, bool(CYFIRMA_API_KEY)),
        "nvd": (NVD_ENABLED, bool(NVD_API_KEY)),
    }
    output = {}
    for name, (enabled, has_key) in configured.items():
        with _provider_runtime_lock:
            by_type = dict((_provider_runtime.get(name) or {}).get("by_ioc_type") or {})
        if not enabled:
            mode = "disabled"
        elif not by_type:
            mode = "configured" if has_key else "unavailable"
        else:
            tested_modes = {entry.get("mode", "unknown") for entry in by_type.values()}
            if tested_modes == {"live"}: mode = "live"
            elif tested_modes == {"unavailable"}: mode = "unavailable"
            elif tested_modes == {"stale_cache"}: mode = "stale_cache"
            else: mode = "partial"
        latest_type, latest = max(by_type.items(), key=lambda item: item[1].get("last_checked", 0), default=(None, {}))
        failures = [f"{ioc_type}: {entry.get('detail') or entry.get('mode')}"
                    for ioc_type, entry in sorted(by_type.items()) if entry.get("mode") == "unavailable"]
        output[name] = {"enabled": enabled, "mode": mode, "last_checked": latest.get("last_checked"),
                        "last_ioc_type": latest_type, "detail": "; ".join(failures) or latest.get("detail"),
                        "by_ioc_type": by_type}
    return output
def detect_apt_indicator(ioc_hits: list[dict]) -> Optional[str]:
    for hit in ioc_hits:
        detail = (hit.get("detail") or "").lower()
        for marker in _APT_NAME_MARKERS:
            if marker in detail: return hit.get("detail")
    return None
