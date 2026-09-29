from __future__ import annotations
import hashlib, logging, os, time
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
CYFIRMA_TAILORED_IOC_PATH = os.getenv("CYFIRMA_TAILORED_IOC_PATH", "/api/ex/v3/da/stix/2.1/indicators/tailored")
CYFIRMA_GLOBAL_IOC_PATH = os.getenv("CYFIRMA_GLOBAL_IOC_PATH", "/api/ex/v3/da/stix/2.1/indicators/all")
CYFIRMA_VERIFY_SSL = os.getenv("CYFIRMA_VERIFY_SSL", "true").lower() == "true"
CYFIRMA_CACHE_TTL = int(os.getenv("CYFIRMA_CACHE_TTL", "1800")); CYFIRMA_MAX_PAGES = int(os.getenv("CYFIRMA_MAX_PAGES", "10"))
CYFIRMA_MAX_SECONDS = int(os.getenv("CYFIRMA_MAX_SECONDS", "90"))
_cyfirma_feed_cache = {"fetched_at": 0.0, "indicators": set()}
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
def check_virustotal(ioc, ioc_type):
    if not VT_ENABLED: return {"name": "virustotal", "malicious": False, "score": 0.0, "mode": "disabled"}
    if not VT_API_KEY: return _mock_or_unavailable("virustotal", ioc, "API key not configured")
    try:
        endpoint = {"ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}", "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
                    "hash": f"https://www.virustotal.com/api/v3/files/{ioc}", "url": "https://www.virustotal.com/api/v3/urls"}.get(ioc_type)
        if not endpoint: return _unavailable_result("virustotal", "unsupported IOC type")
        with httpx.Client(timeout=10) as client:
            resp = client.get(endpoint, headers={"x-apikey": VT_API_KEY}); resp.raise_for_status(); data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0); total = sum(stats.values()) or 1
            score = round(malicious_count / total, 3)
            return {"name": "virustotal", "malicious": malicious_count >= 2 and score >= 0.05,
                    "score": score, "mode": "live", "detections": malicious_count, "engines": total}
    except Exception as exc: return _mock_or_unavailable("virustotal", ioc, type(exc).__name__)
def check_abuseipdb(ioc, ioc_type):
    if not ABUSEIPDB_ENABLED or ioc_type != "ip": return {"name": "abuseipdb", "malicious": False, "score": 0.0, "mode": "disabled"}
    if not ABUSEIPDB_API_KEY: return _mock_or_unavailable("abuseipdb", ioc, "API key not configured")
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ioc, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"})
            resp.raise_for_status(); data = resp.json().get("data", {}); score = round(data.get("abuseConfidenceScore", 0) / 100.0, 3)
            return {"name": "abuseipdb", "malicious": score > 0.5, "score": score, "mode": "live"}
    except Exception as exc: return _mock_or_unavailable("abuseipdb", ioc, type(exc).__name__)
def check_otx(ioc, ioc_type):
    if not OTX_ENABLED: return {"name": "otx", "malicious": False, "score": 0.0, "mode": "disabled"}
    if not OTX_API_KEY: return _mock_or_unavailable("otx", ioc, "API key not configured")
    try:
        section = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url"}.get(ioc_type, "IPv4")
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
    except Exception as exc: return _mock_or_unavailable("otx", ioc, type(exc).__name__)
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
    except Exception as exc: return _mock_or_unavailable("threatfox", ioc, type(exc).__name__)
def check_urlhaus(ioc, ioc_type):
    if not URLHAUS_ENABLED or ioc_type not in ("url", "domain"): return {"name": "urlhaus", "malicious": False, "score": 0.0, "mode": "disabled"}
    try:
        headers = {"Auth-Key": URLHAUS_API_KEY} if URLHAUS_API_KEY else {}
        with httpx.Client(timeout=10) as client:
            resp = client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": ioc}, headers=headers)
            resp.raise_for_status(); data = resp.json(); found = data.get("query_status") == "ok" and int(data.get("url_count", 0) or 0) > 0
            return {"name": "urlhaus", "malicious": found, "score": 0.9 if found else 0.0, "mode": "live"}
    except Exception as exc: return _mock_or_unavailable("urlhaus", ioc, type(exc).__name__)
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
    except Exception as exc: return _mock_or_unavailable("crowdsec", ioc, type(exc).__name__)
def check_crowdsec_watchlist(ioc):
    watchlist = [ip.strip() for ip in os.getenv("CROWDSEC_WATCHLIST_IPS", "").split(",") if ip.strip()]
    if ioc in watchlist: return {"name": "crowdsec_watchlist", "malicious": True, "score": 0.99, "mode": "live", "detail": "IP in watchlist"}
    return None
def _fetch_cyfirma_indicators(path, deadline):
    indicators = set(); url = f"{CYFIRMA_BASE_URL.rstrip('/')}{path}"; params = {}; page = 0
    with httpx.Client(timeout=30, verify=CYFIRMA_VERIFY_SSL) as client:
        while page < CYFIRMA_MAX_PAGES and time.time() < deadline:
            resp = client.get(url, headers={"Authorization": f"Bearer {CYFIRMA_API_KEY}"}, params=params)
            resp.raise_for_status(); data = resp.json()
            for obj in data.get("objects", []):
                pattern = obj.get("pattern", "")
                if "=" in pattern: indicators.add(pattern.split("=", 1)[1].strip(" ]'\""))
            page += 1; next_cursor = data.get("next") or data.get("more")
            if not next_cursor: break
            params = {"next": next_cursor}
    return indicators
def _refresh_cyfirma_feed():
    now = time.time()
    if _cyfirma_feed_cache["indicators"] and (now - _cyfirma_feed_cache["fetched_at"]) < CYFIRMA_CACHE_TTL: return _cyfirma_feed_cache["indicators"]
    if not CYFIRMA_API_KEY: return _cyfirma_feed_cache["indicators"]
    deadline = now + CYFIRMA_MAX_SECONDS; merged = set()
    try: merged |= _fetch_cyfirma_indicators(CYFIRMA_TAILORED_IOC_PATH, deadline)
    except Exception: pass
    try:
        if time.time() < deadline: merged |= _fetch_cyfirma_indicators(CYFIRMA_GLOBAL_IOC_PATH, deadline)
    except Exception: pass
    if merged: _cyfirma_feed_cache["indicators"] = merged; _cyfirma_feed_cache["fetched_at"] = now
    return _cyfirma_feed_cache["indicators"]
def check_cyfirma(ioc, ioc_type):
    if not CYFIRMA_ENABLED: return {"name": "cyfirma", "malicious": False, "score": 0.0, "mode": "disabled"}
    if not CYFIRMA_API_KEY: return _mock_or_unavailable("cyfirma", ioc, "API key not configured")
    try:
        indicators = _refresh_cyfirma_feed(); found = ioc in indicators
        return {"name": "cyfirma", "malicious": found, "score": 0.95 if found else 0.0,
                "mode": "live" if indicators else "unavailable"}
    except Exception as exc: return _mock_or_unavailable("cyfirma", ioc, type(exc).__name__)
PROVIDERS_BY_TYPE = {
    "ip": [check_virustotal, check_abuseipdb, check_otx, check_threatfox, check_crowdsec, check_cyfirma],
    "domain": [check_virustotal, check_otx, check_urlhaus, check_cyfirma],
    "hash": [check_virustotal, check_otx, check_cyfirma],
    "url": [check_virustotal, check_urlhaus, check_threatfox, check_cyfirma],
    "cve": [check_otx],
}
def run_all_providers(ioc, ioc_type):
    results = []
    if ioc_type == "ip":
        w = check_crowdsec_watchlist(ioc)
        if w: results.append(w)
    for check in PROVIDERS_BY_TYPE.get(ioc_type, PROVIDERS_BY_TYPE["ip"]):
        result = check(ioc, ioc_type)
        if result.get("mode") != "disabled": results.append(result)
    return results
def detect_apt_indicator(ioc_hits: list[dict]) -> Optional[str]:
    for hit in ioc_hits:
        detail = (hit.get("detail") or "").lower()
        for marker in _APT_NAME_MARKERS:
            if marker in detail: return hit.get("detail")
    return None
