from __future__ import annotations
import logging, os, time, uuid
from datetime import datetime, timedelta, timezone
import httpx
from . import db
from . import redis_client
logger = logging.getLogger("threat-intel.cyfirma_feeds")
CYFIRMA_API_KEY = os.getenv("CYFIRMA_API_KEY", ""); CYFIRMA_VERIFY_SSL = os.getenv("CYFIRMA_VERIFY_SSL", "true").lower() == "true"
ORG_VULN_ENABLED = os.getenv("CYFIRMA_ORG_VULN_ENABLED", "false").lower() == "true"
ORG_VULN_API_KEY = os.getenv("CYFIRMA_ORG_VULN_API_KEY", CYFIRMA_API_KEY); ORG_VULN_URL = os.getenv("CYFIRMA_ORG_VULN_URL", "")
ORG_VULN_INTERVAL_SECONDS = int(os.getenv("CYFIRMA_ORG_VULN_INTERVAL_SECONDS", "21600"))
ORG_VULN_LOOKBACK_DAYS = int(os.getenv("CYFIRMA_ORG_VULN_LOOKBACK_DAYS", "30")); ORG_VULN_PAGE_SIZE = int(os.getenv("CYFIRMA_ORG_VULN_PAGE_SIZE", "50"))
RESEARCH_ENABLED = os.getenv("CYFIRMA_RESEARCH_ENABLED", "false").lower() == "true"; RESEARCH_URL = os.getenv("CYFIRMA_RESEARCH_URL", "")
RESEARCH_INTERVAL_SECONDS = int(os.getenv("CYFIRMA_RESEARCH_INTERVAL_SECONDS", "21600")); RESEARCH_MAX_ITEMS = int(os.getenv("CYFIRMA_RESEARCH_MAX_ITEMS", "25"))
TAXII_ENABLED = os.getenv("CYFIRMA_TAXII_ENABLED", "false").lower() == "true"
TAXII_COLLECTION_URL = os.getenv("CYFIRMA_TAXII_COLLECTION_URL", ""); TAXII_BEARER_TOKEN = os.getenv("CYFIRMA_TAXII_BEARER_TOKEN", "")
TAXII_MAX_PAGES = int(os.getenv("CYFIRMA_TAXII_MAX_PAGES", "2"))
_ZERO_DAY_MARKERS = ("zero-day", "zero day", "0-day", "0day", "actively exploited", "in the wild", "no patch")
_stats = {"org_vuln_polls": 0, "org_vuln_new": 0, "org_vuln_errors": 0, "org_vuln_zero_day_count": 0,
          "research_polls": 0, "research_new": 0, "research_errors": 0, "taxii_polls": 0, "taxii_objects": 0, "taxii_errors": 0}
def get_stats() -> dict: return dict(_stats)
def _is_zero_day(item: dict) -> bool:
    if item.get("zero_day") is True: return True
    text = f"{item.get('name', '')} {item.get('title', '')} {item.get('description', '')}".lower()
    return any(marker in text for marker in _ZERO_DAY_MARKERS)
def poll_org_vulnerabilities_once() -> int:
    if not ORG_VULN_ENABLED: return 0
    if not ORG_VULN_URL or not ORG_VULN_API_KEY: return 0
    since = (datetime.now(timezone.utc) - timedelta(days=ORG_VULN_LOOKBACK_DAYS)).isoformat(); new_count = 0
    try:
        with httpx.Client(timeout=30, verify=CYFIRMA_VERIFY_SSL) as client:
            resp = client.get(ORG_VULN_URL, headers={"Authorization": f"Bearer {ORG_VULN_API_KEY}"}, params={"since": since, "limit": ORG_VULN_PAGE_SIZE})
            resp.raise_for_status(); data = resp.json()
            items = data.get("objects", data.get("vulnerabilities", data if isinstance(data, list) else []))
            for item in items[:ORG_VULN_PAGE_SIZE]:
                cve = item.get("cve") or item.get("cve_id") or "UNKNOWN-CVE"; severity = str(item.get("severity", "medium")).lower()
                title = item.get("name") or item.get("title") or cve; description = item.get("description", ""); zero_day = _is_zero_day(item)
                is_new = db.upsert_org_vulnerability(cve=cve, severity=severity, title=title, description=description,
                    is_zero_day=zero_day, detected_at=datetime.now(timezone.utc), raw_payload=item)
                if not is_new: continue
                new_count += 1
                if zero_day: _stats["org_vuln_zero_day_count"] += 1
                normalized_severity = "critical" if (severity == "critical" or zero_day) else "high" if severity == "high" else "medium" if severity == "medium" else "low"
                event_type = "zero_day" if zero_day else "vulnerability"; desc_text = f"{cve}: {title}".strip(": ")
                if zero_day: desc_text = f"ZERO-DAY / Actively Exploited: {desc_text}"
                event = {"id": f"evt-cyfirma-vuln-{uuid.uuid4().hex[:8]}", "source": "cyfirma_org_vuln", "type": event_type,
                         "severity": normalized_severity, "description": desc_text, "mitre_technique": [],
                         "time": datetime.now(timezone.utc).isoformat(), "raw": item, "raw_hash": cve,
                         "raw_kv": {"cve": cve, "provider": "cyfirma_org_vuln", "is_zero_day": zero_day}}
                redis_client.push_raw_event(event)
        _stats["org_vuln_polls"] += 1; _stats["org_vuln_new"] += new_count
    except Exception: _stats["org_vuln_errors"] += 1
    return new_count
def org_vuln_loop() -> None:
    if not ORG_VULN_ENABLED: return
    while True: poll_org_vulnerabilities_once(); time.sleep(ORG_VULN_INTERVAL_SECONDS)
def poll_research_once() -> int:
    if not RESEARCH_ENABLED: return 0
    if not RESEARCH_URL: return 0
    new_count = 0
    try:
        with httpx.Client(timeout=30, verify=CYFIRMA_VERIFY_SSL) as client:
            headers = {"Authorization": f"Bearer {CYFIRMA_API_KEY}"} if CYFIRMA_API_KEY else {}
            resp = client.get(RESEARCH_URL, headers=headers); resp.raise_for_status()
            try: data = resp.json()
            except ValueError: return 0
            items = data.get("items", data.get("articles", data if isinstance(data, list) else []))
            for item in items[:RESEARCH_MAX_ITEMS]:
                title = item.get("title", "Untitled"); url = item.get("url", item.get("link", ""))
                summary = item.get("summary", item.get("description", "")); published_at = item.get("published_at") or item.get("date")
                if db.upsert_research_item(title=title, url=url, summary=summary, published_at=published_at, raw_payload=item): new_count += 1
        _stats["research_polls"] += 1; _stats["research_new"] += new_count
    except Exception: _stats["research_errors"] += 1
    return new_count
def research_loop() -> None:
    if not RESEARCH_ENABLED: return
    while True: poll_research_once(); time.sleep(RESEARCH_INTERVAL_SECONDS)
def poll_taxii_once() -> int:
    if not TAXII_ENABLED: return 0
    if not TAXII_COLLECTION_URL or not TAXII_BEARER_TOKEN: return 0
    object_count = 0; next_url = TAXII_COLLECTION_URL
    try:
        with httpx.Client(timeout=30, verify=CYFIRMA_VERIFY_SSL) as client:
            for _ in range(max(1, TAXII_MAX_PAGES)):
                if not next_url: break
                resp = client.get(next_url, headers={"Authorization": f"Bearer {TAXII_BEARER_TOKEN}", "Accept": "application/taxii+json;version=2.1"})
                resp.raise_for_status(); data = resp.json(); objects = data.get("objects", []); object_count += len(objects)
                next_url = data.get("next") or None
        _stats["taxii_polls"] += 1; _stats["taxii_objects"] += object_count
    except Exception: _stats["taxii_errors"] += 1
    return object_count
def taxii_loop() -> None:
    if not TAXII_ENABLED: return
    while True: poll_taxii_once(); time.sleep(3600)
