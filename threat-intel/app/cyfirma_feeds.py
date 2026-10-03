from __future__ import annotations
import html, logging, os, re, time, uuid
from datetime import datetime, timedelta, timezone
import httpx
from . import db
from . import redis_client
logger = logging.getLogger("threat-intel.cyfirma_feeds")
CYFIRMA_API_KEY = os.getenv("CYFIRMA_API_KEY", ""); CYFIRMA_VERIFY_SSL = os.getenv("CYFIRMA_VERIFY_SSL", "true").lower() == "true"
CYFIRMA_API_KEY_HEADER = os.getenv("CYFIRMA_API_KEY_HEADER", "x-api-key")
ORG_VULN_ENABLED = os.getenv("CYFIRMA_ORG_VULN_ENABLED", "false").lower() == "true"
ORG_VULN_API_KEY = os.getenv("CYFIRMA_ORG_VULN_API_KEY", CYFIRMA_API_KEY); ORG_VULN_URL = os.getenv("CYFIRMA_ORG_VULN_URL", "")
ORG_VULN_API_KEY_HEADER = os.getenv("CYFIRMA_ORG_VULN_API_KEY_HEADER", CYFIRMA_API_KEY_HEADER)
ORG_VULN_INTERVAL_SECONDS = int(os.getenv("CYFIRMA_ORG_VULN_INTERVAL_SECONDS", "21600"))
ORG_VULN_LOOKBACK_DAYS = int(os.getenv("CYFIRMA_ORG_VULN_LOOKBACK_DAYS", "30")); ORG_VULN_PAGE_SIZE = int(os.getenv("CYFIRMA_ORG_VULN_PAGE_SIZE", "50"))
RESEARCH_ENABLED = os.getenv("CYFIRMA_RESEARCH_ENABLED", "false").lower() == "true"; RESEARCH_URL = os.getenv("CYFIRMA_RESEARCH_URL", "")
RESEARCH_API_KEY_HEADER = os.getenv("CYFIRMA_RESEARCH_API_KEY_HEADER", CYFIRMA_API_KEY_HEADER)
RESEARCH_AUTH_ENABLED = os.getenv("CYFIRMA_RESEARCH_AUTH_ENABLED", "false").lower() == "true"
RESEARCH_INTERVAL_SECONDS = int(os.getenv("CYFIRMA_RESEARCH_INTERVAL_SECONDS", "21600")); RESEARCH_MAX_ITEMS = int(os.getenv("CYFIRMA_RESEARCH_MAX_ITEMS", "25"))
TAXII_ENABLED = os.getenv("CYFIRMA_TAXII_ENABLED", "false").lower() == "true"
TAXII_COLLECTION_URL = os.getenv("CYFIRMA_TAXII_COLLECTION_URL", ""); TAXII_BEARER_TOKEN = os.getenv("CYFIRMA_TAXII_BEARER_TOKEN", "")
TAXII_USERNAME = os.getenv("CYFIRMA_TAXII_USERNAME", ""); TAXII_PASSWORD = os.getenv("CYFIRMA_TAXII_PASSWORD", "")
TAXII_MAX_PAGES = int(os.getenv("CYFIRMA_TAXII_MAX_PAGES", "2"))
_ZERO_DAY_MARKERS = ("zero-day", "zero day", "0-day", "0day", "actively exploited", "in the wild", "no patch")
_stats = {"org_vuln_polls": 0, "org_vuln_new": 0, "org_vuln_errors": 0, "org_vuln_zero_day_count": 0,
          "org_vuln_last_success": None, "org_vuln_last_error": None,
          "research_polls": 0, "research_new": 0, "research_errors": 0,
          "research_last_success": None, "research_last_error": None,
          "taxii_polls": 0, "taxii_objects": 0, "taxii_errors": 0,
          "taxii_last_success": None, "taxii_last_error": None}
def _auth_headers(header_name: str, key: str) -> dict[str, str]:
    if not key: return {}
    if header_name.lower() == "authorization": return {"Authorization": f"Bearer {key}"}
    return {header_name: key}
def _configuration_status(enabled: bool, url: str, key: str = "") -> str:
    if not enabled: return "disabled"
    if not url: return "missing_url"
    if key == "": return "missing_api_key"
    return "configured"
def get_stats() -> dict:
    org_status = _configuration_status(ORG_VULN_ENABLED, ORG_VULN_URL, ORG_VULN_API_KEY)
    research_status = _configuration_status(
        RESEARCH_ENABLED, RESEARCH_URL, CYFIRMA_API_KEY if RESEARCH_AUTH_ENABLED else "public_feed")
    taxii_credentials = TAXII_BEARER_TOKEN or (TAXII_PASSWORD if TAXII_USERNAME else "")
    taxii_status = _configuration_status(TAXII_ENABLED, TAXII_COLLECTION_URL, taxii_credentials)
    if org_status == "configured" and _stats["org_vuln_last_error"] in ("HTTP 401", "HTTP 403"):
        org_status = "authentication_failed"
    if research_status == "configured" and _stats["research_last_error"] == "invalid_json_endpoint":
        research_status = "invalid_json_endpoint"
    if taxii_status == "configured" and _stats["taxii_last_error"]:
        taxii_status = "runtime_error"
    return {**_stats, "org_vuln_config_status": org_status,
            "research_config_status": research_status, "taxii_config_status": taxii_status}
def _safe_error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError): return f"HTTP {exc.response.status_code}"
    if isinstance(exc, ValueError) and "JSON" in str(exc): return "invalid_json_endpoint"
    return type(exc).__name__
def _is_zero_day(item: dict) -> bool:
    if item.get("zero_day") is True: return True
    text = f"{item.get('name', '')} {item.get('title', '')} {item.get('description', '')}".lower()
    return any(marker in text for marker in _ZERO_DAY_MARKERS)
def poll_org_vulnerabilities_once() -> int:
    if not ORG_VULN_ENABLED: return 0
    if not ORG_VULN_URL or not ORG_VULN_API_KEY: return 0
    since = (datetime.now(timezone.utc) - timedelta(days=ORG_VULN_LOOKBACK_DAYS)).isoformat(); new_count = 0
    _stats["org_vuln_polls"] += 1
    try:
        with httpx.Client(timeout=30, verify=CYFIRMA_VERIFY_SSL) as client:
            resp = client.get(ORG_VULN_URL, headers=_auth_headers(ORG_VULN_API_KEY_HEADER, ORG_VULN_API_KEY),
                              params={"since": since, "limit": ORG_VULN_PAGE_SIZE})
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
        _stats["org_vuln_new"] += new_count
        _stats["org_vuln_last_success"] = datetime.now(timezone.utc).isoformat(); _stats["org_vuln_last_error"] = None
    except Exception as exc:
        _stats["org_vuln_errors"] += 1; _stats["org_vuln_last_error"] = _safe_error(exc)
        logger.warning("CYFIRMA org vulnerability poll failed: %s", _safe_error(exc))
    return new_count
def org_vuln_loop() -> None:
    if not ORG_VULN_ENABLED: return
    while True: poll_org_vulnerabilities_once(); time.sleep(ORG_VULN_INTERVAL_SECONDS)
def poll_research_once() -> int:
    if not RESEARCH_ENABLED: return 0
    if not RESEARCH_URL: return 0
    new_count = 0
    _stats["research_polls"] += 1
    try:
        with httpx.Client(timeout=30, verify=CYFIRMA_VERIFY_SSL) as client:
            headers = {"Accept": "application/json", "User-Agent": "AgenticSOC/1.0"}
            if RESEARCH_AUTH_ENABLED:
                headers.update(_auth_headers(RESEARCH_API_KEY_HEADER, CYFIRMA_API_KEY))
            resp = client.get(RESEARCH_URL, headers=headers); resp.raise_for_status()
            content_type = resp.headers.get("content-type", "").lower()
            if "json" not in content_type:
                raise ValueError("configured research URL is not a JSON API endpoint")
            try: data = resp.json()
            except ValueError as exc: raise ValueError("invalid JSON research response") from exc
            items = data.get("items", data.get("articles", [])) if isinstance(data, dict) else data
            if not isinstance(items, list): raise ValueError("invalid JSON research response")
            for item in items[:RESEARCH_MAX_ITEMS]:
                if not isinstance(item, dict): continue
                title, url, summary, published_at = _research_item_fields(item)
                if not url: continue
                if db.upsert_research_item(title=title, url=url, summary=summary, published_at=published_at, raw_payload=item): new_count += 1
        _stats["research_new"] += new_count
        _stats["research_last_success"] = datetime.now(timezone.utc).isoformat(); _stats["research_last_error"] = None
    except Exception as exc:
        _stats["research_errors"] += 1; _stats["research_last_error"] = _safe_error(exc)
        logger.warning("CYFIRMA research poll failed: %s", _safe_error(exc))
    return new_count
def research_loop() -> None:
    if not RESEARCH_ENABLED: return
    while True: poll_research_once(); time.sleep(RESEARCH_INTERVAL_SECONDS)


def _plain_research_text(value) -> str:
    if isinstance(value, dict): value = value.get("rendered", "")
    if value is None: return ""
    text = re.sub(r"<[^>]+>", " ", str(value))
    text = " ".join(html.unescape(text).split())
    return re.sub(r"\s+([.,;:!?])", r"\1", text)


def _research_item_fields(item: dict) -> tuple[str, str, str, str | None]:
    title = _plain_research_text(item.get("title")) or "Untitled"
    url = str(item.get("url") or item.get("link") or "").strip()
    summary = _plain_research_text(item.get("summary") or item.get("excerpt") or item.get("description"))
    published_at = item.get("published_at") or item.get("date_gmt") or item.get("date")
    if isinstance(published_at, str) and published_at and not re.search(r"(?:Z|[+-]\d\d:\d\d)$", published_at):
        published_at = f"{published_at}Z"
    return title, url, summary, published_at
def poll_taxii_once() -> int:
    if not TAXII_ENABLED: return 0
    if not TAXII_COLLECTION_URL or not (TAXII_BEARER_TOKEN or (TAXII_USERNAME and TAXII_PASSWORD)): return 0
    object_count = 0; next_token = None
    try:
        headers = {"Accept": "application/taxii+json;version=2.1", "User-Agent": "AgenticSOC/1.0"}
        auth = httpx.BasicAuth(TAXII_USERNAME, TAXII_PASSWORD) if TAXII_USERNAME and TAXII_PASSWORD else None
        if TAXII_BEARER_TOKEN: headers["Authorization"] = f"Bearer {TAXII_BEARER_TOKEN}"
        with httpx.Client(timeout=30, verify=CYFIRMA_VERIFY_SSL) as client:
            for _ in range(max(1, TAXII_MAX_PAGES)):
                params = {"next": next_token} if next_token else None
                resp = client.get(TAXII_COLLECTION_URL, headers=headers, auth=auth, params=params)
                resp.raise_for_status(); data = resp.json(); objects = data.get("objects", [])
                if not isinstance(objects, list): raise ValueError("invalid JSON TAXII response")
                object_count += len(objects)
                if not data.get("more"): break
                next_token = data.get("next")
                if not next_token: raise ValueError("invalid JSON TAXII pagination response")
        _stats["taxii_polls"] += 1; _stats["taxii_objects"] += object_count
        _stats["taxii_last_success"] = datetime.now(timezone.utc).isoformat(); _stats["taxii_last_error"] = None
    except Exception as exc:
        _stats["taxii_errors"] += 1; _stats["taxii_last_error"] = _safe_error(exc)
        logger.warning("CYFIRMA TAXII poll failed: %s", _safe_error(exc))
    return object_count
def taxii_loop() -> None:
    if not TAXII_ENABLED: return
    while True: poll_taxii_once(); time.sleep(3600)
