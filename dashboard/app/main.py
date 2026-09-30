from __future__ import annotations
import asyncio, logging, os, time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID
import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from . import aggregations as agg
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("dashboard.main")
SOC_CORE_URL = os.getenv("SOC_CORE_URL", "http://soc-core:18200")
HERMES_URL = os.getenv("HERMES_URL", "http://hermes:8003")
M365_COLLECTOR_URL = os.getenv("M365_COLLECTOR_URL", "http://m365-collector:8006")
THREAT_INTEL_URL = os.getenv("THREAT_INTEL_URL", "http://threat-intel:8005")
SYSLOG_COLLECTOR_URL = os.getenv("SYSLOG_COLLECTOR_URL", "http://syslog-collector:38001")
JEV_URL = os.getenv("JEV_URL", "http://jev:20128")
QDRANT_URL = os.getenv("QDRANT_URL", "http://qdrant:6333")
FINDINGS_WINDOW_MINUTES = int(os.getenv("DASHBOARD_FINDINGS_WINDOW_MINUTES", "1440"))
DASHBOARD_UPSTREAM_TIMEOUT_SECONDS = float(os.getenv("DASHBOARD_UPSTREAM_TIMEOUT_SECONDS", "2.5"))
DASHBOARD_HEALTH_TIMEOUT_SECONDS = max(2.0, float(os.getenv("DASHBOARD_HEALTH_TIMEOUT_SECONDS", "3")))
DASHBOARD_HEALTH_GRACE_SECONDS = max(0.0, float(os.getenv("DASHBOARD_HEALTH_GRACE_SECONDS", "45")))
app = FastAPI(title="Agentic SOC Dashboard", version="4.0.0")
templates = Jinja2Templates(directory="app/templates")
@app.middleware("http")
async def disable_stale_dashboard_cache(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response
@app.get("/health")
async def health() -> dict: return {"status": "ok", "service": "dashboard"}
_SERVICES = {"Syslog Collector": f"{SYSLOG_COLLECTOR_URL}/health", "SOC Core": f"{SOC_CORE_URL}/health",
    "PostgreSQL": f"{SOC_CORE_URL}/health/database", "Hermes": f"{HERMES_URL}/health",
    "Jev (AI Reasoning)": f"{JEV_URL}/health", "Threat Intel": f"{THREAT_INTEL_URL}/health",
    "M365 Collector": f"{M365_COLLECTOR_URL}/health", "Qdrant Memory": f"{QDRANT_URL}/collections"}
_HEALTH_LAST_GOOD: dict[str, float] = {}
_HEALTH_CACHE: tuple[float, dict] | None = None
_HEALTH_LOCK = asyncio.Lock()
async def _ping(name: str, url: str, client: httpx.AsyncClient) -> dict:
    for attempt in range(2):
        start = time.monotonic()
        try:
            resp = await client.get(url, timeout=DASHBOARD_HEALTH_TIMEOUT_SECONDS)
            latency_ms = round((time.monotonic() - start) * 1000); ok = resp.status_code < 400
            try: upstream_status = str(resp.json().get("status") or "").lower()
            except Exception: upstream_status = ""
            degraded = upstream_status in {"degraded", "unavailable", "unreachable", "error"}
            if ok: _HEALTH_LAST_GOOD[name] = time.monotonic()
            return {"name": name, "status": "degraded" if degraded or not ok else "healthy", "latency_ms": latency_ms,
                    "attempts": attempt + 1, "stale_seconds": 0}
        except (httpx.TimeoutException, httpx.TransportError):
            if attempt == 0: await asyncio.sleep(0.12)
    stale_seconds = round(time.monotonic() - _HEALTH_LAST_GOOD.get(name, 0))
    if name in _HEALTH_LAST_GOOD and stale_seconds <= DASHBOARD_HEALTH_GRACE_SECONDS:
        return {"name": name, "status": "recovering", "latency_ms": None, "attempts": 2,
                "stale_seconds": stale_seconds}
    return {"name": name, "status": "unreachable", "latency_ms": None, "attempts": 2,
            "stale_seconds": None}
@app.get("/api/health")
async def api_health() -> dict:
    global _HEALTH_CACHE
    now = time.monotonic()
    if _HEALTH_CACHE and now - _HEALTH_CACHE[0] < 5: return _HEALTH_CACHE[1]
    async with _HEALTH_LOCK:
        now = time.monotonic()
        if _HEALTH_CACHE and now - _HEALTH_CACHE[0] < 5: return _HEALTH_CACHE[1]
        async with httpx.AsyncClient() as client:
            results = await asyncio.gather(*[_ping(name, url, client) for name, url in _SERVICES.items()])
        healthy = sum(1 for r in results if r["status"] in {"healthy", "recovering"})
        payload = {"services": results, "healthy_count": healthy, "total_count": len(results),
                   "checked_at": datetime.now(timezone.utc).isoformat()}
        _HEALTH_CACHE = (time.monotonic(), payload)
        return payload

_SETTING_GROUPS = (
    ("Platform & Dashboard", "Interface, logging, timezone, and dashboard behavior.", ("DASHBOARD_", "LOG_LEVEL", "TZ")),
    ("SOC Pipeline", "Filtering, queues, correlation, reporting, and delivery controls.",
     ("SOC_", "FILTER_", "QUEUE_", "AUTH_", "DOWNLOAD_")),
    ("Wazuh", "Indexer, manager API, alert, vulnerability, and FIM collection.", ("WAZUH_",)),
    ("Syslog", "UDP/TCP listener and collector API ports.", ("SYSLOG_",)),
    ("Hermes & AI", "Finding workers, Jev reasoning, model provider, and AI limits.", ("HERMES_", "AI_", "JEV_")),
    ("M365 & Defender XDR", "Microsoft audit and Defender XDR collection.", ("M365_", "DEFENDER_")),
    ("Threat Intelligence", "External intelligence providers, cache, and CYFIRMA feeds.",
     ("THREAT_INTEL_", "INTEL_", "CYFIRMA_", "NVD_", "VT_", "OTX_", "ABUSEIPDB_", "THREATFOX_",
      "URLHAUS_", "CROWDSEC_", "HUDSONROCK_", "RAPIDAPI_")),
    ("Storage & Memory", "PostgreSQL, Redis, Qdrant, and vector-memory configuration.",
     ("DATABASE_", "POSTGRES_", "REDIS_", "QDRANT_")),
)
_SECRET_MARKERS = ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "WEBHOOK", "DATABASE_URL")

def _setting_group(key: str) -> tuple[str, str] | None:
    for title, description, prefixes in _SETTING_GROUPS:
        if any(key == prefix or key.startswith(prefix) for prefix in prefixes): return title, description
    return None

def _safe_setting_value(key: str, value: str) -> tuple[str, bool]:
    secret = any(marker in key for marker in _SECRET_MARKERS)
    if secret: return ("Configured" if value else "Not configured"), True
    for env_key, env_value in os.environ.items():
        if env_value and len(env_value) >= 4 and any(marker in env_key for marker in _SECRET_MARKERS):
            value = value.replace(env_value, "***")
    if "://" in value:
        try:
            parsed = urlsplit(value)
            if parsed.username or parsed.password:
                host = parsed.hostname or ""
                if parsed.port: host += f":{parsed.port}"
                value = urlunsplit((parsed.scheme, f"***@{host}", parsed.path, parsed.query, parsed.fragment))
        except ValueError: pass
    return value if value else "Not configured", False

def _settings_inventory() -> list[dict]:
    grouped: dict[str, dict] = {title: {"name": title, "description": description, "settings": []}
                                for title, description, _ in _SETTING_GROUPS}
    for key in sorted(os.environ):
        group = _setting_group(key)
        if not group: continue
        value, secret = _safe_setting_value(key, os.environ.get(key, ""))
        grouped[group[0]]["settings"].append({"key": key, "label": key.replace("_", " ").title(),
            "value": value, "configured": bool(os.environ.get(key, "")), "secret": secret,
            "restart_required": True})
    return [grouped[title] for title, _, _ in _SETTING_GROUPS if grouped[title]["settings"]]

@app.get("/api/settings")
async def api_settings() -> dict:
    health_data = await api_health()
    async with httpx.AsyncClient() as client:
        hermes_stats, intel_providers, feed_stats = await asyncio.gather(
            _safe_get(client, f"{HERMES_URL}/stats", {}),
            _safe_get(client, f"{THREAT_INTEL_URL}/providers", {}),
            _safe_get(client, f"{THREAT_INTEL_URL}/feeds/stats", {}))
    groups = _settings_inventory(); settings = [item for group in groups for item in group["settings"]]
    skills = hermes_stats.get("skills_loaded", [])
    return {"groups": groups, "setting_count": len(settings),
        "configured_count": sum(1 for item in settings if item["configured"]),
        "secret_count": sum(1 for item in settings if item["secret"]),
        "health": health_data,
        "hermes": {"workers": int(hermes_stats.get("finding_workers", 0) or 0),
                   "queue_depth": int(hermes_stats.get("filtered_queue_length", 0) or 0),
                   "skills_count": len(skills), "skills": skills},
        "threat_intel": {"providers": intel_providers, "feeds": feed_stats},
        "source_of_truth": ".env", "editable": False,
        "generated_at": datetime.now(timezone.utc).isoformat()}
async def _safe_get(client: httpx.AsyncClient, url: str, default: Any,
                    timeout: float | None = None, attempts: int = 1) -> Any:
    request_timeout = timeout or DASHBOARD_UPSTREAM_TIMEOUT_SECONDS
    for attempt in range(max(1, attempts)):
        try:
            resp = await client.get(url, timeout=request_timeout); resp.raise_for_status(); return resp.json()
        except Exception:
            if attempt + 1 < attempts: await asyncio.sleep(0.12)
    return default
async def _gather_raw_data() -> dict:
    async with httpx.AsyncClient() as client:
        (soc_stats, events_resp, timeline_resp, findings_resp, findings_window_resp, m365_stats, intel_providers,
         cyfirma_feed_stats, research_resp) = await asyncio.gather(
            _safe_get(client, f"{SOC_CORE_URL}/stats", {}),
            _safe_get(client, f"{SOC_CORE_URL}/events?limit=300", {"events": []}),
            _safe_get(client, f"{SOC_CORE_URL}/analytics/timeline?hours=24", {"buckets": []}),
            _safe_get(client, f"{SOC_CORE_URL}/findings?limit=200", {"findings": []}),
            _safe_get(client, f"{SOC_CORE_URL}/findings/recent-window?minutes={FINDINGS_WINDOW_MINUTES}", {"findings": []}),
            _safe_get(client, f"{M365_COLLECTOR_URL}/stats", {}),
            _safe_get(client, f"{THREAT_INTEL_URL}/providers", {}),
            _safe_get(client, f"{THREAT_INTEL_URL}/feeds/stats", {}),
            _safe_get(client, f"{THREAT_INTEL_URL}/feeds/research?limit=5", {"items": []}))
    return {"soc_stats": soc_stats, "events": events_resp.get("events", []), "timeline_buckets": timeline_resp.get("buckets", []),
        "findings": findings_resp.get("findings", []), "findings_window": findings_window_resp.get("findings", []),
        "m365_stats": m365_stats, "intel_providers": intel_providers, "cyfirma_feed_stats": cyfirma_feed_stats,
        "research_items": research_resp.get("items", [])}
@app.get("/api/summary")
async def api_summary() -> dict:
    raw = await _gather_raw_data(); findings = raw["findings"]; findings_window = raw["findings_window"] or findings
    events = raw["events"]; soc_stats = raw["soc_stats"]
    return {"kpis": agg.compute_kpis(soc_stats, findings), "threat_intel_classification": agg.threat_intel_classification(findings_window),
        "threat_types": agg.threat_type_distribution(findings_window), "mitre": agg.mitre_frequency(findings_window),
        "severity": agg.severity_distribution(events), "timeline": agg.hourly_timeline(raw["timeline_buckets"]),
        "sources": agg.source_breakdown(soc_stats.get("events_by_source", {})),
        "coverage": agg.cloud_application_coverage(raw["m365_stats"], raw["intel_providers"]),
        "top_iocs": agg.top_malicious_iocs(findings_window), "apt_attributions": agg.apt_attributions(findings_window),
        "recent_findings": findings[:25], "recent_events": events[:25], "cyfirma_feed_stats": raw["cyfirma_feed_stats"],
        "research_items": raw["research_items"]}
@app.get("/api/overview")
async def api_filtered_overview(start: datetime | None = None, end: datetime | None = None,
                                bucket: str = Query("hour", pattern="^(hour|day|week|month|year)$"),
                                severity: str | None = None, category: str | None = None) -> dict:
    if start and end and start > end: raise HTTPException(status_code=400, detail="start must be before end")
    params = {key: value for key, value in {"start": start.isoformat() if start else None,
        "end": end.isoformat() if end else None, "bucket": bucket, "severity": severity,
        "category": category}.items() if value not in (None, "")}
    try:
        async with httpx.AsyncClient() as client:
            core_request = client.get(f"{SOC_CORE_URL}/analytics/overview", params={**params, "limit": 25}, timeout=20.0)
            findings_request = client.get(f"{SOC_CORE_URL}/findings/search", params={**params, "limit": 200, "offset": 0}, timeout=20.0)
            analytics_request = client.get(f"{SOC_CORE_URL}/findings/analytics", params=params, timeout=20.0)
            core_response, findings_response, analytics_response = await asyncio.gather(
                core_request, findings_request, analytics_request)
            for response in (core_response, findings_response, analytics_response): response.raise_for_status()
            core, findings_page, findings_analytics = core_response.json(), findings_response.json(), analytics_response.json()
    except Exception as exc:
        logger.warning("Filtered overview query failed: %s", exc)
        raise HTTPException(status_code=502, detail="overview data service unavailable")
    findings = findings_page.get("findings", [])
    event_stats = core.get("stats", {}); total_events = int(event_stats.get("total_events", 0) or 0)
    forwarded = int(event_stats.get("filtered_in_events", 0) or 0)
    total_findings = int(findings_analytics.get("total", 0) or 0)
    kpis = {"total_events": total_events, "forwarded_events": forwarded,
        "compression_pct": round((1 - forwarded / total_events) * 100, 1) if total_events else 0.0,
        "total_findings": total_findings,
        "high_critical_findings": int(findings_analytics.get("high_critical", 0) or 0),
        "avg_confidence": float(findings_analytics.get("avg_confidence", 0) or 0)}
    return {"kpis": kpis, "threat_intel_classification": agg.threat_intel_classification(findings),
        "threat_types": agg.threat_type_distribution_counts(findings_analytics.get("categories", [])),
        "mitre": agg.mitre_from_counts(findings_analytics.get("mitre", [])),
        "severity": agg.severity_distribution_counts(core.get("severities", [])),
        "timeline": core.get("timeline", []), "sources": agg.source_breakdown_counts(core.get("sources", [])),
        "recent_findings": findings[:25], "recent_events": core.get("events", [])[:25],
        "top_iocs": agg.top_malicious_iocs(findings), "apt_attributions": agg.apt_attributions(findings),
        "bucket": bucket}
async def _findings_filtered(path: str, start: datetime | None, end: datetime | None, severity: str | None,
                             category: str | None, q: str | None, **extra) -> dict:
    if start and end and start > end: raise HTTPException(status_code=400, detail="start must be before end")
    params = {key: value for key, value in {"start": start.isoformat() if start else None,
        "end": end.isoformat() if end else None, "severity": severity, "category": category, "q": q, **extra}.items()
        if value not in (None, "")}
    query_timeout = max(DASHBOARD_UPSTREAM_TIMEOUT_SECONDS, 20.0)
    async with httpx.AsyncClient() as client:
        last_error = None
        for attempt in range(2):
            try:
                response = await client.get(f"{SOC_CORE_URL}{path}", params=params, timeout=query_timeout)
                if response.status_code == 400: raise HTTPException(status_code=400, detail=response.json().get("detail", "invalid filter"))
                response.raise_for_status(); return response.json()
            except HTTPException: raise
            except Exception as exc:
                last_error = exc
                if attempt == 0: await asyncio.sleep(0.12)
    logger.warning("SOC Core finding query failed after retry: %s", last_error)
    raise HTTPException(status_code=502, detail="finding search service unavailable")
@app.get("/api/findings/search")
async def api_findings_search(start: datetime | None = None, end: datetime | None = None,
                              limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0),
                              severity: str | None = None, category: str | None = None, q: str | None = None) -> dict:
    return await _findings_filtered("/findings/search", start, end, severity, category, q, limit=limit, offset=offset)
@app.get("/api/findings/analytics")
async def api_findings_analytics(start: datetime | None = None, end: datetime | None = None,
                                 bucket: str = Query("hour", pattern="^(hour|day|week|month|year)$"),
                                 severity: str | None = None, category: str | None = None, q: str | None = None) -> dict:
    return await _findings_filtered("/findings/analytics", start, end, severity, category, q, bucket=bucket)
@app.get("/api/findings/by-event/{event_id}")
async def api_finding_by_event(event_id: str) -> dict:
    try: canonical_id = str(UUID(event_id))
    except ValueError: raise HTTPException(status_code=400, detail="invalid event id")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{SOC_CORE_URL}/findings/by-event/{canonical_id}", timeout=max(DASHBOARD_UPSTREAM_TIMEOUT_SECONDS, 10.0))
            if response.status_code == 404: raise HTTPException(status_code=404, detail="finding not found for event")
            response.raise_for_status()
            return response.json()
    except HTTPException: raise
    except Exception as exc:
        logger.warning("Finding lookup by event unavailable for %s: %s", canonical_id, exc)
        raise HTTPException(status_code=502, detail="finding lookup service unavailable")
@app.get("/api/findings/{finding_id}")
async def api_finding_detail(finding_id: str) -> dict:
    try: canonical_id = str(UUID(finding_id))
    except ValueError: raise HTTPException(status_code=400, detail="invalid finding id")
    detail_timeout = max(DASHBOARD_UPSTREAM_TIMEOUT_SECONDS, 10.0)
    async with httpx.AsyncClient() as client:
        finding = None; last_error = None
        for attempt in range(2):
            try:
                response = await client.get(f"{SOC_CORE_URL}/findings/detail/{canonical_id}", timeout=detail_timeout)
                if response.status_code == 404: raise HTTPException(status_code=404, detail="finding not found")
                response.raise_for_status(); finding = response.json(); break
            except HTTPException: raise
            except Exception as exc:
                last_error = exc
                if attempt == 0: await asyncio.sleep(0.12)
        if finding is None:
            logger.warning("Finding detail unavailable for %s after retry: %s", canonical_id, last_error)
            raise HTTPException(status_code=502, detail="finding service unavailable")
        event_ids_raw = finding.get("event_ids") or []
        if isinstance(event_ids_raw, str):
            event_ids_raw = [item.strip().strip('"') for item in event_ids_raw.strip("{}").split(",") if item.strip()]
        event_ids = [str(event_id) for event_id in event_ids_raw][:20]
        event_responses = await asyncio.gather(*[
            _safe_get(client, f"{SOC_CORE_URL}/events/{event_id}", None,
                      timeout=detail_timeout, attempts=2) for event_id in event_ids
        ])
    events = [event for event in event_responses if isinstance(event, dict)]
    detail = agg.attack_detail(finding, events)
    detail["missing_event_count"] = len(event_ids) - len(events)
    return detail
@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    summary = await api_summary(); health_data = await api_health()
    return templates.TemplateResponse("index.html", {"request": request, "kpis": summary["kpis"], "tic": summary["threat_intel_classification"],
        "threat_types": summary["threat_types"], "mitre": summary["mitre"], "severity": summary["severity"],
        "timeline": summary["timeline"], "sources": summary["sources"], "coverage": summary["coverage"],
        "top_iocs": summary["top_iocs"], "apt_attributions": summary["apt_attributions"], "findings": summary["recent_findings"],
        "events": summary["recent_events"], "service_health": health_data["services"], "healthy_count": health_data["healthy_count"],
        "total_count": health_data["total_count"], "cyfirma_feed_stats": summary["cyfirma_feed_stats"], "research_items": summary["research_items"]})
