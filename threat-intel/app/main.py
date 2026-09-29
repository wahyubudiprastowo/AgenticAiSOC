from __future__ import annotations
import logging, os, threading, time
from typing import Literal
from fastapi import FastAPI
from pydantic import BaseModel
from . import cyfirma_feeds
from . import db
from .providers import provider_statuses, run_all_providers, warm_cyfirma_feed
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("threat-intel.main")
app = FastAPI(title="Threat Intelligence Service", version="4.0.0")
_CACHE: dict[str, tuple[float, dict]] = {}
CACHE_TTL_SECONDS = int(os.getenv("INTEL_CACHE_TTL_SECONDS", "3600"))
class EnrichRequest(BaseModel):
    ioc: str
    ioc_type: Literal["ip", "domain", "hash", "url", "cve"] = "ip"
@app.on_event("startup")
async def startup_event() -> None:
    db.init_pool()
    threading.Thread(target=cyfirma_feeds.org_vuln_loop, daemon=True).start()
    threading.Thread(target=cyfirma_feeds.research_loop, daemon=True).start()
    threading.Thread(target=cyfirma_feeds.taxii_loop, daemon=True).start()
    threading.Thread(target=warm_cyfirma_feed, daemon=True).start()
@app.get("/health")
async def health() -> dict: return {"status": "ok", "service": "threat-intel"}
@app.get("/providers")
async def providers_status() -> dict:
    return provider_statuses()
@app.get("/feeds/stats")
async def feeds_stats() -> dict:
    return {**cyfirma_feeds.get_stats(), "org_vuln_enabled": cyfirma_feeds.ORG_VULN_ENABLED,
            "research_enabled": cyfirma_feeds.RESEARCH_ENABLED, "taxii_enabled": cyfirma_feeds.TAXII_ENABLED}
@app.get("/feeds/research")
def feeds_research(limit: int = 25) -> dict:
    items = db.list_research(limit=limit); return {"count": len(items), "items": items}
@app.get("/feeds/org-vulnerabilities")
def feeds_org_vulnerabilities(limit: int = 50) -> dict:
    items = db.list_org_vulnerabilities(limit=limit); return {"count": len(items), "items": items}
@app.post("/feeds/poll-now")
def poll_now() -> dict:
    return {"org_vuln_new": cyfirma_feeds.poll_org_vulnerabilities_once(), "research_new": cyfirma_feeds.poll_research_once(),
            "taxii_objects": cyfirma_feeds.poll_taxii_once()}
@app.post("/enrich")
def enrich(payload: EnrichRequest) -> dict:
    cache_key = f"{payload.ioc_type}:{payload.ioc}"; now = time.time(); cached = _CACHE.get(cache_key)
    if cached and (now - cached[0]) < CACHE_TTL_SECONDS:
        return {**cached[1], "cache_status": "fresh", "cache_age_seconds": round(now - cached[0], 1)}
    providers = run_all_providers(payload.ioc, payload.ioc_type)
    live_hits = [p for p in providers if p.get("mode") == "live" and p.get("malicious")]
    strong_sources = {"threatfox", "urlhaus", "cyfirma", "crowdsec_watchlist"}
    strong_exact_hit = any(p.get("name") in strong_sources and float(p.get("score", 0)) >= 0.8 for p in live_hits)
    trusted_score_sources = strong_sources | {"virustotal", "abuseipdb", "crowdsec"}
    high_score_hit = any(p.get("name") in trusted_score_sources and float(p.get("score", 0)) >= 0.8 for p in live_hits)
    consensus = len({p.get("name") for p in live_hits if float(p.get("score", 0)) >= 0.2}) >= 2
    malicious = strong_exact_hit or high_score_hit or consensus
    confidence = round(max((float(p.get("score", 0.0)) for p in live_hits), default=0.0), 3) if malicious else 0.0
    reason = "exact/high-confidence live hit" if (strong_exact_hit or high_score_hit) else "multi-provider live consensus" if consensus else "insufficient live evidence"
    live_count = sum(p.get("mode") == "live" for p in providers)
    unavailable_count = sum(p.get("mode") == "unavailable" for p in providers)
    stale_count = sum(p.get("mode") == "stale_cache" for p in providers)
    enrichment_status = ("complete" if live_count and not unavailable_count and not stale_count else
                         "partial" if live_count else "stale_cache" if stale_count else "unavailable")
    if enrichment_status == "unavailable" and cached:
        stale = {**cached[1], "enrichment_status": "stale_cache", "cache_status": "stale",
                 "cache_age_seconds": round(now - cached[0], 1)}
        return stale
    result = {"ioc": payload.ioc, "ioc_type": payload.ioc_type, "malicious": malicious,
              "confidence": confidence, "verdict_reason": reason, "enrichment_status": enrichment_status,
              "cache_status": "miss", "providers": providers}
    _CACHE[cache_key] = (now, result); return result
