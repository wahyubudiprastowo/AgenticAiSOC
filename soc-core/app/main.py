from __future__ import annotations
import hashlib, json, logging, os, threading, uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from . import db, worker
from shared.taxonomy import public_registry
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("soc-core.main")
app = FastAPI(title="SOC Core", version="4.0.0")
@app.on_event("startup")
async def startup_event():
    db.init_pool()
    recovered = worker.redis_client.recover_raw_inflight()
    if recovered: logger.warning("Recovered %s unacknowledged raw events", recovered)
    for index in range(worker.SOC_RAW_EVENT_WORKERS):
        threading.Thread(target=worker.raw_event_loop, name=f"raw-event-{index + 1}", daemon=True).start()
    threading.Thread(target=worker.wazuh_alerts_loop, daemon=True).start()
    threading.Thread(target=worker.wazuh_fim_loop, daemon=True).start()
    threading.Thread(target=worker.wazuh_vuln_loop, daemon=True).start()
@app.get("/health")
async def health(): return {"status": "ok", "service": "soc-core"}
@app.get("/health/database")
def database_health():
    if not db.health(): raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ok", "service": "postgresql"}
@app.get("/taxonomy")
async def taxonomy(): return public_registry()
@app.get("/stats")
def get_stats(): return {**db.stats(), "raw_queue": worker.redis_client.raw_queue_stats(),
                         "raw_event_workers": worker.SOC_RAW_EVENT_WORKERS}
@app.get("/events")
def get_events(limit: int = 100, severity: str | None = None, since_minutes: int | None = None):
    events = db.list_events(limit=limit, severity=severity, since_minutes=since_minutes)
    return {"count": len(events), "events": events}
@app.get("/events/{event_id}")
def get_event(event_id: str):
    event = db.get_event(event_id)
    if not event: raise HTTPException(status_code=404, detail="event not found")
    return event
@app.get("/findings")
def get_findings(limit: int = Query(50, ge=1, le=200)):
    findings = db.list_findings(limit); return {"count": len(findings), "findings": findings}
@app.get("/findings/recent-window")
def findings_recent_window(minutes: int = Query(1440, ge=1), limit: int = Query(200, ge=1, le=500)):
    findings = db.findings_since(minutes, limit); return {"count": len(findings), "findings": findings}
@app.get("/findings/search")
def findings_search(start: datetime | None = None, end: datetime | None = None,
                          limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0),
                          severity: str | None = None, category: str | None = None, q: str | None = None):
    if start and end and start > end: raise HTTPException(status_code=400, detail="start must be before end")
    findings, total = db.search_findings(start, end, limit, offset, severity, category, q)
    return {"count": len(findings), "total": total, "limit": limit, "offset": offset, "findings": findings}
@app.get("/findings/analytics")
def findings_analytics(start: datetime | None = None, end: datetime | None = None,
                             bucket: str = Query("hour", pattern="^(hour|day|week|month|year)$"),
                             severity: str | None = None, category: str | None = None, q: str | None = None):
    if start and end and start > end: raise HTTPException(status_code=400, detail="start must be before end")
    return db.findings_analytics(start, end, bucket, severity, category, q)
@app.get("/findings/by-event/{event_id}")
def finding_by_event(event_id: str):
    try: canonical_id = str(uuid.UUID(event_id))
    except ValueError: raise HTTPException(status_code=400, detail="invalid event id")
    finding = db.get_finding_by_event_id(canonical_id)
    if not finding: raise HTTPException(status_code=404, detail="finding not found for event")
    return finding
@app.get("/findings/detail/{finding_id}")
def finding_detail(finding_id: str):
    try: canonical_id = str(uuid.UUID(finding_id))
    except ValueError: raise HTTPException(status_code=400, detail="invalid finding id")
    finding = db.get_finding(canonical_id)
    if not finding: raise HTTPException(status_code=404, detail="finding not found")
    return finding
@app.get("/analytics/timeline")
def get_timeline(hours: int = 24): return {"hours": hours, "buckets": db.timeline_buckets(hours=hours)}
@app.get("/analytics/overview")
def get_overview(start: datetime | None = None, end: datetime | None = None,
                       bucket: str = Query("hour", pattern="^(hour|day|week|month|year)$"),
                       severity: str | None = None, category: str | None = None,
                       limit: int = Query(25, ge=1, le=100)):
    if start and end and start > end: raise HTTPException(status_code=400, detail="start must be before end")
    return db.overview(start, end, bucket, severity, category, limit)
class IngestEventRequest(BaseModel):
    source: str
    type: str
    description: str
    severity: str = "medium"
    mitre_technique: Optional[list[str]] = None
    src_ip: Optional[str] = None
    destination: Optional[str] = None
    user_name: Optional[str] = None
    test_marker: Optional[str] = None
    is_synthetic_test: bool = False
    raw: Optional[dict] = None
@app.post("/events/ingest")
def ingest_event(payload: IngestEventRequest):
    raw_payload = dict(payload.raw or {})
    raw_payload.setdefault("description", payload.description)
    if payload.test_marker:
        raw_payload["test_marker"] = payload.test_marker
    if payload.is_synthetic_test:
        raw_payload["is_synthetic_test"] = True
    event = {"id": f"evt-ingest-{uuid.uuid4().hex[:10]}", "source": payload.source, "type": payload.type,
        "severity": payload.severity, "src_ip": payload.src_ip, "destination": payload.destination,
        "user_name": payload.user_name, "description": payload.description, "mitre_technique": payload.mitre_technique or [],
        "time": datetime.now(timezone.utc).isoformat(), "raw": raw_payload,
        "raw_hash": hashlib.sha256(json.dumps(raw_payload, sort_keys=True).encode()).hexdigest(),
        "raw_kv": raw_payload}
    event_uuid = worker.process_event(event)
    return {"status": "ingested", "event_id": event["id"], "db_id": event_uuid}
