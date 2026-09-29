from __future__ import annotations
import hashlib, json, logging, os, threading, uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from . import db, worker
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("soc-core.main")
app = FastAPI(title="SOC Core", version="4.0.0")
@app.on_event("startup")
async def startup_event():
    db.init_pool()
    threading.Thread(target=worker.raw_event_loop, daemon=True).start()
    threading.Thread(target=worker.wazuh_alerts_loop, daemon=True).start()
    threading.Thread(target=worker.wazuh_fim_loop, daemon=True).start()
    threading.Thread(target=worker.wazuh_vuln_loop, daemon=True).start()
@app.get("/health")
async def health(): return {"status": "ok", "service": "soc-core"}
@app.get("/health/database")
async def database_health():
    if not db.health(): raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ok", "service": "postgresql"}
@app.get("/stats")
async def get_stats(): return db.stats()
@app.get("/events")
async def get_events(limit: int = 100, severity: str | None = None, since_minutes: int | None = None):
    events = db.list_events(limit=limit, severity=severity, since_minutes=since_minutes)
    return {"count": len(events), "events": events}
@app.get("/events/{event_id}")
async def get_event(event_id: str):
    event = db.get_event(event_id)
    if not event: raise HTTPException(status_code=404, detail="event not found")
    return event
@app.get("/analytics/timeline")
async def get_timeline(hours: int = 24): return {"hours": hours, "buckets": db.timeline_buckets(hours=hours)}
@app.get("/analytics/overview")
async def get_overview(start: datetime | None = None, end: datetime | None = None,
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
    raw: Optional[dict] = None
@app.post("/events/ingest")
async def ingest_event(payload: IngestEventRequest):
    raw_payload = payload.raw or {"description": payload.description}
    event = {"id": f"evt-ingest-{uuid.uuid4().hex[:10]}", "source": payload.source, "type": payload.type,
        "severity": payload.severity, "src_ip": payload.src_ip, "destination": payload.destination,
        "user_name": payload.user_name, "description": payload.description, "mitre_technique": payload.mitre_technique or [],
        "time": datetime.now(timezone.utc).isoformat(), "raw": raw_payload,
        "raw_hash": hashlib.sha256(json.dumps(raw_payload, sort_keys=True).encode()).hexdigest(), "raw_kv": {}}
    event_uuid = worker.process_event(event)
    return {"status": "ingested", "event_id": event["id"], "db_id": event_uuid}
