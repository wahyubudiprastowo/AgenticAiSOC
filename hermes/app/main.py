from __future__ import annotations
import logging, os, threading
from datetime import datetime
from uuid import UUID
from fastapi import FastAPI, HTTPException, Query
from . import db, memory, redis_client
from .reporter import delivery_loop
from .skill_loader import load_skills
from .worker import _process_filtered_event, orchestration_loop
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("hermes.main")
AI_FINDING_WORKERS = max(1, int(os.getenv("AI_FINDING_WORKERS", "1")))
app = FastAPI(title="Hermes - SOC Orchestrator", version="4.0.0")
@app.on_event("startup")
async def startup_event():
    db.init_pool(); load_skills(); memory.ensure_collection()
    for _ in range(AI_FINDING_WORKERS):
        threading.Thread(target=orchestration_loop, daemon=True).start()
    threading.Thread(target=delivery_loop, daemon=True).start()
@app.get("/health")
async def health(): return {"status": "ok", "service": "hermes"}
@app.get("/stats")
async def stats(): return {"filtered_queue_length": redis_client.filtered_queue_length(), "finding_workers": AI_FINDING_WORKERS,
                           "skills_loaded": [s.get("skill") for s in load_skills()]}
@app.get("/skills")
async def get_skills(): return {"skills": load_skills()}
@app.get("/findings")
async def get_findings(limit: int = 50):
    f = db.list_findings(limit=limit); return {"count": len(f), "findings": f}
@app.get("/findings/recent-window")
async def findings_recent_window(minutes: int = 1440):
    f = db.findings_since(minutes=minutes); return {"count": len(f), "findings": f}
@app.get("/findings/search")
async def findings_search(start: datetime | None = None, end: datetime | None = None,
                          limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0),
                          severity: str | None = None, category: str | None = None, q: str | None = None):
    if start and end and start > end: raise HTTPException(status_code=400, detail="start must be before end")
    findings, total = db.search_findings(start, end, limit, offset, severity, category, q)
    return {"count": len(findings), "total": total, "limit": limit, "offset": offset, "findings": findings}
@app.get("/findings/analytics")
async def findings_analytics(start: datetime | None = None, end: datetime | None = None,
                             bucket: str = Query("hour", pattern="^(hour|day|week|month|year)$"),
                             severity: str | None = None, category: str | None = None, q: str | None = None):
    if start and end and start > end: raise HTTPException(status_code=400, detail="start must be before end")
    return db.findings_analytics(start, end, bucket, severity, category, q)
@app.get("/findings/by-event/{event_id}")
async def finding_by_event(event_id: str):
    try: canonical_id = str(UUID(event_id))
    except ValueError: raise HTTPException(status_code=400, detail="invalid event id")
    finding = db.get_finding_by_event_id(canonical_id)
    if not finding: raise HTTPException(status_code=404, detail="finding not found for event")
    return finding
@app.get("/findings/detail/{finding_id}")
async def finding_detail(finding_id: str):
    finding = db.get_finding(finding_id)
    if not finding: raise HTTPException(status_code=404, detail="finding not found")
    return finding
@app.post("/findings/replay")
async def replay(event: dict):
    _process_filtered_event(event); return {"status": "processed"}
@app.get("/memory/search")
async def memory_search(query: str, limit: int = 3):
    results = memory.search_similar_incidents(query, limit=limit); return {"query": query, "count": len(results), "results": results}
