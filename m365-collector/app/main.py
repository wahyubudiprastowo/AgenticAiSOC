from __future__ import annotations
import logging, os, threading, time
from fastapi import FastAPI
from . import defender_xdr, management_api, redis_client
from .normalizer import normalize_m365_record
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("m365-collector.main")
M365_ENABLED = os.getenv("M365_ANALYTICS_ENABLED", "true").lower() == "true"
M365_POLL_INTERVAL_SECONDS = int(os.getenv("M365_POLL_INTERVAL_SECONDS", "300"))
DEFENDER_POLL_INTERVAL_SECONDS = int(os.getenv("DEFENDER_XDR_POLL_INTERVAL_SECONDS", "900"))
app = FastAPI(title="M365 / Defender XDR Collector", version="4.0.0")
_stats = {"m365_records": 0, "defender_incidents": 0, "m365_errors": 0, "defender_errors": 0, "last_m365_poll": None, "last_defender_poll": None}
def _poll_m365_once(lookback_minutes=15):
    count = 0
    try:
        for record in management_api.poll_all_content(lookback_minutes=lookback_minutes):
            redis_client.push_raw_event(normalize_m365_record(record)); count += 1
        _stats["m365_records"] += count
    except Exception: _stats["m365_errors"] += 1
    _stats["last_m365_poll"] = time.time(); return count
def _poll_defender_once(lookback_minutes=20):
    count = 0
    try:
        for incident in defender_xdr.fetch_recent_incidents(lookback_minutes=lookback_minutes):
            redis_client.push_raw_event(defender_xdr.defender_incident_to_normalized(incident)); count += 1
        _stats["defender_incidents"] += count
    except Exception: _stats["defender_errors"] += 1
    _stats["last_defender_poll"] = time.time(); return count
def _m365_loop():
    if not M365_ENABLED: return
    while True: _poll_m365_once(); time.sleep(M365_POLL_INTERVAL_SECONDS)
def _defender_loop():
    if not defender_xdr.ENABLED: return
    while True: _poll_defender_once(); time.sleep(DEFENDER_POLL_INTERVAL_SECONDS)
@app.on_event("startup")
async def startup_event():
    threading.Thread(target=_m365_loop, daemon=True).start()
    threading.Thread(target=_defender_loop, daemon=True).start()
@app.get("/health")
async def health(): return {"status": "ok", "service": "m365-collector"}
@app.get("/stats")
async def stats(): return {**_stats, "m365_enabled": M365_ENABLED, "defender_xdr_enabled": defender_xdr.ENABLED}
@app.post("/poll/m365")
async def poll_m365(): return {"status": "polled", "records_pushed": _poll_m365_once()}
@app.post("/poll/defender")
async def poll_defender(): return {"status": "polled", "incidents_pushed": _poll_defender_once()}
