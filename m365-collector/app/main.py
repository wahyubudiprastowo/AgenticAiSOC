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
_stats = {"m365_records": 0, "defender_incidents": 0, "m365_errors": 0, "defender_errors": 0,
          "last_m365_poll": None, "last_defender_poll": None, "last_m365_error": None,
          "last_defender_error": None, "m365_poll_skipped": 0, "defender_poll_skipped": 0}
_m365_poll_lock = threading.Lock()
_defender_poll_lock = threading.Lock()


def _safe_poll_error(exc: Exception) -> str:
    text = str(exc).strip()
    allowed_prefixes = ("OAuth ", "Graph ", "Defender ", "unsupported ", "untrusted ")
    return text[:160] if text.startswith(allowed_prefixes) else type(exc).__name__


def _poll_m365_once(lookback_minutes=15):
    if not _m365_poll_lock.acquire(blocking=False):
        _stats["m365_poll_skipped"] += 1
        return 0
    count = 0
    try:
        for record in management_api.poll_all_content(
                lookback_minutes=lookback_minutes,
                cursor_getter=redis_client.get_content_cursor,
                cursor_setter=redis_client.set_content_cursor):
            redis_client.push_raw_event(normalize_m365_record(record)); count += 1
        _stats["m365_records"] += count
        _stats["last_m365_error"] = None
    except Exception as exc:
        _stats["m365_errors"] += 1; _stats["last_m365_error"] = _safe_poll_error(exc)
        logger.exception("M365 content poll failed")
    finally:
        _stats["last_m365_poll"] = time.time(); _m365_poll_lock.release()
    return count
def _poll_defender_once(lookback_minutes=20):
    if not _defender_poll_lock.acquire(blocking=False):
        _stats["defender_poll_skipped"] += 1
        return 0
    count = 0
    try:
        for incident in defender_xdr.fetch_recent_incidents(lookback_minutes=lookback_minutes):
            redis_client.push_raw_event(defender_xdr.defender_incident_to_normalized(incident)); count += 1
        _stats["defender_incidents"] += count
        _stats["last_defender_error"] = None
    except Exception as exc:
        _stats["defender_errors"] += 1; _stats["last_defender_error"] = _safe_poll_error(exc)
        logger.exception("Defender poll failed")
    finally:
        _stats["last_defender_poll"] = time.time(); _defender_poll_lock.release()
    return count
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
def _source_health(enabled: bool, last_poll, last_error, interval: int) -> str:
    if not enabled: return "disabled"
    if last_error: return "degraded"
    if last_poll is None: return "initializing"
    if time.time() - float(last_poll) > max(60, interval * 3): return "stale"
    return "healthy"


@app.get("/health")
async def health():
    sources = {
        "m365_management_activity": _source_health(
            M365_ENABLED, _stats["last_m365_poll"], _stats["last_m365_error"], M365_POLL_INTERVAL_SECONDS),
        "defender_xdr": _source_health(
            defender_xdr.ENABLED, _stats["last_defender_poll"], _stats["last_defender_error"],
            DEFENDER_POLL_INTERVAL_SECONDS),
    }
    degraded = any(value in {"degraded", "stale"} for value in sources.values())
    return {"status": "degraded" if degraded else "ok", "service": "m365-collector", "sources": sources}
@app.get("/stats")
async def stats(): return {**_stats, **management_api.get_stats(), "m365_enabled": M365_ENABLED,
                           "defender_xdr_enabled": defender_xdr.ENABLED}
@app.post("/poll/m365")
async def poll_m365(): return {"status": "polled", "records_pushed": _poll_m365_once()}
@app.post("/poll/defender")
async def poll_defender(): return {"status": "polled", "incidents_pushed": _poll_defender_once()}
