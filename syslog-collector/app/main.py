from __future__ import annotations
import logging, os, socketserver, threading
from typing import List, Optional
from fastapi import FastAPI
from pydantic import BaseModel
from .normalizer import normalize_syslog_line
from .redis_client import push_raw_event, queue_length
from .samples import SAMPLE_SCENARIOS
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("syslog-collector")
UDP_PORT = int(os.getenv("SYSLOG_UDP_PORT", "36514")); TCP_PORT = int(os.getenv("SYSLOG_TCP_PORT", "36514"))
_counters = {"received": 0, "pushed": 0, "errors": 0,
             "network_received": 0, "manual_api_received": 0, "simulated_received": 0}
def _handle_line(raw_line: str, client_ip: Optional[str] = None,
                 ingestion_mode: str = "direct_syslog", scenario: str | None = None) -> None:
    if not raw_line.strip(): return
    try:
        event = normalize_syslog_line(raw_line, source_ip=client_ip)
        event.setdefault("raw_kv", {})["source_provenance"] = ingestion_mode
        if ingestion_mode == "synthetic_simulation":
            event["is_synthetic_test"] = True
            event["raw_kv"]["is_synthetic_test"] = True
            event["raw_kv"]["test_marker"] = f"syslog-simulation:{scenario or 'unknown'}"
        push_raw_event(event); _counters["received"] += 1; _counters["pushed"] += 1
        counter = {"direct_syslog": "network_received", "manual_api": "manual_api_received",
                   "synthetic_simulation": "simulated_received"}.get(ingestion_mode)
        if counter: _counters[counter] += 1
        logger.info("Ingested %s from %s (sev=%s, type=%s)", event["id"], event["source"], event["severity"], event["type"])
    except Exception:
        _counters["errors"] += 1; logger.exception("Failed to process syslog line")
class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None: _handle_line(self.request[0].decode("utf-8", errors="ignore"), self.client_address[0])
class TCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        for raw_line in self.rfile: _handle_line(raw_line.decode("utf-8", errors="ignore"), self.client_address[0])
def _start_udp_server():
    with socketserver.ThreadingUDPServer(("0.0.0.0", UDP_PORT), UDPHandler) as server: server.serve_forever()
def _start_tcp_server():
    with socketserver.ThreadingTCPServer(("0.0.0.0", TCP_PORT), TCPHandler) as server: server.serve_forever()
app = FastAPI(title="Syslog Collector", version="4.0.0")
@app.on_event("startup")
async def startup_event():
    threading.Thread(target=_start_udp_server, daemon=True).start()
    threading.Thread(target=_start_tcp_server, daemon=True).start()
@app.get("/health")
async def health(): return {"status": "ok", "service": "syslog-collector"}
@app.get("/stats")
async def stats(): return {**_counters, "queue_length": queue_length(), "udp_port": UDP_PORT, "tcp_port": TCP_PORT}
class IngestRequest(BaseModel):
    raw: str
    source_hint: Optional[str] = None
@app.post("/ingest")
async def ingest(payload: IngestRequest):
    _handle_line(payload.raw, ingestion_mode="manual_api"); return {"status": "accepted"}
class SimulateRequest(BaseModel):
    scenario: Optional[str] = "vpn_bruteforce"
    count: Optional[int] = None
@app.get("/simulate/scenarios")
async def list_scenarios(): return {"scenarios": list(SAMPLE_SCENARIOS.keys())}
@app.post("/simulate")
async def simulate(payload: SimulateRequest):
    scenario = SAMPLE_SCENARIOS.get(payload.scenario, SAMPLE_SCENARIOS["vpn_bruteforce"])
    lines: List[str] = scenario["lines"]
    if payload.count: lines = lines[: payload.count]
    for line in lines:
        _handle_line(line, client_ip="127.0.0.1", ingestion_mode="synthetic_simulation",
                     scenario=payload.scenario)
    return {"status": "simulated", "scenario": payload.scenario, "events_sent": len(lines)}
