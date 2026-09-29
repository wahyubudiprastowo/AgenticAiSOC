from __future__ import annotations
import logging, os
import httpx
logger = logging.getLogger("hermes.threat_intel_client")
THREAT_INTEL_URL = os.getenv("THREAT_INTEL_URL", "http://threat-intel:8005")
def enrich_ioc(ioc, ioc_type="ip"):
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.post(f"{THREAT_INTEL_URL.rstrip('/')}/enrich", json={"ioc": ioc, "ioc_type": ioc_type})
            resp.raise_for_status(); return resp.json()
    except Exception: return None
