from __future__ import annotations
import logging, os
import httpx
logger = logging.getLogger("soc-core.threat_intel_client")
THREAT_INTEL_URL = os.getenv("THREAT_INTEL_URL", "http://threat-intel:8005")
def enrich_ioc(ioc: str, ioc_type: str = "ip"):
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.post(f"{THREAT_INTEL_URL.rstrip('/')}/enrich", json={"ioc": ioc, "ioc_type": ioc_type})
            resp.raise_for_status(); return resp.json()
    except Exception:
        logger.warning("threat-intel enrichment failed"); return {"ioc": ioc, "ioc_type": ioc_type, "malicious": False, "confidence": 0.0, "providers": []}
