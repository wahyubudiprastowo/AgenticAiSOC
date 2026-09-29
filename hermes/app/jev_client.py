from __future__ import annotations
import logging, os
import httpx
logger = logging.getLogger("hermes.jev_client")
JEV_URL = os.getenv("JEV_URL", os.getenv("AI_BASE_URL", "http://jev:20128"))
AI_TIMEOUT = int(os.getenv("AI_TIMEOUT_SECONDS", os.getenv("AI_TIMEOUT", "180")))
def analyze_evidence(evidence: dict) -> dict:
    try:
        with httpx.Client(timeout=AI_TIMEOUT) as client:
            resp = client.post(f"{JEV_URL.rstrip('/')}/analyze", json=evidence); resp.raise_for_status(); return resp.json()
    except Exception:
        return {"threat_classification": "Unknown", "mitre_technique": [], "confidence": 0.0,
                "investigation_recommendation": "Jev reasoning engine unreachable - manual review required.",
                "severity": "low", "based_on": []}
