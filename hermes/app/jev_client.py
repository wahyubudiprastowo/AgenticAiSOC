from __future__ import annotations
import logging, os
import httpx
logger = logging.getLogger("hermes.jev_client")
JEV_URL = os.getenv("JEV_URL", os.getenv("AI_BASE_URL", "http://jev:20128"))
JEV_TIMEOUT = float(os.getenv("HERMES_JEV_TIMEOUT_SECONDS", "20"))


def _unavailable_result(reason: str) -> dict:
    return {
        "verdict": "unavailable",
        "reasoning_mode": "unavailable",
        "proposed_category": None,
        "proposed_subtype": None,
        "threat_classification": "Unavailable",
        "mitre_technique": [],
        "confidence": 0.0,
        "severity": "low",
        "investigation_recommendation": "Review deterministic evidence; Jev reasoning is unavailable.",
        "reasoning": reason,
        "based_on": [],
    }


def analyze_evidence(evidence: dict) -> dict:
    try:
        with httpx.Client(timeout=JEV_TIMEOUT) as client:
            resp = client.post(f"{JEV_URL.rstrip('/')}/analyze", json=evidence); resp.raise_for_status(); return resp.json()
    except Exception as exc:
        logger.warning("Jev request unavailable: %s", type(exc).__name__)
        return _unavailable_result("Jev service could not be reached within the Hermes timeout.")
