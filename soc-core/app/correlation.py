from __future__ import annotations

import hashlib
import os

from . import redis_client


AUTH_FAILURE_THRESHOLD = int(os.getenv("AUTH_FAILURE_THRESHOLD", "5"))
AUTH_FAILURE_WINDOW_SECONDS = int(os.getenv("AUTH_FAILURE_WINDOW_SECONDS", "900"))
DOWNLOAD_THRESHOLD = int(os.getenv("DOWNLOAD_THRESHOLD", "20"))
DOWNLOAD_WINDOW_SECONDS = int(os.getenv("DOWNLOAD_WINDOW_SECONDS", "900"))


def _identity(event: dict) -> str:
    value = "|".join([
        str(event.get("source") or ""),
        str(event.get("user_name") or ""),
        str(event.get("src_ip") or ""),
    ])
    return hashlib.sha256(value.encode()).hexdigest()[:24]


def _raise_once(event: dict, family: str, threshold: int, window_seconds: int) -> int:
    identity = _identity(event)
    count = redis_client.increment_window(f"soc:corr:{family}:{identity}", window_seconds)
    event.setdefault("raw_kv", {})["correlation_count"] = count
    event["raw_kv"]["correlation_window_seconds"] = window_seconds
    if count >= threshold and redis_client.claim_once(f"soc:corr-alert:{family}:{identity}", window_seconds):
        event["raw_kv"]["security_signal"] = True
        return count
    return 0


def apply(event: dict) -> dict:
    event_type = str(event.get("type") or "")
    raw_kv = event.setdefault("raw_kv", {})
    if event_type == "auth_failure" and raw_kv.get("correlate", True):
        count = _raise_once(event, "auth", AUTH_FAILURE_THRESHOLD, AUTH_FAILURE_WINDOW_SECONDS)
        if count:
            event["type"] = "credential_attack"
            event["severity"] = "high"
            event["description"] = f"Correlated credential failures: {count} attempts within {AUTH_FAILURE_WINDOW_SECONDS // 60} minutes"
            event["mitre_technique"] = sorted(set((event.get("mitre_technique") or []) + ["T1110"]))
    elif event_type == "file_download" and raw_kv.get("correlate"):
        count = _raise_once(event, "download", DOWNLOAD_THRESHOLD, DOWNLOAD_WINDOW_SECONDS)
        if count:
            event["type"] = "insider_risk"
            event["severity"] = "high"
            event["description"] = f"Correlated bulk download: {count} files within {DOWNLOAD_WINDOW_SECONDS // 60} minutes"
            event["mitre_technique"] = sorted(set((event.get("mitre_technique") or []) + ["T1005"]))
    return event
