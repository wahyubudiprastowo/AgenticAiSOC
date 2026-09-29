from __future__ import annotations
import hashlib, json, logging, os
from datetime import datetime, timedelta, timezone
import httpx
from .auth import get_graph_token
logger = logging.getLogger("m365-collector.defender_xdr")
ENABLED = os.getenv("DEFENDER_XDR_ENABLED", "false").lower() == "true"
TENANT_ID = os.getenv("DEFENDER_XDR_TENANT_ID", ""); CLIENT_ID = os.getenv("DEFENDER_XDR_CLIENT_ID", ""); CLIENT_SECRET = os.getenv("DEFENDER_XDR_CLIENT_SECRET", "")
COLLECTION_MODE = os.getenv("DEFENDER_XDR_COLLECTION_MODE", "incidents"); BATCH_SIZE = int(os.getenv("DEFENDER_XDR_BATCH_SIZE", "50"))
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"; _warned_403 = False
def fetch_recent_incidents(lookback_minutes=20):
    global _warned_403
    if not ENABLED: return []
    token = get_graph_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    if not token: return []
    since = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    endpoint = "/security/incidents" if COLLECTION_MODE == "incidents" else "/security/alerts_v2"
    params = {"$filter": f"lastUpdateDateTime ge {since}", "$top": BATCH_SIZE, "$orderby": "lastUpdateDateTime desc"}
    try:
        with httpx.Client(timeout=20) as client:
            resp = client.get(f"{GRAPH_BASE_URL}{endpoint}", params=params, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 403: return []
            resp.raise_for_status(); return resp.json().get("value", [])
    except Exception: return []
def defender_incident_to_normalized(incident):
    severity_map = {"informational": "low", "low": "low", "medium": "medium", "high": "high"}
    severity = severity_map.get(str(incident.get("severity", "medium")).lower(), "medium")
    mitre_techniques = []; alert_categories = []
    for alert in incident.get("alerts", []) or []:
        mitre_techniques.extend(alert.get("mitreTechniques", []) or [])
        if alert.get("category"): alert_categories.append(alert["category"])
    display_name = incident.get("displayName") or incident.get("determination") or "Defender XDR incident"
    top_category = alert_categories[0] if alert_categories else None
    description = f"{display_name} [{top_category}]" if top_category else display_name
    incident_id = str(incident.get("id") or "")
    raw_hash = hashlib.sha256(json.dumps(incident, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    stable_id = hashlib.sha256(("defender:" + (incident_id or raw_hash)).encode()).hexdigest()[:24]
    return {"id": f"evt-defxdr-{stable_id}", "source": "m365_defender_xdr", "type": "security_alert",
            "severity": severity, "description": description, "mitre_technique": list(set(mitre_techniques)),
            "time": incident.get("lastUpdateDateTime", datetime.now(timezone.utc).isoformat()), "raw": incident,
            "raw_hash": raw_hash, "raw_kv": {"defender_incident_id": incident_id,
            "classification": incident.get("classification"), "determination": incident.get("determination"),
            "status": incident.get("status"), "alert_categories": alert_categories, "security_signal": True}}
