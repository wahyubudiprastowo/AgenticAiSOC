from __future__ import annotations
import logging, os
from datetime import datetime, timedelta, timezone
from typing import Iterable
import httpx
from .auth import get_management_api_token
logger = logging.getLogger("m365-collector.management_api")
TENANT_ID = os.getenv("M365_TENANT_ID", ""); CLIENT_ID = os.getenv("M365_CLIENT_ID", ""); CLIENT_SECRET = os.getenv("M365_CLIENT_SECRET", "")
CONTENT_TYPES = [c.strip() for c in os.getenv("M365_CONTENT_TYPES", "Audit.AzureActiveDirectory,Audit.Exchange,Audit.SharePoint,Audit.General,DLP.All").split(",") if c.strip()]
BASE_URL = f"https://manage.office.com/api/v1.0/{TENANT_ID}/activity/feed"
_started_subscriptions: set[str] = set()
def _headers():
    token = get_management_api_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    if not token: raise RuntimeError("no token")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
def ensure_subscriptions_started():
    for ct in CONTENT_TYPES:
        if ct in _started_subscriptions: continue
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.put(f"{BASE_URL}/subscriptions/start", params={"contentType": ct}, headers=_headers())
                if resp.status_code in (200, 400): _started_subscriptions.add(ct)
        except Exception: pass
def fetch_content_blobs(content_type, lookback_minutes=15):
    end_time = datetime.now(timezone.utc); start_time = end_time - timedelta(minutes=lookback_minutes)
    params = {"contentType": content_type, "startTime": start_time.strftime("%Y-%m-%dT%H:%M:%S"), "endTime": end_time.strftime("%Y-%m-%dT%H:%M:%S")}
    try:
        with httpx.Client(timeout=20) as client:
            resp = client.get(f"{BASE_URL}/subscriptions/content", params=params, headers=_headers()); resp.raise_for_status(); return resp.json()
    except Exception: return []
def fetch_blob_records(content_uri):
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(content_uri, headers=_headers()); resp.raise_for_status(); return resp.json()
    except Exception: return []
def poll_all_content(lookback_minutes=15) -> Iterable[dict]:
    ensure_subscriptions_started()
    for ct in CONTENT_TYPES:
        for blob in fetch_content_blobs(ct, lookback_minutes=lookback_minutes):
            uri = blob.get("contentUri")
            if not uri: continue
            for record in fetch_blob_records(uri): record["_content_type"] = ct; yield record
