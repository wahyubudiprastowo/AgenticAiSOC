from __future__ import annotations
import logging, os
from datetime import datetime, timedelta, timezone
from typing import Iterable
from urllib.parse import urlsplit
import httpx
from .auth import get_management_api_token
logger = logging.getLogger("m365-collector.management_api")
TENANT_ID = os.getenv("M365_TENANT_ID", ""); CLIENT_ID = os.getenv("M365_CLIENT_ID", ""); CLIENT_SECRET = os.getenv("M365_CLIENT_SECRET", "")
CONTENT_TYPES = [c.strip() for c in os.getenv("M365_CONTENT_TYPES", "Audit.AzureActiveDirectory,Audit.Exchange,Audit.SharePoint,Audit.General,DLP.All").split(",") if c.strip()]
BASE_URL = f"https://manage.office.com/api/v1.0/{TENANT_ID}/activity/feed"
PUBLISHER_IDENTIFIER = os.getenv("M365_PUBLISHER_IDENTIFIER", "").strip()
MAX_CONTENT_PAGES = max(1, int(os.getenv("M365_MAX_CONTENT_PAGES", "100")))
CURSOR_OVERLAP_SECONDS = max(0, int(os.getenv("M365_CURSOR_OVERLAP_SECONDS", "120")))
_started_subscriptions: set[str] = set()
_stats = {"subscription_list_checks": 0, "subscription_attempts": 0,
          "subscription_errors": 0, "content_pages": 0,
          "content_blobs": 0, "blob_errors": 0, "last_error": None}

def get_stats() -> dict:
    return {**_stats, "started_subscriptions": sorted(_started_subscriptions)}

def _headers():
    token = get_management_api_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    if not token: raise RuntimeError("no token")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def _publisher_params(content_type: str) -> dict[str, str]:
    params = {"contentType": content_type}
    if PUBLISHER_IDENTIFIER:
        params["PublisherIdentifier"] = PUBLISHER_IDENTIFIER
    return params

def _list_subscription_params() -> dict[str, str]:
    return {"PublisherIdentifier": PUBLISHER_IDENTIFIER} if PUBLISHER_IDENTIFIER else {}

def _safe_next_page_uri(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value)
    allowed_hosts = {"manage.office.com", "manage-gcc.office.com", "manage.office365.us",
                     "manage.protection.apps.mil"}
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in allowed_hosts:
        raise RuntimeError("untrusted NextPageUri returned by M365")
    return value

def ensure_subscriptions_started():
    missing = [ct for ct in CONTENT_TYPES if ct not in _started_subscriptions]
    if not missing:
        return
    try:
        _stats["subscription_list_checks"] += 1
        with httpx.Client(timeout=15) as client:
            response = client.get(f"{BASE_URL}/subscriptions/list",
                                  params=_list_subscription_params(), headers=_headers())
            response.raise_for_status()
            subscriptions = response.json()
        if not isinstance(subscriptions, list):
            raise RuntimeError("M365 subscription list returned a non-list response")
        _started_subscriptions.update(
            item.get("contentType") for item in subscriptions
            if isinstance(item, dict) and item.get("status") == "enabled" and item.get("contentType")
        )
    except Exception as exc:
        # Listing failure must not prevent a valid POST start attempt.
        logger.warning("M365 subscription list failed: %s", type(exc).__name__)
    for ct in CONTENT_TYPES:
        if ct in _started_subscriptions: continue
        _stats["subscription_attempts"] += 1
        try:
            with httpx.Client(timeout=15) as client:
                # The Management Activity API defines this operation as POST.
                resp = client.post(f"{BASE_URL}/subscriptions/start", params=_publisher_params(ct),
                                   headers=_headers())
                resp.raise_for_status()
                _started_subscriptions.add(ct)
        except Exception as exc:
            _stats["subscription_errors"] += 1
            _stats["last_error"] = f"subscription {ct}: {type(exc).__name__}"
            logger.warning("M365 subscription start failed for %s: %s", ct, type(exc).__name__)

def fetch_content_blobs(content_type, start_time: datetime, end_time: datetime) -> list[dict]:
    params = {**_publisher_params(content_type),
              "startTime": start_time.strftime("%Y-%m-%dT%H:%M:%S"),
              "endTime": end_time.strftime("%Y-%m-%dT%H:%M:%S")}
    url: str | None = f"{BASE_URL}/subscriptions/content"
    blobs: list[dict] = []
    with httpx.Client(timeout=20) as client:
        for page in range(MAX_CONTENT_PAGES):
            if not url:
                break
            response = client.get(url, params=params if page == 0 else None, headers=_headers())
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, list):
                raise RuntimeError("M365 content listing returned a non-list response")
            blobs.extend(item for item in payload if isinstance(item, dict))
            _stats["content_pages"] += 1
            url = _safe_next_page_uri(response.headers.get("NextPageUri"))
        else:
            if url:
                raise RuntimeError(f"M365 content pagination exceeded {MAX_CONTENT_PAGES} pages")
    _stats["content_blobs"] += len(blobs)
    return blobs

def fetch_blob_records(content_uri):
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(content_uri, headers=_headers()); resp.raise_for_status()
            payload = resp.json()
            if not isinstance(payload, list):
                raise RuntimeError("M365 content blob returned a non-list response")
            return payload
    except Exception:
        _stats["blob_errors"] += 1
        raise

def _cursor_start(cursor_value: str | None, end_time: datetime, lookback_minutes: int) -> datetime:
    initial = end_time - timedelta(minutes=lookback_minutes)
    if cursor_value:
        try:
            parsed = datetime.fromisoformat(cursor_value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            initial = parsed.astimezone(timezone.utc) - timedelta(seconds=CURSOR_OVERLAP_SECONDS)
        except (TypeError, ValueError):
            logger.warning("Ignoring invalid M365 cursor timestamp")
    # The service supports at most a 24-hour content interval.
    return max(initial, end_time - timedelta(hours=24))

def poll_all_content(lookback_minutes=15, cursor_getter=None, cursor_setter=None) -> Iterable[dict]:
    ensure_subscriptions_started()
    for ct in CONTENT_TYPES:
        end_time = datetime.now(timezone.utc)
        cursor_value = cursor_getter(ct) if cursor_getter else None
        start_time = _cursor_start(cursor_value, end_time, lookback_minutes)
        for blob in fetch_content_blobs(ct, start_time=start_time, end_time=end_time):
            uri = blob.get("contentUri")
            if not uri: continue
            for record in fetch_blob_records(uri): record["_content_type"] = ct; yield record
        if cursor_setter:
            cursor_setter(ct, end_time.isoformat())
        _stats["last_error"] = None
