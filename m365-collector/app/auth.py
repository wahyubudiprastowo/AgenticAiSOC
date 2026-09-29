from __future__ import annotations
import logging, os, time
from typing import Optional
import httpx
logger = logging.getLogger("m365-collector.auth")
_token_cache: dict[str, tuple[float, str]] = {}
def get_token(tenant_id, client_id, client_secret, scope) -> Optional[str]:
    cache_key = f"{tenant_id}:{client_id}:{scope}"; cached = _token_cache.get(cache_key); now = time.time()
    if cached and cached[0] > now: return cached[1]
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret, "scope": scope}
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.post(url, data=data); resp.raise_for_status(); payload = resp.json()
            token = payload["access_token"]; expires_in = payload.get("expires_in", 3600)
            _token_cache[cache_key] = (now + expires_in - 120, token); return token
    except Exception: return None
def get_management_api_token(t, c, s): return get_token(t, c, s, "https://manage.office.com/.default")
def get_graph_token(t, c, s): return get_token(t, c, s, "https://graph.microsoft.com/.default")
