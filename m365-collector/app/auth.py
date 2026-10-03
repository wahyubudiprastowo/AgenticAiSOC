from __future__ import annotations
import logging, os, time
import httpx
logger = logging.getLogger("m365-collector.auth")
_token_cache: dict[str, tuple[float, str]] = {}


class OAuthTokenError(RuntimeError):
    """Authentication failed without exposing the OAuth response or credentials."""


def _safe_oauth_error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"OAuth HTTP {exc.response.status_code}"
    if isinstance(exc, httpx.TimeoutException):
        return "OAuth timeout"
    if isinstance(exc, httpx.TransportError):
        return "OAuth transport error"
    if isinstance(exc, (KeyError, ValueError)):
        return "OAuth response schema error"
    return f"OAuth {type(exc).__name__}"


def get_token(tenant_id, client_id, client_secret, scope) -> str:
    cache_key = f"{tenant_id}:{client_id}:{scope}"; cached = _token_cache.get(cache_key); now = time.time()
    if cached and cached[0] > now: return cached[1]
    if not tenant_id or not client_id or not client_secret:
        raise OAuthTokenError("OAuth configuration incomplete")
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret, "scope": scope}
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.post(url, data=data); resp.raise_for_status(); payload = resp.json()
            token = payload["access_token"]; expires_in = payload.get("expires_in", 3600)
            _token_cache[cache_key] = (now + expires_in - 120, token); return token
    except Exception as exc:
        detail = _safe_oauth_error(exc)
        logger.warning("Microsoft token request failed: %s", detail)
        raise OAuthTokenError(detail) from exc
def get_management_api_token(t, c, s): return get_token(t, c, s, "https://manage.office.com/.default")
def get_graph_token(t, c, s): return get_token(t, c, s, "https://graph.microsoft.com/.default")
