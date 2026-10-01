import json, os
import redis
REDIS_HOST = os.getenv("REDIS_HOST", "redis"); REDIS_PORT = int(os.getenv("REDIS_PORT", "6379")); REDIS_DB = int(os.getenv("REDIS_DB", "0"))
QUEUE_RAW_EVENTS = os.getenv("QUEUE_RAW_EVENTS", "raw_events")
CURSOR_PREFIX = os.getenv("M365_CURSOR_PREFIX", "m365:content_cursor:")
_client = None
def get_client():
    global _client
    if _client is None: _client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    return _client
def push_raw_event(event: dict) -> None: get_client().rpush(QUEUE_RAW_EVENTS, json.dumps(event))
def get_content_cursor(content_type: str) -> str | None: return get_client().get(f"{CURSOR_PREFIX}{content_type}")
def set_content_cursor(content_type: str, value: str) -> None: get_client().set(f"{CURSOR_PREFIX}{content_type}", value)
