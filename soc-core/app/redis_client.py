import json, os
from typing import Optional
import redis
REDIS_HOST = os.getenv("REDIS_HOST", "redis"); REDIS_PORT = int(os.getenv("REDIS_PORT", "6379")); REDIS_DB = int(os.getenv("REDIS_DB", "0"))
QUEUE_RAW_EVENTS = os.getenv("QUEUE_RAW_EVENTS", "raw_events"); QUEUE_FILTERED_EVENTS = os.getenv("QUEUE_FILTERED_EVENTS", "filtered_events")
_client: Optional[redis.Redis] = None
def get_client() -> redis.Redis:
    global _client
    if _client is None: _client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    return _client
def blocking_pop_raw_event(timeout=5):
    item = get_client().blpop(QUEUE_RAW_EVENTS, timeout=timeout)
    if item is None: return None
    _, payload = item; return json.loads(payload)
def push_filtered_event(event: dict) -> None: get_client().rpush(QUEUE_FILTERED_EVENTS, json.dumps(event))
def raw_queue_length() -> int: return get_client().llen(QUEUE_RAW_EVENTS)
def filtered_queue_length() -> int: return get_client().llen(QUEUE_FILTERED_EVENTS)
def increment_window(key: str, ttl_seconds: int) -> int:
    client = get_client(); count = int(client.incr(key))
    if count == 1: client.expire(key, ttl_seconds)
    return count
def claim_once(key: str, ttl_seconds: int) -> bool:
    return bool(get_client().set(key, "1", nx=True, ex=ttl_seconds))
