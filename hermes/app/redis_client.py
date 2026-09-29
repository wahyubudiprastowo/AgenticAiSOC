import json, os
from typing import Optional
import redis
REDIS_HOST = os.getenv("REDIS_HOST", "redis"); REDIS_PORT = int(os.getenv("REDIS_PORT", "6379")); REDIS_DB = int(os.getenv("REDIS_DB", "0"))
QUEUE_FILTERED_EVENTS = os.getenv("QUEUE_FILTERED_EVENTS", "filtered_events"); QUEUE_FINDINGS = os.getenv("QUEUE_FINDINGS", "findings_stream")
_client: Optional[redis.Redis] = None
def get_client() -> redis.Redis:
    global _client
    if _client is None: _client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    return _client
def blocking_pop_filtered_event(timeout=5):
    item = get_client().blpop(QUEUE_FILTERED_EVENTS, timeout=timeout)
    if item is None: return None
    _, payload = item; return json.loads(payload)
def publish_finding(finding: dict) -> None:
    client = get_client(); client.rpush(QUEUE_FINDINGS, json.dumps(finding)); client.ltrim(QUEUE_FINDINGS, -500, -1)
def recent_findings(count=50) -> list[dict]: return [json.loads(r) for r in get_client().lrange(QUEUE_FINDINGS, -count, -1)]
def filtered_queue_length() -> int: return get_client().llen(QUEUE_FILTERED_EVENTS)
