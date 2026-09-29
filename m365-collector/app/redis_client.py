import json, os
import redis
REDIS_HOST = os.getenv("REDIS_HOST", "redis"); REDIS_PORT = int(os.getenv("REDIS_PORT", "6379")); REDIS_DB = int(os.getenv("REDIS_DB", "0"))
QUEUE_RAW_EVENTS = os.getenv("QUEUE_RAW_EVENTS", "raw_events")
_client = None
def get_client():
    global _client
    if _client is None: _client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    return _client
def push_raw_event(event: dict) -> None: get_client().rpush(QUEUE_RAW_EVENTS, json.dumps(event))
