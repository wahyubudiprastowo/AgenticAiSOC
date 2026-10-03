import hashlib, json, os
from typing import Optional
import redis
REDIS_HOST = os.getenv("REDIS_HOST", "redis"); REDIS_PORT = int(os.getenv("REDIS_PORT", "6379")); REDIS_DB = int(os.getenv("REDIS_DB", "0"))
QUEUE_RAW_EVENTS = os.getenv("QUEUE_RAW_EVENTS", "raw_events"); QUEUE_FILTERED_EVENTS = os.getenv("QUEUE_FILTERED_EVENTS", "filtered_events")
QUEUE_RAW_PROCESSING = os.getenv("QUEUE_RAW_PROCESSING", f"{QUEUE_RAW_EVENTS}:processing")
QUEUE_RAW_DLQ = os.getenv("QUEUE_RAW_DLQ", f"{QUEUE_RAW_EVENTS}:dead_letter")
QUEUE_MAX_RETRIES = max(0, int(os.getenv("QUEUE_MAX_RETRIES", "3")))
_RETRY_HASH = f"{QUEUE_RAW_EVENTS}:retry_count"
_SOURCE_CURSOR_PREFIX = "soc:source_cursor:"
_client: Optional[redis.Redis] = None
def get_client() -> redis.Redis:
    global _client
    if _client is None: _client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    return _client
def _retry_key(payload: str) -> str: return hashlib.sha256(payload.encode()).hexdigest()
def blocking_claim_raw_event(timeout=5):
    payload = get_client().blmove(QUEUE_RAW_EVENTS, QUEUE_RAW_PROCESSING, timeout, "LEFT", "RIGHT")
    if payload is None: return None
    try: return json.loads(payload), payload
    except (TypeError, ValueError):
        client = get_client(); pipe = client.pipeline(transaction=True)
        pipe.lrem(QUEUE_RAW_PROCESSING, 1, payload); pipe.rpush(QUEUE_RAW_DLQ, payload); pipe.execute()
        return None
def ack_raw_event(payload: str) -> None:
    client = get_client(); pipe = client.pipeline(transaction=True)
    pipe.lrem(QUEUE_RAW_PROCESSING, 1, payload); pipe.hdel(_RETRY_HASH, _retry_key(payload)); pipe.execute()
def retry_raw_event(payload: str) -> str:
    client = get_client(); key = _retry_key(payload); attempts = int(client.hincrby(_RETRY_HASH, key, 1))
    pipe = client.pipeline(transaction=True); pipe.lrem(QUEUE_RAW_PROCESSING, 1, payload)
    if attempts > QUEUE_MAX_RETRIES:
        pipe.rpush(QUEUE_RAW_DLQ, payload); pipe.hdel(_RETRY_HASH, key); outcome = "dead_letter"
    else:
        pipe.rpush(QUEUE_RAW_EVENTS, payload); outcome = "retried"
    pipe.execute(); return outcome
def recover_raw_inflight() -> int:
    script = """
    local count=0
    while true do
      local value=redis.call('RPOP', KEYS[1])
      if not value then break end
      redis.call('LPUSH', KEYS[2], value)
      count=count+1
    end
    return count
    """
    return int(get_client().eval(script, 2, QUEUE_RAW_PROCESSING, QUEUE_RAW_EVENTS))
def push_filtered_event(event: dict) -> None: get_client().rpush(QUEUE_FILTERED_EVENTS, json.dumps(event))
def raw_queue_length() -> int: return get_client().llen(QUEUE_RAW_EVENTS)
def filtered_queue_length() -> int: return get_client().llen(QUEUE_FILTERED_EVENTS)
def raw_queue_stats() -> dict:
    client = get_client()
    return {"queued": client.llen(QUEUE_RAW_EVENTS), "processing": client.llen(QUEUE_RAW_PROCESSING),
            "dead_letter": client.llen(QUEUE_RAW_DLQ)}
def increment_window(key: str, ttl_seconds: int) -> int:
    client = get_client(); count = int(client.incr(key))
    if count == 1: client.expire(key, ttl_seconds)
    return count
def claim_once(key: str, ttl_seconds: int) -> bool:
    return bool(get_client().set(key, "1", nx=True, ex=ttl_seconds))


def get_source_cursor(stream: str) -> dict | None:
    value = get_client().get(f"{_SOURCE_CURSOR_PREFIX}{stream}")
    if not value: return None
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else None
    except (TypeError, ValueError):
        return None


def set_source_cursor(stream: str, cursor: dict) -> None:
    get_client().set(f"{_SOURCE_CURSOR_PREFIX}{stream}", json.dumps(cursor, separators=(",", ":")))
