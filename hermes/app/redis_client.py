import hashlib, json, os
from typing import Optional
import redis
REDIS_HOST = os.getenv("REDIS_HOST", "redis"); REDIS_PORT = int(os.getenv("REDIS_PORT", "6379")); REDIS_DB = int(os.getenv("REDIS_DB", "0"))
QUEUE_FILTERED_EVENTS = os.getenv("QUEUE_FILTERED_EVENTS", "filtered_events"); QUEUE_FINDINGS = os.getenv("QUEUE_FINDINGS", "findings_stream")
QUEUE_FILTERED_PROCESSING = os.getenv("QUEUE_FILTERED_PROCESSING", f"{QUEUE_FILTERED_EVENTS}:processing")
QUEUE_FILTERED_DLQ = os.getenv("QUEUE_FILTERED_DLQ", f"{QUEUE_FILTERED_EVENTS}:dead_letter")
QUEUE_MAX_RETRIES = max(0, int(os.getenv("QUEUE_MAX_RETRIES", "3")))
_RETRY_HASH = f"{QUEUE_FILTERED_EVENTS}:retry_count"
_client: Optional[redis.Redis] = None
def get_client() -> redis.Redis:
    global _client
    if _client is None: _client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    return _client
def _retry_key(payload: str) -> str: return hashlib.sha256(payload.encode()).hexdigest()
def blocking_claim_filtered_event(timeout=5):
    payload = get_client().blmove(QUEUE_FILTERED_EVENTS, QUEUE_FILTERED_PROCESSING, timeout, "LEFT", "RIGHT")
    if payload is None: return None
    try: return json.loads(payload), payload
    except (TypeError, ValueError):
        client = get_client(); pipe = client.pipeline(transaction=True)
        pipe.lrem(QUEUE_FILTERED_PROCESSING, 1, payload); pipe.rpush(QUEUE_FILTERED_DLQ, payload); pipe.execute()
        return None
def ack_filtered_event(payload: str) -> None:
    client = get_client(); pipe = client.pipeline(transaction=True)
    pipe.lrem(QUEUE_FILTERED_PROCESSING, 1, payload); pipe.hdel(_RETRY_HASH, _retry_key(payload)); pipe.execute()
def retry_filtered_event(payload: str) -> str:
    client = get_client(); key = _retry_key(payload); attempts = int(client.hincrby(_RETRY_HASH, key, 1))
    pipe = client.pipeline(transaction=True); pipe.lrem(QUEUE_FILTERED_PROCESSING, 1, payload)
    if attempts > QUEUE_MAX_RETRIES:
        pipe.rpush(QUEUE_FILTERED_DLQ, payload); pipe.hdel(_RETRY_HASH, key); outcome = "dead_letter"
    else:
        pipe.rpush(QUEUE_FILTERED_EVENTS, payload); outcome = "retried"
    pipe.execute(); return outcome
def recover_filtered_inflight() -> int:
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
    return int(get_client().eval(script, 2, QUEUE_FILTERED_PROCESSING, QUEUE_FILTERED_EVENTS))
def publish_finding(finding: dict) -> None:
    client = get_client(); client.rpush(QUEUE_FINDINGS, json.dumps(finding)); client.ltrim(QUEUE_FINDINGS, -500, -1)
def recent_findings(count=50) -> list[dict]: return [json.loads(r) for r in get_client().lrange(QUEUE_FINDINGS, -count, -1)]
def filtered_queue_length() -> int: return get_client().llen(QUEUE_FILTERED_EVENTS)
def filtered_queue_stats() -> dict:
    client = get_client()
    return {"queued": client.llen(QUEUE_FILTERED_EVENTS), "processing": client.llen(QUEUE_FILTERED_PROCESSING),
            "dead_letter": client.llen(QUEUE_FILTERED_DLQ)}
