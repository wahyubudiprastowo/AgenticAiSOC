from __future__ import annotations
import hashlib, logging, os, uuid
import httpx
logger = logging.getLogger("hermes.memory")
QDRANT_ENABLED = os.getenv("QDRANT_ENABLED", "true").lower() == "true"
QDRANT_HOST = os.getenv("QDRANT_HOST", "qdrant"); QDRANT_PORT = int(os.getenv("QDRANT_PORT", "6333"))
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "soc_incident_memory"); QDRANT_VECTOR_SIZE = int(os.getenv("QDRANT_VECTOR_SIZE", "384"))
BASE_URL = f"http://{QDRANT_HOST}:{QDRANT_PORT}"; _collection_ready = False
def _point_id(finding_id: str) -> str:
    try: return str(uuid.UUID(str(finding_id)))
    except (ValueError, TypeError, AttributeError):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"agentic-soc-finding:{finding_id}"))
def _hash_embed(text: str, dim: int = QDRANT_VECTOR_SIZE) -> list[float]:
    vec = [0.0] * dim
    for tok in text.lower().split():
        for i in range(len(tok) - 2):
            h = int(hashlib.md5(tok[i:i+3].encode()).hexdigest(), 16); vec[h % dim] += 1.0
    norm = sum(v * v for v in vec) ** 0.5
    if norm > 0: vec = [v / norm for v in vec]
    return vec
def ensure_collection() -> None:
    global _collection_ready
    if _collection_ready or not QDRANT_ENABLED: return
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(f"{BASE_URL}/collections/{QDRANT_COLLECTION}")
            if resp.status_code == 200: _collection_ready = True; return
            create_resp = client.put(f"{BASE_URL}/collections/{QDRANT_COLLECTION}", json={"vectors": {"size": QDRANT_VECTOR_SIZE, "distance": "Cosine"}})
            create_resp.raise_for_status(); _collection_ready = True
    except Exception: pass
def store_incident_memory(finding_id: str, evidence_obj: dict, jev_result: dict) -> None:
    if not QDRANT_ENABLED: return
    ensure_collection()
    if not _collection_ready: return
    text = f"{evidence_obj.get('finding', '')} " + " ".join(evidence_obj.get("evidence", [])); vector = _hash_embed(text)
    payload = {"finding_id": finding_id, "finding_text": evidence_obj.get("finding"), "context": evidence_obj.get("context"),
               "threat_classification": jev_result.get("threat_classification"), "mitre_technique": jev_result.get("mitre_technique", []),
               "confidence": jev_result.get("confidence"), "severity": jev_result.get("severity"),
               "recommendation": jev_result.get("investigation_recommendation")}
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.put(f"{BASE_URL}/collections/{QDRANT_COLLECTION}/points",
                json={"points": [{"id": _point_id(finding_id), "vector": vector, "payload": payload}]}); resp.raise_for_status()
    except Exception: pass
def search_similar_incidents(query_text: str, limit: int = 3) -> list[dict]:
    if not QDRANT_ENABLED: return []
    ensure_collection()
    if not _collection_ready: return []
    vector = _hash_embed(query_text)
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(f"{BASE_URL}/collections/{QDRANT_COLLECTION}/points/search", json={"vector": vector, "limit": limit, "with_payload": True})
            resp.raise_for_status(); hits = resp.json().get("result", [])
            return [{"score": h.get("score"), **h.get("payload", {})} for h in hits]
    except Exception: return []
