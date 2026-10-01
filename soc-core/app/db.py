from __future__ import annotations
import ipaddress, json, os, logging, threading
from contextlib import contextmanager
from typing import Optional
import psycopg2, psycopg2.extras
from psycopg2 import pool
logger = logging.getLogger("soc-core.db")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://soc_admin:change_this_password@postgres:5432/agentic_soc")
_pool: Optional[pool.SimpleConnectionPool] = None
_pool_slots: Optional[threading.BoundedSemaphore] = None

# Lists intentionally exclude the large normalized event and complete AI payload.
# Full evidence remains available through get_finding()/the detail endpoint.
_FINDING_LIST_COLUMNS = """
    id, event_ids, primary_event_id, category, threat_classification,
    mitre_technique, confidence, severity, recommendation, status,
    created_time, analysis_status, detection_rule, detection_source,
    updated_time, attack_family, attack_subtype, taxonomy_version,
    classification_method, detection_rule_version, evidence_quality,
    attribution_status, ai_verdict, ai_reasoning_mode,
    correlation_key, correlation_scope, correlation_count, first_seen, last_seen,
    jsonb_build_object(
        'threat_summary', coalesce(ai_result->'threat_summary', '{}'::jsonb)
    ) AS ai_result,
    jsonb_build_object(
        'evidence', coalesce(evidence->'evidence', '[]'::jsonb),
        'event', jsonb_build_object(
            'is_synthetic_test', coalesce(evidence #>> '{event,is_synthetic_test}', 'false') = 'true'
        )
    ) AS evidence,
    (coalesce(evidence #>> '{event,is_synthetic_test}', 'false') = 'true') AS is_synthetic_test
"""

_EVENT_LIST_COLUMNS = """
    id, external_id, source, type, severity, src_ip, dst_ip, user_name,
    description, mitre_technique, is_filtered_in, created_at
"""
def init_pool(minconn: int | None = None, maxconn: int | None = None):
    global _pool, _pool_slots
    if _pool is None:
        minconn = minconn if minconn is not None else int(os.getenv("SOC_DB_POOL_MIN", "2"))
        maxconn = maxconn if maxconn is not None else int(os.getenv("SOC_DB_POOL_MAX", "16"))
        if minconn < 1 or maxconn < minconn:
            raise ValueError("SOC DB pool requires 1 <= min <= max")
        _pool = psycopg2.pool.ThreadedConnectionPool(minconn, maxconn, dsn=DATABASE_URL)
        _pool_slots = threading.BoundedSemaphore(maxconn)
        _ensure_finding_schema()
@contextmanager
def get_conn():
    if _pool is None: init_pool()
    if _pool_slots is None or not _pool_slots.acquire(timeout=float(os.getenv("SOC_DB_POOL_WAIT_SECONDS", "20"))):
        raise TimeoutError("timed out waiting for a SOC database connection")
    conn = None
    try:
        conn = _pool.getconn()
        yield conn
        conn.commit()
    except Exception:
        if conn is not None: conn.rollback()
        raise
    finally:
        if conn is not None: _pool.putconn(conn)
        _pool_slots.release()
def _ensure_finding_schema() -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS primary_event_id UUID")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS analysis_status TEXT NOT NULL DEFAULT 'complete'")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS detection_rule TEXT")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS detection_source TEXT")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS updated_time TIMESTAMPTZ")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack_family TEXT")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack_subtype TEXT")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS taxonomy_version TEXT")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS classification_method TEXT")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS detection_rule_version INTEGER")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_quality TEXT")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS attribution_status TEXT NOT NULL DEFAULT 'none'")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_verdict TEXT")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_reasoning_mode TEXT")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS correlation_key TEXT")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS correlation_scope TEXT")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS correlation_count INTEGER NOT NULL DEFAULT 1")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ")
            cur.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_subtype ON findings (attack_subtype)")
            cur.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS pipeline_status TEXT NOT NULL DEFAULT 'complete'")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_pipeline_status ON events (pipeline_status) WHERE pipeline_status <> 'complete'")
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_primary_event ON findings (primary_event_id) WHERE primary_event_id IS NOT NULL")
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_correlation_key ON findings (correlation_key) WHERE correlation_key IS NOT NULL")
            cur.execute("""CREATE TABLE IF NOT EXISTS finding_indicators (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                event_id UUID REFERENCES events(id) ON DELETE SET NULL,
                ioc TEXT NOT NULL, ioc_type TEXT NOT NULL,
                malicious BOOLEAN NOT NULL DEFAULT FALSE,
                confidence NUMERIC(4,3) NOT NULL DEFAULT 0.0,
                enrichment_status TEXT NOT NULL DEFAULT 'unknown', verdict_reason TEXT,
                provider_results JSONB NOT NULL DEFAULT '[]'::jsonb,
                checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                UNIQUE (finding_id, ioc_type, ioc))""")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_finding_indicators_finding ON finding_indicators (finding_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_finding_indicators_ioc ON finding_indicators (ioc_type, ioc)")
def _finding_dict(row) -> dict:
    value = dict(row); event_ids = value.get("event_ids")
    if isinstance(event_ids, str):
        value["event_ids"] = [item.strip().strip('"') for item in event_ids.strip("{}").split(",") if item.strip()]
    elif event_ids is not None:
        value["event_ids"] = [str(item) for item in event_ids]
    return value
def _as_ip(value) -> str:
    if value is None: return ""
    candidate = str(value).strip()
    try: return str(ipaddress.ip_address(candidate))
    except ValueError: return ""
def health() -> bool:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            return cur.fetchone()[0] == 1
def insert_event(event: dict) -> tuple[str, bool]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO events (external_id, source, type, severity, src_ip, dst_ip,
                    user_name, description, mitre_technique, raw_hash, raw_payload, normalized, is_filtered_in,
                    pipeline_status)
                VALUES (%(external_id)s, %(source)s, %(type)s, %(severity)s, NULLIF(%(src_ip)s, '')::inet,
                    NULLIF(%(dst_ip)s, '')::inet, %(user_name)s, %(description)s, %(mitre_technique)s,
                    %(raw_hash)s, %(raw_payload)s, %(normalized)s, %(is_filtered_in)s, 'processing')
                ON CONFLICT DO NOTHING RETURNING id;""", {
                    "external_id": event.get("id"), "source": event.get("source", "unknown"), "type": event.get("type"),
                    "severity": event.get("severity", "low"), "src_ip": _as_ip(event.get("src_ip")), "dst_ip": _as_ip(event.get("destination")),
                    "user_name": event.get("user_name"), "description": event.get("description"),
                    "mitre_technique": event.get("mitre_technique") or [], "raw_hash": event.get("raw_hash", ""),
                    "raw_payload": json.dumps(event.get("raw_kv", {})), "normalized": json.dumps(event),
                    "is_filtered_in": event.get("is_filtered_in", False)})
            row = cur.fetchone()
            if row: return str(row[0]), True
            if event.get("source") in ("m365_audit", "m365_defender_xdr"):
                cur.execute("SELECT id FROM events WHERE source=%s AND (external_id=%s OR raw_hash=%s) LIMIT 1",
                            (event.get("source"), event.get("id"), event.get("raw_hash", "")))
            else:
                cur.execute("SELECT id FROM events WHERE source=%s AND external_id=%s LIMIT 1",
                            (event.get("source", "unknown"), event.get("id")))
            existing = cur.fetchone()
            if not existing: raise RuntimeError("event insert conflict without existing row")
            return str(existing[0]), False

def find_event_by_external_id(source: str, external_id: str) -> Optional[str]:
    if not external_id: return None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM events WHERE source=%s AND external_id=%s LIMIT 1", (source, external_id))
            row = cur.fetchone(); return str(row[0]) if row else None

def find_duplicate_event(event: dict) -> Optional[str]:
    source = event.get("source", "unknown"); external_id = event.get("id", "")
    with get_conn() as conn:
        with conn.cursor() as cur:
            if source in ("m365_audit", "m365_defender_xdr"):
                cur.execute("SELECT id FROM events WHERE source=%s AND (external_id=%s OR raw_hash=%s) LIMIT 1",
                            (source, external_id, event.get("raw_hash", "")))
            else:
                cur.execute("SELECT id FROM events WHERE source=%s AND external_id=%s LIMIT 1", (source, external_id))
            row = cur.fetchone(); return str(row[0]) if row else None

def event_pipeline_status(event_id: str) -> str:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pipeline_status FROM events WHERE id=%s", (event_id,))
            row = cur.fetchone(); return str(row[0]) if row else "missing"

def update_event_decision(event_id: str, event: dict) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE events SET type=%s, severity=%s, description=%s, mitre_technique=%s,
                    raw_payload=%s, normalized=%s, is_filtered_in=%s WHERE id=%s""",
                (event.get("type"), event.get("severity", "low"), event.get("description"),
                 event.get("mitre_technique") or [], json.dumps(event.get("raw_kv", {})),
                 json.dumps(event), event.get("is_filtered_in", False), event_id))

def mark_event_complete(event_id: str) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE events SET pipeline_status='complete' WHERE id=%s", (event_id,))
def list_events(limit=100, severity=None, since_minutes=None) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            conditions, params = [], []
            if severity: conditions.append("severity = %s"); params.append(severity)
            if since_minutes: conditions.append("created_at >= now() - (%s || ' minutes')::interval"); params.append(str(since_minutes))
            where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            params.append(limit)
            cur.execute(f"SELECT {_EVENT_LIST_COLUMNS} FROM events {where} ORDER BY created_at DESC LIMIT %s", params)
            return [dict(r) for r in cur.fetchall()]
def get_event(event_id: str) -> Optional[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM events WHERE id = %s", (event_id,)); row = cur.fetchone()
            return dict(row) if row else None
def _incident_values(event: dict) -> tuple[str | None, str | None, str | None]:
    raw = event.get("raw_kv") or {}
    key = str(raw.get("incident_key") or "").strip() or None
    scope = str(raw.get("incident_scope") or "").strip() or None
    source_time = str(event.get("time") or "").strip() or None
    return key, scope, source_time


def _attach_correlated(cur, correlation_key: str, event_id: str, event: dict) -> str | None:
    max_events = max(1, int(os.getenv("M365_INCIDENT_MAX_LINKED_EVENTS", "100")))
    _, _, source_time = _incident_values(event)
    cur.execute("""UPDATE findings SET
            event_ids=CASE WHEN %s::uuid=ANY(event_ids) OR cardinality(event_ids)>=%s
                THEN event_ids ELSE array_append(event_ids,%s::uuid) END,
            correlation_count=CASE WHEN %s::uuid=ANY(event_ids)
                THEN correlation_count ELSE correlation_count+1 END,
            first_seen=LEAST(coalesce(first_seen,created_time),coalesce(%s::timestamptz,now())),
            last_seen=GREATEST(coalesce(last_seen,created_time),coalesce(%s::timestamptz,now())),
            updated_time=now()
        WHERE correlation_key=%s RETURNING id,correlation_count""",
        (event_id, max_events, event_id, event_id, source_time, source_time, correlation_key))
    row = cur.fetchone()
    if not row:
        return None
    finding_id, count = str(row[0]), int(row[1])
    cur.execute("""UPDATE findings SET evidence=jsonb_set(evidence,'{correlation}',
            jsonb_build_object('key',correlation_key,'scope',correlation_scope,
                'event_count',%s,'linked_event_limit',%s),true) WHERE id=%s""",
        (count, max_events, finding_id))
    return finding_id


def attach_event_to_correlated_finding(correlation_key: str, event_id: str, event: dict) -> str | None:
    if not correlation_key:
        return None
    with get_conn() as conn:
        with conn.cursor() as cur:
            return _attach_correlated(cur, correlation_key, event_id, event)


def insert_deterministic_finding(event_id: str, event: dict, detection: dict,
                                 ioc_hits: list[dict] | None = None) -> tuple[str, bool]:
    raw = event.get("raw_kv") or {}
    correlation_key, correlation_scope, source_time = _incident_values(event)
    indicators = [{"ioc": hit.get("ioc"), "ioc_type": hit.get("ioc_type"),
                   "malicious": bool(hit.get("malicious")), "confidence": float(hit.get("confidence") or 0),
                   "enrichment_status": hit.get("enrichment_status", "unknown"),
                   "verdict_reason": hit.get("verdict_reason"), "providers": hit.get("providers") or []}
                  for hit in (ioc_hits or [])]
    evidence = {"finding": event.get("description") or event.get("type"),
        "evidence": [f"{detection['rule_id']}: normalized event type '{event.get('type')}' matched deterministic detection"],
        "context": event.get("destination") or event.get("source"), "category_hint": detection["category"],
        "subtype_hint": detection["attack_subtype"], "taxonomy_version": detection["taxonomy_version"],
        "deterministic_detection": detection,
        "indicators": indicators,
        "skill": None, "event": {"source": event.get("source"), "type": event.get("type"),
            "severity": event.get("severity"), "action": event.get("action"),
            "mitre_technique": event.get("mitre_technique") or [], "operation": raw.get("operation"),
            "wazuh_rule_id": raw.get("wazuh_rule_id"), "wazuh_rule_groups": raw.get("wazuh_rule_groups") or [],
            "correlation_count": raw.get("correlation_count"), "test_marker": raw.get("test_marker"),
            "is_synthetic_test": bool(raw.get("is_synthetic_test"))},
        "correlation": ({"key": correlation_key, "scope": correlation_scope, "event_count": 1}
                        if correlation_key else None)}
    ai_result = {"analysis_status": "pending_ai", "deterministic": True,
                 "reason": "Finding persisted before optional Hermes/Jev enrichment"}
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO findings (event_ids, primary_event_id, category, threat_classification,
                    mitre_technique, confidence, severity, evidence, ai_result, recommendation,
                    analysis_status, detection_rule, detection_source, updated_time,
                    attack_family, attack_subtype, taxonomy_version, classification_method,
                    detection_rule_version, evidence_quality, attribution_status, ai_verdict, ai_reasoning_mode,
                    correlation_key, correlation_scope, correlation_count, first_seen, last_seen)
                VALUES (ARRAY[%s::uuid], %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s,
                    'pending_ai', %s, 'soc_core', now(), %s, %s, %s, %s, %s, %s, %s, NULL, NULL,
                    %s, %s, 1, coalesce(%s::timestamptz,now()), coalesce(%s::timestamptz,now()))
                ON CONFLICT DO NOTHING RETURNING id""",
                (event_id, event_id, detection["category"], detection["classification"],
                 detection.get("mitre_technique") or event.get("mitre_technique") or [], detection["confidence"],
                 event.get("severity", "low"), json.dumps(evidence), json.dumps(ai_result),
                 detection["recommendation"], detection["rule_id"], detection.get("attack_family"),
                 detection.get("attack_subtype"), detection.get("taxonomy_version"),
                 detection.get("classification_method"), detection.get("rule_version"),
                 detection.get("evidence_quality"), detection.get("attribution_status", "none"),
                 correlation_key, correlation_scope, source_time, source_time))
            row = cur.fetchone()
            if row: return str(row[0]), True
            if correlation_key:
                attached = _attach_correlated(cur, correlation_key, event_id, event)
                if attached:
                    return attached, False
            cur.execute("SELECT id FROM findings WHERE primary_event_id=%s::uuid", (event_id,))
            existing = cur.fetchone()
            if not existing: raise RuntimeError("deterministic finding conflict without existing row")
            return str(existing[0]), False
def upsert_finding_indicators(finding_id: str, event_id: str, ioc_hits: list[dict]) -> None:
    if not ioc_hits: return
    with get_conn() as conn:
        with conn.cursor() as cur:
            for hit in ioc_hits:
                if not hit.get("ioc") or not hit.get("ioc_type"): continue
                cur.execute("""INSERT INTO finding_indicators
                        (finding_id,event_id,ioc,ioc_type,malicious,confidence,enrichment_status,verdict_reason,provider_results)
                    VALUES (%s::uuid,%s::uuid,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (finding_id,ioc_type,ioc) DO UPDATE SET
                        event_id=EXCLUDED.event_id, malicious=EXCLUDED.malicious,
                        confidence=EXCLUDED.confidence, enrichment_status=EXCLUDED.enrichment_status,
                        verdict_reason=EXCLUDED.verdict_reason, provider_results=EXCLUDED.provider_results,
                        checked_at=now()""",
                    (finding_id, event_id, hit["ioc"], hit["ioc_type"], bool(hit.get("malicious")),
                     float(hit.get("confidence") or 0), hit.get("enrichment_status", "unknown"),
                     hit.get("verdict_reason"), json.dumps(hit.get("providers") or [])))
def _attach_indicators(cur, finding: dict | None) -> dict | None:
    if finding is None: return None
    value = _finding_dict(finding)
    cur.execute("""SELECT ioc,ioc_type,malicious,confidence,enrichment_status,verdict_reason,
                    provider_results,checked_at FROM finding_indicators
                WHERE finding_id=%s ORDER BY malicious DESC,ioc_type,ioc""", (value["id"],))
    indicators = []
    for row in cur.fetchall():
        item = dict(row); item["confidence"] = float(item.get("confidence") or 0)
        item["checked_at"] = item["checked_at"].isoformat() if item.get("checked_at") else None
        indicators.append(item)
    value["indicators"] = indicators
    return value
def list_findings(limit=50) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"SELECT {_FINDING_LIST_COLUMNS} FROM findings ORDER BY created_time DESC LIMIT %s", (limit,))
            return [_finding_dict(row) for row in cur.fetchall()]
def get_finding(finding_id: str) -> Optional[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM findings WHERE id=%s", (finding_id,)); row = cur.fetchone()
            return _attach_indicators(cur, row)
def get_finding_by_event_id(event_id: str) -> Optional[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM findings WHERE %s::uuid=ANY(event_ids) ORDER BY created_time DESC LIMIT 1", (event_id,))
            row = cur.fetchone(); return _attach_indicators(cur, row)
def findings_since(minutes=1440, limit=200) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"""SELECT {_FINDING_LIST_COLUMNS} FROM findings
                        WHERE created_time >= now()-(%s || ' minutes')::interval
                        ORDER BY created_time DESC LIMIT %s""", (str(minutes), limit))
            return [_finding_dict(row) for row in cur.fetchall()]
def _finding_filters(start_time=None, end_time=None, severity=None, category=None, query=None) -> tuple[str, list]:
    conditions, params = [], []
    if start_time is not None: conditions.append("created_time >= %s"); params.append(start_time)
    if end_time is not None: conditions.append("created_time <= %s"); params.append(end_time)
    if severity: conditions.append("severity = %s"); params.append(severity)
    if category: conditions.append("category = %s"); params.append(category)
    if query:
        pattern = f"%{query.strip()}%"
        conditions.append("(id::text ILIKE %s OR threat_classification ILIKE %s OR category ILIKE %s OR recommendation ILIKE %s)")
        params.extend([pattern] * 4)
    return (f"WHERE {' AND '.join(conditions)}" if conditions else ""), params
def search_findings(start_time=None, end_time=None, limit=100, offset=0, severity=None, category=None, query=None) -> tuple[list[dict], int]:
    where, params = _finding_filters(start_time, end_time, severity, category, query)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"SELECT count(*) AS total FROM findings {where}", params); total = int(cur.fetchone()["total"])
            cur.execute(f"SELECT {_FINDING_LIST_COLUMNS} FROM findings {where} ORDER BY created_time DESC LIMIT %s OFFSET %s",
                        [*params, limit, offset])
            return [_finding_dict(row) for row in cur.fetchall()], total
def findings_analytics(start_time=None, end_time=None, bucket="hour", severity=None, category=None, query=None) -> dict:
    bucket_sql = {"hour": "hour", "day": "day", "week": "week", "month": "month", "year": "year"}[bucket]
    where, params = _finding_filters(start_time, end_time, severity, category, query)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"""SELECT date_trunc('{bucket_sql}', created_time) AS bucket, count(*) AS total,
                        count(*) FILTER (WHERE severity IN ('high','critical')) AS high_critical
                    FROM findings {where} GROUP BY 1 ORDER BY 1""", params)
            timeline = [{"bucket": row["bucket"], "total": int(row["total"]), "high_critical": int(row["high_critical"])} for row in cur.fetchall()]
            cur.execute(f"SELECT category, count(*) AS total FROM findings {where} GROUP BY category ORDER BY total DESC", params)
            categories = [{"category": row["category"] or "unknown", "total": int(row["total"])} for row in cur.fetchall()]
            cur.execute(f"SELECT severity, count(*) AS total FROM findings {where} GROUP BY severity ORDER BY total DESC", params)
            severities = [{"severity": row["severity"] or "unknown", "total": int(row["total"])} for row in cur.fetchall()]
            cur.execute(f"SELECT count(*) FILTER (WHERE severity IN ('high','critical')) AS high_critical, coalesce(avg(confidence),0) AS avg_confidence FROM findings {where}", params)
            summary = cur.fetchone()
            cur.execute(f"""SELECT t.technique, count(*) AS total FROM findings,
                        LATERAL unnest(coalesce(mitre_technique, ARRAY[]::text[])) AS t(technique)
                    {where} GROUP BY t.technique ORDER BY total DESC LIMIT 16""", params)
            mitre = [{"id": row["technique"], "total": int(row["total"])} for row in cur.fetchall()]
    return {"bucket": bucket, "timeline": timeline, "categories": categories, "severities": severities,
            "mitre": mitre, "total": sum(item["total"] for item in categories),
            "high_critical": int(summary["high_critical"]), "avg_confidence": round(float(summary["avg_confidence"]), 3)}
def stats() -> dict:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM events;"); total_events = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM events WHERE is_filtered_in = TRUE;"); filtered_in = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM findings;"); total_findings = cur.fetchone()[0]
            cur.execute("SELECT severity, count(*) FROM events GROUP BY severity ORDER BY severity;")
            by_severity = {r[0]: r[1] for r in cur.fetchall()}
            cur.execute("SELECT source, count(*) FROM events GROUP BY source ORDER BY count(*) DESC;")
            by_source = {r[0]: r[1] for r in cur.fetchall()}
            cur.execute("SELECT type, count(*) FROM events GROUP BY type ORDER BY count(*) DESC;")
            by_type = {r[0]: r[1] for r in cur.fetchall()}
    return {"total_events": total_events, "filtered_in_events": filtered_in, "total_findings": total_findings,
            "events_by_severity": by_severity, "events_by_source": by_source, "events_by_type": by_type}
def timeline_buckets(hours=24) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT date_trunc('hour', created_at) AS bucket, count(*) AS total,
                       count(*) FILTER (WHERE is_filtered_in) AS forwarded FROM events
                WHERE created_at >= now() - (%s || ' hours')::interval GROUP BY bucket ORDER BY bucket ASC;""", (str(hours),))
            return [{"bucket": r[0].isoformat(), "total": r[1], "forwarded": r[2]} for r in cur.fetchall()]

def _overview_filters(start_time=None, end_time=None, severity=None, category=None) -> tuple[str, list]:
    conditions, params = [], []
    if start_time is not None: conditions.append("e.created_at >= %s"); params.append(start_time)
    if end_time is not None: conditions.append("e.created_at <= %s"); params.append(end_time)
    if severity: conditions.append("e.severity = %s"); params.append(severity)
    if category:
        conditions.append("e.id IN (SELECT unnest(f.event_ids) FROM findings f WHERE f.category = %s)")
        params.append(category)
    return (f"WHERE {' AND '.join(conditions)}" if conditions else ""), params

def overview(start_time=None, end_time=None, bucket="hour", severity=None, category=None, limit=25) -> dict:
    """Return exact, time-scoped event metrics for the dashboard in one DB round trip."""
    bucket_sql = {"hour": "hour", "day": "day", "week": "week", "month": "month", "year": "year"}[bucket]
    where, params = _overview_filters(start_time, end_time, severity, category)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"""SELECT count(*) AS total_events,
                        count(*) FILTER (WHERE e.is_filtered_in) AS filtered_in_events
                    FROM events e {where}""", params)
            stats_row = cur.fetchone()
            cur.execute(f"""SELECT date_trunc('{bucket_sql}', e.created_at) AS bucket,
                        count(*) AS total, count(*) FILTER (WHERE e.is_filtered_in) AS forwarded
                    FROM events e {where} GROUP BY 1 ORDER BY 1""", params)
            timeline = [{"bucket": row["bucket"], "total": int(row["total"]), "forwarded": int(row["forwarded"])}
                        for row in cur.fetchall()]
            cur.execute(f"SELECT e.severity, count(*) AS total FROM events e {where} GROUP BY e.severity ORDER BY total DESC", params)
            severities = [{"severity": row["severity"] or "unknown", "total": int(row["total"])} for row in cur.fetchall()]
            cur.execute(f"SELECT e.source, count(*) AS total FROM events e {where} GROUP BY e.source ORDER BY total DESC", params)
            sources = [{"source": row["source"] or "unknown", "total": int(row["total"])} for row in cur.fetchall()]
            cur.execute(f"SELECT {_EVENT_LIST_COLUMNS} FROM events e {where} ORDER BY e.created_at DESC LIMIT %s",
                        [*params, limit])
            events = [dict(row) for row in cur.fetchall()]
    total_events = int(stats_row["total_events"])
    filtered_in = int(stats_row["filtered_in_events"])
    return {"stats": {"total_events": total_events, "filtered_in_events": filtered_in},
            "bucket": bucket, "timeline": timeline, "severities": severities, "sources": sources,
            "events": events, "count": len(events)}
def upsert_intelligence(ioc, ioc_type, provider, malicious, score, raw) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO intelligence (ioc, ioc_type, provider, malicious, score, raw_response)
                VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (ioc, provider) DO UPDATE SET malicious = EXCLUDED.malicious,
                    score = EXCLUDED.score, raw_response = EXCLUDED.raw_response, checked_at = now();""",
                (ioc, ioc_type, provider, malicious, score, json.dumps(raw)))
