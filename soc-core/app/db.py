from __future__ import annotations
import ipaddress, json, os, logging
from contextlib import contextmanager
from typing import Optional
import psycopg2, psycopg2.extras
from psycopg2 import pool
logger = logging.getLogger("soc-core.db")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://soc_admin:change_this_password@postgres:5432/agentic_soc")
_pool: Optional[pool.SimpleConnectionPool] = None
def init_pool(minconn=1, maxconn=10):
    global _pool
    if _pool is None: _pool = psycopg2.pool.SimpleConnectionPool(minconn, maxconn, dsn=DATABASE_URL)
@contextmanager
def get_conn():
    if _pool is None: init_pool()
    conn = _pool.getconn()
    try: yield conn; conn.commit()
    except Exception: conn.rollback(); raise
    finally: _pool.putconn(conn)
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
                    user_name, description, mitre_technique, raw_hash, raw_payload, normalized, is_filtered_in)
                VALUES (%(external_id)s, %(source)s, %(type)s, %(severity)s, NULLIF(%(src_ip)s, '')::inet,
                    NULLIF(%(dst_ip)s, '')::inet, %(user_name)s, %(description)s, %(mitre_technique)s,
                    %(raw_hash)s, %(raw_payload)s, %(normalized)s, %(is_filtered_in)s)
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

def update_event_decision(event_id: str, event: dict) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE events SET type=%s, severity=%s, description=%s, mitre_technique=%s,
                    raw_payload=%s, normalized=%s, is_filtered_in=%s WHERE id=%s""",
                (event.get("type"), event.get("severity", "low"), event.get("description"),
                 event.get("mitre_technique") or [], json.dumps(event.get("raw_kv", {})),
                 json.dumps(event), event.get("is_filtered_in", False), event_id))
def list_events(limit=100, severity=None, since_minutes=None) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            conditions, params = [], []
            if severity: conditions.append("severity = %s"); params.append(severity)
            if since_minutes: conditions.append("created_at >= now() - (%s || ' minutes')::interval"); params.append(str(since_minutes))
            where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            params.append(limit)
            cur.execute(f"SELECT * FROM events {where} ORDER BY created_at DESC LIMIT %s", params)
            return [dict(r) for r in cur.fetchall()]
def get_event(event_id: str) -> Optional[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM events WHERE id = %s", (event_id,)); row = cur.fetchone()
            return dict(row) if row else None
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
            cur.execute(f"SELECT e.* FROM events e {where} ORDER BY e.created_at DESC LIMIT %s", [*params, limit])
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
