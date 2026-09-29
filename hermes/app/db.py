from __future__ import annotations
import json, logging, os
from contextlib import contextmanager
from typing import Optional
import psycopg2, psycopg2.extras
from psycopg2 import pool
logger = logging.getLogger("hermes.db")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://soc_admin:change_this_password@postgres:5432/agentic_soc")
_pool: Optional[pool.SimpleConnectionPool] = None
def _finding_dict(row) -> dict:
    value = dict(row)
    event_ids = value.get("event_ids")
    if isinstance(event_ids, str):
        value["event_ids"] = [item.strip().strip('"') for item in event_ids.strip("{}").split(",") if item.strip()]
    elif event_ids is not None:
        value["event_ids"] = [str(item) for item in event_ids]
    return value
def init_pool(minconn=1, maxconn=5):
    global _pool
    if _pool is None: _pool = psycopg2.pool.SimpleConnectionPool(minconn, maxconn, dsn=DATABASE_URL)
@contextmanager
def get_conn():
    if _pool is None: init_pool()
    conn = _pool.getconn()
    try: yield conn; conn.commit()
    except Exception: conn.rollback(); raise
    finally: _pool.putconn(conn)
def insert_finding(event_ids, category, threat_classification, mitre_technique, confidence, severity, evidence, ai_result, recommendation) -> str:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO findings (event_ids, category, threat_classification, mitre_technique,
                    confidence, severity, evidence, ai_result, recommendation) VALUES (%s::uuid[], %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;""",
                (event_ids, category, threat_classification, mitre_technique, confidence, severity, json.dumps(evidence), json.dumps(ai_result), recommendation))
            return str(cur.fetchone()[0])
def log_agent_run(agent_name, finding_id, input_payload, output_payload, duration_ms) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO agent_runs (agent_name, finding_id, input_payload, output_payload, duration_ms) VALUES (%s, %s, %s, %s, %s);""",
                (agent_name, finding_id, json.dumps(input_payload), json.dumps(output_payload), duration_ms))
def list_findings(limit=50) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM findings ORDER BY created_time DESC LIMIT %s", (limit,)); return [_finding_dict(r) for r in cur.fetchall()]
def get_finding(finding_id: str) -> Optional[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM findings WHERE id = %s", (finding_id,)); row = cur.fetchone()
            return _finding_dict(row) if row else None
def findings_since(minutes=1440) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""SELECT * FROM findings WHERE created_time >= now() - (%s || ' minutes')::interval ORDER BY created_time DESC""", (str(minutes),))
            return [_finding_dict(r) for r in cur.fetchall()]

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
            cur.execute(f"SELECT count(*) AS total FROM findings {where}", params)
            total = int(cur.fetchone()["total"])
            cur.execute(f"SELECT * FROM findings {where} ORDER BY created_time DESC LIMIT %s OFFSET %s",
                        [*params, limit, offset])
            return [_finding_dict(r) for r in cur.fetchall()], total

def findings_analytics(start_time=None, end_time=None, bucket="hour", severity=None, category=None, query=None) -> dict:
    bucket_sql = {"hour": "hour", "day": "day", "week": "week", "month": "month", "year": "year"}[bucket]
    where, params = _finding_filters(start_time, end_time, severity, category, query)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"""SELECT date_trunc('{bucket_sql}', created_time) AS bucket, count(*) AS total,
                        count(*) FILTER (WHERE severity IN ('high','critical')) AS high_critical
                    FROM findings {where} GROUP BY 1 ORDER BY 1""", params)
            timeline = [{"bucket": row["bucket"], "total": int(row["total"]),
                         "high_critical": int(row["high_critical"])} for row in cur.fetchall()]
            cur.execute(f"SELECT category, count(*) AS total FROM findings {where} GROUP BY category ORDER BY total DESC", params)
            categories = [{"category": row["category"] or "unknown", "total": int(row["total"])} for row in cur.fetchall()]
            cur.execute(f"SELECT severity, count(*) AS total FROM findings {where} GROUP BY severity ORDER BY total DESC", params)
            severities = [{"severity": row["severity"] or "unknown", "total": int(row["total"])} for row in cur.fetchall()]
            cur.execute(f"""SELECT count(*) FILTER (WHERE severity IN ('high','critical')) AS high_critical,
                        coalesce(avg(confidence), 0) AS avg_confidence FROM findings {where}""", params)
            summary = cur.fetchone()
            cur.execute(f"""SELECT t.technique, count(*) AS total FROM findings,
                        LATERAL unnest(coalesce(mitre_technique, ARRAY[]::text[])) AS t(technique)
                    {where} GROUP BY t.technique ORDER BY total DESC LIMIT 16""", params)
            mitre = [{"id": row["technique"], "total": int(row["total"])} for row in cur.fetchall()]
    return {"bucket": bucket, "timeline": timeline, "categories": categories, "severities": severities,
            "mitre": mitre, "total": sum(item["total"] for item in categories),
            "high_critical": int(summary["high_critical"]), "avg_confidence": round(float(summary["avg_confidence"]), 3)}
