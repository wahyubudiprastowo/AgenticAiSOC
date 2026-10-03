from __future__ import annotations
import json, logging, os, threading
from contextlib import contextmanager
from typing import Optional
import psycopg2, psycopg2.extras
from psycopg2 import pool
logger = logging.getLogger("threat-intel.db")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://soc_admin:change_this_password@postgres:5432/agentic_soc")
_pool: Optional[pool.ThreadedConnectionPool] = None
_pool_slots: Optional[threading.BoundedSemaphore] = None
_pool_init_lock = threading.Lock()
def init_pool(minconn: int | None = None, maxconn: int | None = None):
    global _pool, _pool_slots
    if _pool is not None: return
    with _pool_init_lock:
        if _pool is not None: return
        minconn = minconn if minconn is not None else int(os.getenv("INTEL_DB_POOL_MIN", "2"))
        maxconn = maxconn if maxconn is not None else int(os.getenv("INTEL_DB_POOL_MAX", "8"))
        if minconn < 1 or maxconn < minconn:
            raise ValueError("threat-intel DB pool requires 1 <= min <= max")
        _pool = psycopg2.pool.ThreadedConnectionPool(minconn, maxconn, dsn=DATABASE_URL)
        _pool_slots = threading.BoundedSemaphore(maxconn)
@contextmanager
def get_conn():
    if _pool is None: init_pool()
    if _pool_slots is None or not _pool_slots.acquire(timeout=float(os.getenv("INTEL_DB_POOL_WAIT_SECONDS", "20"))):
        raise TimeoutError("timed out waiting for a threat-intel database connection")
    conn = None
    try:
        conn = _pool.getconn()
        if conn.closed:
            _pool.putconn(conn, close=True)
            conn = _pool.getconn()
        yield conn
        conn.commit()
    except Exception:
        if conn is not None and not conn.closed:
            conn.rollback()
        raise
    finally:
        if conn is not None:
            _pool.putconn(conn, close=bool(conn.closed))
        _pool_slots.release()
def upsert_research_item(title, url, summary, published_at, raw_payload) -> bool:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO threat_research (provider, title, url, summary, published_at, raw_payload)
                VALUES ('cyfirma', %s, %s, %s, %s, %s) ON CONFLICT (provider, url) DO NOTHING RETURNING id;""",
                (title, url, summary, published_at, json.dumps(raw_payload)))
            return cur.fetchone() is not None
def upsert_org_vulnerability(cve, severity, title, description, is_zero_day, detected_at, raw_payload) -> bool:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO cyfirma_org_vulnerabilities (cve, severity, title, description, is_zero_day, detected_at, raw_payload)
                VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (cve, title) DO NOTHING RETURNING id;""",
                (cve, severity, title, description, is_zero_day, detected_at, json.dumps(raw_payload)))
            return cur.fetchone() is not None
def list_research(limit=25) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""SELECT * FROM threat_research
                ORDER BY published_at DESC NULLS LAST, fetched_at DESC LIMIT %s""", (limit,))
            return [dict(r) for r in cur.fetchall()]
def list_org_vulnerabilities(limit=50) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM cyfirma_org_vulnerabilities ORDER BY fetched_at DESC LIMIT %s", (limit,))
            return [dict(r) for r in cur.fetchall()]


def get_recent_provider_result(ioc: str, ioc_type: str, provider: str,
                               max_age_seconds: int) -> dict | None:
    """Return previously persisted live provider evidence, if it is still fresh."""
    if max_age_seconds <= 0:
        return None
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT raw_response
                FROM intelligence
                WHERE upper(ioc)=upper(%s) AND ioc_type=%s AND provider=%s
                  AND checked_at >= now() - (%s * interval '1 second')
                  AND raw_response->>'mode'='live'
                ORDER BY checked_at DESC LIMIT 1
            """, (ioc, ioc_type, provider, max_age_seconds))
            row = cur.fetchone()
    raw = row.get("raw_response") if row else None
    return dict(raw) if isinstance(raw, dict) else None
