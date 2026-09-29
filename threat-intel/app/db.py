from __future__ import annotations
import json, logging, os
from contextlib import contextmanager
from typing import Optional
import psycopg2, psycopg2.extras
from psycopg2 import pool
logger = logging.getLogger("threat-intel.db")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://soc_admin:change_this_password@postgres:5432/agentic_soc")
_pool: Optional[pool.SimpleConnectionPool] = None
def init_pool(minconn=1, maxconn=3):
    global _pool
    if _pool is None: _pool = psycopg2.pool.SimpleConnectionPool(minconn, maxconn, dsn=DATABASE_URL)
@contextmanager
def get_conn():
    if _pool is None: init_pool()
    conn = _pool.getconn()
    try: yield conn; conn.commit()
    except Exception: conn.rollback(); raise
    finally: _pool.putconn(conn)
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
            cur.execute("SELECT * FROM threat_research ORDER BY fetched_at DESC LIMIT %s", (limit,))
            return [dict(r) for r in cur.fetchall()]
def list_org_vulnerabilities(limit=50) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM cyfirma_org_vulnerabilities ORDER BY fetched_at DESC LIMIT %s", (limit,))
            return [dict(r) for r in cur.fetchall()]
