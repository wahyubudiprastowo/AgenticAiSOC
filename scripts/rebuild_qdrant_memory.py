#!/usr/bin/env python3
"""Rebuild Qdrant incident memory from authoritative PostgreSQL findings."""
from __future__ import annotations

import os
import psycopg2
import psycopg2.extras

from app import memory


def main() -> int:
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    stored = 0
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id,evidence,ai_result FROM findings ORDER BY created_time")
        rows = cur.fetchall()
    for row in rows:
        memory.store_incident_memory(str(row["id"]), dict(row["evidence"] or {}), dict(row["ai_result"] or {}))
        stored += 1
    conn.close()
    print({"stored": stored})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
