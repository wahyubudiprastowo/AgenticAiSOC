#!/usr/bin/env python3
"""Add CVE enrichment to historical findings without rewriting source data.

Dry-run is the default. ``--apply`` performs idempotent upserts into
``finding_indicators`` only; events and findings are never updated or deleted.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import time
from urllib.request import Request, ProxyHandler, build_opener

import psycopg2
import psycopg2.extras


ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = ("vulnerability_management", "zero_day", "sql_injection", "supply_chain")


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def connect(args):
    if args.db_dsn:
        return psycopg2.connect(args.db_dsn)
    if os.getenv("DATABASE_URL") and not args.db_host:
        return psycopg2.connect(os.environ["DATABASE_URL"])
    env = load_env(ROOT / ".env")
    return psycopg2.connect(
        host=args.db_host or "127.0.0.1",
        port=args.db_port or int(env.get("POSTGRES_HOST_PORT", "35432")),
        dbname=env.get("POSTGRES_DB", "agentic_soc"),
        user=env.get("POSTGRES_USER", "soc_admin"),
        password=env.get("POSTGRES_PASSWORD", ""),
    )


def candidates(connection, refresh_unavailable: bool) -> list[dict]:
    refresh_clause = "OR fi.enrichment_status IN ('unavailable','stale_cache','unknown')" if refresh_unavailable else ""
    query = f"""
    WITH candidate_events AS (
        SELECT f.id AS finding_id, linked.event_id, e.description, e.raw_payload
        FROM findings f
        CROSS JOIN LATERAL unnest(f.event_ids) AS linked(event_id)
        JOIN events e ON e.id=linked.event_id
        WHERE f.category = ANY(%s)
          AND (e.description ILIKE '%%CVE-%%' OR e.raw_payload::text ILIKE '%%CVE-%%')
    ), extracted AS (
        SELECT DISTINCT c.finding_id, c.event_id, upper(match[1]) AS cve
        FROM candidate_events c
        CROSS JOIN LATERAL regexp_matches(
            coalesce(c.description,'') || ' ' || coalesce(c.raw_payload::text,''),
            '(CVE-[0-9]{{4}}-[0-9]{{4,8}})', 'gi'
        ) AS match
    )
    SELECT x.finding_id::text, x.event_id::text, x.cve,
           fi.enrichment_status AS existing_status
    FROM extracted x
    LEFT JOIN finding_indicators fi
      ON fi.finding_id=x.finding_id AND fi.ioc_type='cve' AND upper(fi.ioc)=x.cve
    WHERE fi.id IS NULL {refresh_clause}
    ORDER BY x.cve, x.finding_id
    """
    with connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
        cursor.execute(query, (list(CATEGORIES),))
        return [dict(row) for row in cursor.fetchall()]


def enrich(threat_intel_url: str, cve: str, timeout: float, refresh: bool = False) -> dict:
    body = json.dumps({"ioc": cve, "ioc_type": "cve", "providers": ["nvd"],
                       "refresh": refresh}).encode()
    request = Request(f"{threat_intel_url.rstrip('/')}/enrich", data=body,
                      headers={"Content-Type": "application/json"}, method="POST")
    # Internal Docker service names must bypass inherited HTTP(S) proxies.
    # The endpoint is configured explicitly and never derived from finding data.
    opener = build_opener(ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        return json.load(response)


def upsert_cve(connection, rows: list[dict], result: dict) -> int:
    providers = result.get("providers") or []
    with connection.cursor() as cursor:
        for row in rows:
            cursor.execute("""
                INSERT INTO finding_indicators
                    (finding_id,event_id,ioc,ioc_type,malicious,confidence,
                     enrichment_status,verdict_reason,provider_results,checked_at)
                VALUES (%s::uuid,%s::uuid,%s,'cve',%s,%s,%s,%s,%s,now())
                ON CONFLICT (finding_id,ioc_type,ioc) DO UPDATE SET
                    event_id=EXCLUDED.event_id,
                    malicious=EXCLUDED.malicious,
                    confidence=EXCLUDED.confidence,
                    enrichment_status=EXCLUDED.enrichment_status,
                    verdict_reason=EXCLUDED.verdict_reason,
                    provider_results=EXCLUDED.provider_results,
                    checked_at=now()
            """, (row["finding_id"], row["event_id"], row["cve"],
                  bool(result.get("malicious")), float(result.get("confidence") or 0),
                  result.get("enrichment_status") or "unknown",
                  result.get("verdict_reason") or "historical_cve_enrichment",
                  json.dumps(providers)))
    connection.commit()
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write additive finding_indicators rows")
    parser.add_argument("--refresh-unavailable", action="store_true")
    parser.add_argument("--max-cves", type=int, default=0, help="0 means all candidates")
    parser.add_argument("--delay", type=float, default=0.0, help="optional delay after each CVE")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--threat-intel-url", default=os.getenv("THREAT_INTEL_URL", "http://localhost:38005"),
                        help="threat-intel base URL; SOC Core container receives its internal URL from Compose")
    parser.add_argument("--db-dsn")
    parser.add_argument("--db-host")
    parser.add_argument("--db-port", type=int)
    args = parser.parse_args()

    connection = connect(args)
    try:
        rows = candidates(connection, args.refresh_unavailable)
        grouped: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            grouped[row["cve"]].append(row)
        cves = sorted(grouped)
        if args.max_cves > 0:
            cves = cves[:args.max_cves]
        print(json.dumps({"mode": "apply" if args.apply else "dry_run",
                          "candidate_cves": len(grouped), "selected_cves": len(cves),
                          "candidate_finding_links": sum(len(grouped[cve]) for cve in cves)}))
        if not args.apply:
            return 0
        inserted = errors = unavailable = 0
        for index, cve in enumerate(cves, start=1):
            try:
                result = enrich(args.threat_intel_url, cve, args.timeout,
                                refresh=args.refresh_unavailable)
                inserted += upsert_cve(connection, grouped[cve], result)
                if result.get("enrichment_status") == "unavailable": unavailable += 1
                print(json.dumps({"progress": f"{index}/{len(cves)}", "cve": cve,
                                  "links": len(grouped[cve]),
                                  "status": result.get("enrichment_status")}))
            except Exception as exc:
                connection.rollback(); errors += 1
                print(json.dumps({"progress": f"{index}/{len(cves)}", "cve": cve,
                                  "error": type(exc).__name__}))
            if args.delay > 0: time.sleep(args.delay)
        print(json.dumps({"completed": True, "upserted_links": inserted,
                          "unavailable_cves": unavailable, "errors": errors}))
        return 1 if errors else 0
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
