#!/usr/bin/env python3
"""Rebuild findings from persisted events using the current Hermes skills.

Run inside the Hermes container, where DATABASE_URL/Redis settings and the
Hermes package are available. Use --apply only after creating database backup
tables. Routine/unmatched events remain in the events table but do not become
AI findings.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json

import psycopg2
import psycopg2.extras

from app import redis_client
from app.skill_loader import select_skill


M365_TYPE_BY_OPERATION = {
    "MalwareDetected": "malware",
    "PhishNotAllowed": "phishing",
    "DlpRuleMatch": "data_exfiltration",
    "Copy to Removable Media": "data_exfiltration",
    "New-InboxRule": "mailbox_rule_change",
    "Consent to application": "oauth_consent",
    "Add app role assignment to service principal": "privilege_change",
    "Add member to role": "privilege_change",
    "MemberAdded": "privilege_change",
    "AnonymousLinkCreated": "external_sharing",
}


def prepare_event(row: dict) -> dict:
    event = dict(row.get("normalized") or {})
    event["db_id"] = str(row["id"])
    event["source"] = row["source"]
    event["type"] = row.get("type")
    event["severity"] = row.get("severity")
    event["description"] = row.get("description")
    event["mitre_technique"] = row.get("mitre_technique") or []
    event["raw_kv"] = dict(event.get("raw_kv") or row.get("raw_payload") or {})

    if row["source"] == "m365_audit":
        operation = str(event["raw_kv"].get("operation") or "")
        event["type"] = M365_TYPE_BY_OPERATION.get(operation, "generic")
        if operation == "UserLoginFailed": event["type"] = "auth_failure"
        if operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileDownloadedFromBrowser"):
            event["type"] = "file_download"
        if operation == "TIMailData":
            raw = event.get("raw") or {}
            threat_text = json.dumps({"verdict": raw.get("Verdict"), "threats": raw.get("ThreatsAndDetectionTech")}).lower()
            if "phish" in threat_text:
                event["type"] = "phishing"; event["severity"] = "high"; event["raw_kv"]["security_signal"] = True
            elif any(marker in threat_text for marker in ("malware", "trojan", "virus")):
                event["type"] = "malware"; event["severity"] = "high"; event["raw_kv"]["security_signal"] = True

    if row["source"] == "wazuh" and "office365" in (event["raw_kv"].get("wazuh_rule_groups") or []):
        event["skip_reclassification"] = True
    if row["source"] == "wazuh":
        groups = {str(g).strip().lower() for g in (event["raw_kv"].get("wazuh_rule_groups") or [])}
        description = str(event.get("description") or "").lower()
        if "ipsec" in groups and "attack" not in description:
            event["type"] = "security_alert"

    if row["source"] == "wazuh" and row.get("type") == "vulnerability":
        raw = event.get("raw") or {}
        vulnerability = raw.get("vulnerability") or {}
        package = raw.get("package") or vulnerability.get("package") or {}
        cve = vulnerability.get("id") or vulnerability.get("cve")
        if cve:
            event["description"] = f"{cve} affecting {package.get('name', 'unknown package')} {package.get('version', '')}".strip()
            event["raw_kv"].update({"cve": cve, "package": package})
    return event


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--since-hours", type=int, default=24)
    args = parser.parse_args()
    import os
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    counts = Counter(); selected: list[tuple[dict, dict]] = []
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM events WHERE created_at >= now() - (%s || ' hours')::interval ORDER BY created_at",
                    (str(args.since_hours),))
        for row in cur.fetchall():
            event = prepare_event(dict(row))
            if event.pop("skip_reclassification", False):
                counts["duplicate_source"] += 1; continue
            skill = select_skill(event)
            if skill is None:
                counts["unmatched"] += 1; continue
            wazuh_evidence = (event.get("source") == "wazuh" and
                              (bool(event.get("mitre_technique")) or event.get("severity") in ("high", "critical") or
                               event.get("type") in ("network_attack", "reconnaissance", "credential_attack", "malware",
                                                     "ransomware", "web_attack", "dos_attack", "zero_day")))
            if not row.get("is_filtered_in") and not (event.get("raw_kv") or {}).get("security_signal") and not wazuh_evidence:
                counts["not_forwarded"] += 1; continue
            counts[skill["category"]] += 1; selected.append((event, skill))
    print(json.dumps({"events": sum(counts.values()), "selected": len(selected), "distribution": counts}, default=dict, indent=2))
    if not args.apply:
        conn.close(); return 0

    queue = redis_client.get_client()
    queue.delete(redis_client.QUEUE_FILTERED_EVENTS, redis_client.QUEUE_FINDINGS)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM findings")
        cur.execute("UPDATE events SET is_filtered_in=FALSE")
        for event, _skill in selected:
            cur.execute("UPDATE events SET type=%s, description=%s, raw_payload=%s, normalized=%s, is_filtered_in=TRUE WHERE id=%s",
                        (event.get("type"), event.get("description"), json.dumps(event.get("raw_kv") or {}),
                         json.dumps(event), event["db_id"]))
            queue.rpush(redis_client.QUEUE_FILTERED_EVENTS, json.dumps(event, default=str))
    conn.commit(); conn.close()
    print(json.dumps({"applied": True, "queued": len(selected)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
