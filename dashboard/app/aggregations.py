from __future__ import annotations
import json, os, re
from collections import Counter
from datetime import datetime, timezone
MITRE_NAMES = {
    "T1110": "Brute Force", "T1078": "Valid Accounts", "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer", "T1204": "User Execution", "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment", "T1098.001": "Additional Cloud Credentials",
    "T1486": "Data Encrypted for Impact", "T1490": "Inhibit System Recovery",
    "T1046": "Network Service Discovery", "T1595": "Active Scanning",
    "T1190": "Exploit Public-Facing Application", "T1059": "Command and Scripting Interpreter",
    "T1071": "Application Layer Protocol", "T1027": "Obfuscated Files or Information",
    "T1082": "System Information Discovery", "T1053": "Scheduled Task/Job",
    "T1547": "Boot or Logon Autostart Execution", "T1195": "Supply Chain Compromise",
    "T1195.002": "Compromise Software Supply Chain", "T1498": "Network Denial of Service",
    "T1499": "Endpoint Denial of Service", "T1005": "Data from Local System",
    "T1041": "Exfiltration Over C2 Channel", "T1567": "Exfiltration Over Web Service",
    "T1203": "Exploitation for Client Execution", "T1526": "Cloud Service Discovery",
    "T1580": "Cloud Infrastructure Discovery", "T1610": "Deploy Container", "T1613": "Container and Resource Discovery",
    "T1550.002": "Pass the Hash", "T1003": "OS Credential Dumping", "T1003.001": "LSASS Memory",
    "T1003.006": "DCSync", "T1558.003": "Kerberoasting", "T1047": "Windows Management Instrumentation",
    "T1057": "Process Discovery", "T1018": "Remote System Discovery", "T1087": "Account Discovery",
    "T1016": "System Network Configuration Discovery", "T1049": "System Network Connections Discovery",
}
THREAT_TYPE_TAXONOMY = ["Malware", "Ransomware", "Phishing", "Credential Theft", "Network Intrusion",
    "Reconnaissance", "Vulnerability", "File Integrity", "Supply Chain", "DDoS", "SQL Injection",
    "Insider Threat", "Data Exfiltration", "APT Activity", "Zero-Day", "Cloud-Native Attack", "Container/Kubernetes"]
_CATEGORY_TO_THREAT_TYPE = {"malware": "Malware", "ransomware": "Ransomware", "phishing": "Phishing",
    "credential_attack": "Credential Theft", "suspicious_network": "Network Intrusion", "reconnaissance": "Reconnaissance",
    "vulnerability_management": "Vulnerability", "file_integrity": "File Integrity", "supply_chain": "Supply Chain",
    "ddos": "DDoS", "sql_injection": "SQL Injection", "insider_threat": "Insider Threat", "data_exfiltration": "Data Exfiltration",
    "apt_activity": "APT Activity", "zero_day": "Zero-Day", "cloud_native": "Cloud-Native Attack", "container_kubernetes": "Container/Kubernetes"}
_MANUAL_INGEST_ONLY_CATEGORIES = {"Cloud-Native Attack", "Container/Kubernetes"}
_SEVERITY_ORDER = ["critical", "high", "medium", "low"]
_SEVERITY_COLOR = {"critical": "#f85149", "high": "#ff8a3d", "medium": "#e3b341", "low": "#3fb950"}
_SENSITIVE_KEY_PARTS = ("password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "cookie", "credential")

def _json_object(value) -> dict:
    if isinstance(value, dict): return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError): return {}
    return {}

def _redact(value):
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if any(part in str(k).lower() for part in _SENSITIVE_KEY_PARTS) else _redact(v)
                for k, v in value.items()}
    if isinstance(value, list): return [_redact(item) for item in value]
    return value

def _unique(values) -> list[str]:
    seen, result = set(), []
    for value in values:
        if value is None: continue
        if isinstance(value, (list, tuple, set)):
            candidates = value
        else:
            candidates = [value]
        for candidate in candidates:
            text = str(candidate).strip()
            if text and text.lower() not in {"none", "null", "unknown", "n/a"} and text not in seen:
                seen.add(text); result.append(text)
    return result

def _deep_values(value, wanted_keys: set[str]) -> list:
    found = []
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower() in wanted_keys: found.append(nested)
            found.extend(_deep_values(nested, wanted_keys))
    elif isinstance(value, list):
        for nested in value: found.extend(_deep_values(nested, wanted_keys))
    return found

def attack_detail(finding: dict, events: list[dict]) -> dict:
    """Build a stable analyst-facing view from a Hermes finding and its source events."""
    evidence = _json_object(finding.get("evidence")); ai_result = _json_object(finding.get("ai_result"))
    event_details, source_ips, destinations, users, cves, sources, event_types, actions = [], [], [], [], [], [], [], []
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,8}", re.IGNORECASE)
    for event in events:
        normalized = _json_object(event.get("normalized")); raw_payload = _json_object(event.get("raw_payload"))
        raw_kv = _json_object(normalized.get("raw_kv")) or raw_payload
        raw_event = _json_object(normalized.get("raw"))
        combined = {"event": event, "normalized": normalized, "raw_payload": raw_payload, "raw_event": raw_event}
        src = _unique([event.get("src_ip"), normalized.get("src_ip"),
                       _deep_values(combined, {"srcip", "src_ip", "sourceip", "source_ip", "clientip", "actoripaddress", "ipaddress"})])
        dst = _unique([event.get("dst_ip"), normalized.get("destination"), normalized.get("dst_ip"),
                       raw_kv.get("object_id"), _deep_values(combined, {"dstip", "dst_ip", "destinationip", "destination_ip", "hostname", "devicename", "computer", "agent_name"})])
        event_users = _unique([event.get("user_name"), normalized.get("user_name"), raw_kv.get("user_id"),
                               _deep_values(combined, {"userid", "user_id", "username", "user_name", "userprincipalname"})])
        raw_text = json.dumps(combined, default=str)
        event_cves = _unique(cve_pattern.findall(raw_text) + _deep_values(combined, {"cve", "vulnerability_id"}))
        source = str(event.get("source") or normalized.get("source") or "unknown")
        event_type = str(event.get("type") or normalized.get("type") or "unknown")
        action = normalized.get("action") or raw_kv.get("action") or next(iter(_deep_values(combined, {"action"})), None)
        technical = {
            "wazuh_rule_id": raw_kv.get("wazuh_rule_id"), "wazuh_rule_level": raw_kv.get("wazuh_rule_level"),
            "wazuh_rule_groups": raw_kv.get("wazuh_rule_groups") or [], "operation": raw_kv.get("operation"),
            "workload": raw_kv.get("workload"), "result_status": raw_kv.get("result_status"),
            "verdict": raw_kv.get("verdict"), "threats": raw_kv.get("threats") or [],
            "package": raw_kv.get("package"), "condition": raw_kv.get("condition"),
            "correlation_count": raw_kv.get("correlation_count"),
        }
        event_details.append({
            "id": str(event.get("id") or ""), "external_id": event.get("external_id"), "source": source,
            "type": event_type, "severity": event.get("severity") or normalized.get("severity") or "low",
            "timestamp": event.get("created_at") or normalized.get("time"), "description": event.get("description") or normalized.get("description"),
            "source_ips": src, "destinations": dst, "users": event_users, "cves": event_cves,
            "action": action, "mitre_techniques": _unique([event.get("mitre_technique") or [], normalized.get("mitre_technique") or []]),
            "technical": {k: v for k, v in technical.items() if v not in (None, "", [])},
            "raw": _redact({"raw_payload": raw_payload, "normalized": normalized}),
        })
        source_ips.extend(src); destinations.extend(dst); users.extend(event_users); cves.extend(event_cves)
        sources.append(source); event_types.append(event_type); actions.append(action)
    mitre_ids = _unique([finding.get("mitre_technique") or [], *[e.get("mitre_techniques", []) for e in event_details]])
    return {
        "finding": {"id": str(finding.get("id") or ""), "classification": finding.get("threat_classification") or "Unknown",
                    "category": finding.get("category") or "unknown", "severity": finding.get("severity") or "low",
                    "confidence": float(finding.get("confidence") or 0), "status": finding.get("status") or "open",
                    "created_time": finding.get("created_time"), "recommendation": finding.get("recommendation") or ""},
        "attack": {"sources": _unique(sources), "source_ips": _unique(source_ips), "destinations": _unique(destinations),
                   "users": _unique(users), "event_types": _unique(event_types), "actions": _unique(actions), "cves": _unique(cves)},
        "mitre": [{"id": technique, "name": MITRE_NAMES.get(technique, technique)} for technique in mitre_ids],
        "evidence": evidence.get("evidence", []) if isinstance(evidence.get("evidence", []), list) else [],
        "evidence_summary": evidence.get("finding"), "ai_result": _redact(ai_result), "events": event_details,
    }
def _finding_threat_summary(finding: dict) -> dict:
    ai_result = finding.get("ai_result") or {}
    if isinstance(ai_result, str):
        import json
        try: ai_result = json.loads(ai_result)
        except Exception: ai_result = {}
    return ai_result.get("threat_summary", {}) or {}
def threat_intel_classification(findings: list[dict]) -> dict:
    if not findings: return {"bucket": "C1", "credibility": 0.0, "authority": 0.0, "relevant": 0.0, "sample_size": 0, "dominant_type": "Unknown"}
    credibilities, authorities, relevances, buckets, types = [], [], [], [], []
    for f in findings:
        summary = _finding_threat_summary(f)
        if not summary: continue
        credibilities.append(summary.get("credibility", 0.0)); authorities.append(summary.get("authority", 0.0))
        relevances.append(summary.get("relevant", 0.0)); buckets.append(summary.get("threat_classification_bucket", "C1"))
        types.append(summary.get("type", f.get("threat_classification", "Unknown")))
    if not credibilities: return {"bucket": "C1", "credibility": 0.0, "authority": 0.0, "relevant": 0.0, "sample_size": 0, "dominant_type": "Unknown"}
    avg = lambda lst: round(sum(lst) / len(lst), 2) if lst else 0.0
    return {"bucket": Counter(buckets).most_common(1)[0][0], "credibility": avg(credibilities), "authority": avg(authorities),
            "relevant": avg(relevances), "sample_size": len(credibilities), "dominant_type": Counter(types).most_common(1)[0][0]}
def threat_type_distribution(findings: list[dict]) -> list[dict]:
    counts = Counter()
    for f in findings:
        label = _CATEGORY_TO_THREAT_TYPE.get(f.get("category") or "")
        if label: counts[label] += 1
    max_count = max(counts.values(), default=0); result = []
    for label in THREAT_TYPE_TAXONOMY:
        c = counts.get(label, 0); pct = round((c / max_count) * 100) if max_count else 0
        result.append({"label": label, "count": c, "pct": pct, "instrumented": label in _CATEGORY_TO_THREAT_TYPE.values(),
                        "manual_ingest_only": label in _MANUAL_INGEST_ONLY_CATEGORIES})
    return result
def threat_type_distribution_counts(categories: list[dict]) -> list[dict]:
    counts = Counter()
    for item in categories:
        label = _CATEGORY_TO_THREAT_TYPE.get(item.get("category") or "")
        if label: counts[label] += int(item.get("total") or 0)
    max_count = max(counts.values(), default=0)
    return [{"label": label, "count": counts.get(label, 0),
             "pct": round((counts.get(label, 0) / max_count) * 100) if max_count else 0,
             "instrumented": label in _CATEGORY_TO_THREAT_TYPE.values(),
             "manual_ingest_only": label in _MANUAL_INGEST_ONLY_CATEGORIES}
            for label in THREAT_TYPE_TAXONOMY]
def mitre_from_counts(items: list[dict]) -> list[dict]:
    return [{"id": item.get("id"), "name": MITRE_NAMES.get(item.get("id"), item.get("id")),
             "count": int(item.get("total") or 0)} for item in items if item.get("id")]
def mitre_frequency(findings: list[dict], top_n: int = 12) -> list[dict]:
    counts = Counter()
    for f in findings:
        for tech in (f.get("mitre_technique") or []): counts[tech] += 1
    return [{"id": t, "name": MITRE_NAMES.get(t, t), "count": c} for t, c in counts.most_common(top_n)]
def severity_distribution(events: list[dict]) -> list[dict]:
    counts = Counter(e.get("severity", "low") for e in events); total = sum(counts.values()) or 1
    return [{"severity": s, "count": counts.get(s, 0), "pct": round((counts.get(s, 0) / total) * 100), "color": _SEVERITY_COLOR[s]} for s in _SEVERITY_ORDER]
def severity_distribution_counts(items: list[dict]) -> list[dict]:
    counts = {str(item.get("severity") or "unknown"): int(item.get("total") or 0) for item in items}
    total = sum(counts.values()) or 1
    return [{"severity": severity, "count": counts.get(severity, 0),
             "pct": round(counts.get(severity, 0) / total * 100), "color": _SEVERITY_COLOR[severity]}
            for severity in _SEVERITY_ORDER]
def hourly_timeline(buckets: list[dict]) -> list[dict]:
    if not buckets: return []
    max_total = max((b.get("total", 0) for b in buckets), default=0) or 1; result = []
    for b in buckets:
        ts = b.get("bucket", "")
        try: hour_label = datetime.fromisoformat(ts).strftime("%H:%M")
        except Exception: hour_label = ts[-8:-3] if len(ts) >= 8 else ts
        result.append({"label": hour_label, "total": b.get("total", 0), "forwarded": b.get("forwarded", 0),
            "total_height_pct": round((b.get("total", 0) / max_total) * 100),
            "forwarded_height_pct": round((b.get("forwarded", 0) / max_total) * 100) if max_total else 0})
    return result
def source_breakdown(events_by_source: dict) -> list[dict]:
    total = sum(events_by_source.values()) or 1
    return [{"source": s, "count": c, "pct": round((c / total) * 100)} for s, c in sorted(events_by_source.items(), key=lambda kv: -kv[1])]
def source_breakdown_counts(items: list[dict]) -> list[dict]:
    total = sum(int(item.get("total") or 0) for item in items) or 1
    return [{"source": item.get("source") or "unknown", "count": int(item.get("total") or 0),
             "pct": round(int(item.get("total") or 0) / total * 100)} for item in items]
def cloud_application_coverage(m365_stats: dict | None, threat_intel_providers: dict | None) -> dict:
    m365_stats = m365_stats or {}; threat_intel_providers = threat_intel_providers or {}
    m365_enabled = m365_stats.get("m365_enabled", False); m365_has_data = (m365_stats.get("m365_records", 0) or 0) > 0
    defender_enabled = m365_stats.get("defender_xdr_enabled", False)
    def _status(enabled, has_data):
        if not enabled: return "not_configured"
        return "active" if has_data else "configured"
    live_intel = sum(1 for p in threat_intel_providers.values() if isinstance(p, dict) and p.get("mode") in ("live", "mock"))
    cloud = [{"name": "Azure", "status": "not_configured", "detail": "Manual ingest only via /events/ingest"},
             {"name": "AWS", "status": "not_configured", "detail": "Manual ingest only via /events/ingest"},
             {"name": "M365", "status": _status(m365_enabled, m365_has_data), "detail": f"{m365_stats.get('m365_records', 0)} audit records ingested" if m365_enabled else "Disabled"}]
    applications = [{"name": "SaaS", "status": _status(m365_enabled, m365_has_data), "detail": "via M365 Audit + Defender XDR"},
                     {"name": "API", "status": "active" if live_intel else "not_configured", "detail": f"{live_intel} threat-intel provider(s)"},
                     {"name": "DB Monitoring", "status": "not_configured", "detail": "Application DB audit logs not connected; platform PostgreSQL is monitored separately"}]
    return {"cloud": cloud, "applications": applications, "defender_xdr_enabled": defender_enabled}
def top_malicious_iocs(findings: list[dict], limit: int = 8) -> list[dict]:
    seen = {}
    for f in findings:
        evidence = f.get("evidence") or {}
        if isinstance(evidence, str):
            import json
            try: evidence = json.loads(evidence)
            except Exception: evidence = {}
        for line in evidence.get("evidence", []) if isinstance(evidence, dict) else []:
            if line.startswith("IOC-") and "malicious" in line.lower() and "not flagged" not in line.lower():
                ioc_part = line.split(":")[0].replace("IOC-", "")
                if ioc_part not in seen: seen[ioc_part] = {"ioc": ioc_part, "classification": f.get("threat_classification", "Unknown"), "severity": f.get("severity", "low")}
    return list(seen.values())[:limit]
def apt_attributions(findings: list[dict], limit: int = 5) -> list[dict]:
    seen = []
    for f in findings:
        if f.get("category") != "apt_activity": continue
        evidence = f.get("evidence") or {}
        if isinstance(evidence, str):
            import json
            try: evidence = json.loads(evidence)
            except Exception: evidence = {}
        for line in evidence.get("evidence", []) if isinstance(evidence, dict) else []:
            if line.startswith("APT-ATTRIBUTION:"):
                seen.append({"attribution": line.replace("APT-ATTRIBUTION:", "").strip(), "confidence": f.get("confidence", 0.0), "severity": f.get("severity", "low")})
    return seen[:limit]
def compute_kpis(soc_stats: dict, findings_all: list[dict]) -> dict:
    high_critical = sum(1 for f in findings_all if f.get("severity") in ("high", "critical"))
    avg_confidence = round(sum(f.get("confidence", 0) for f in findings_all) / len(findings_all), 2) if findings_all else 0.0
    total_events = soc_stats.get("total_events", 0); forwarded = soc_stats.get("filtered_in_events", 0)
    compression_pct = round((1 - (forwarded / total_events)) * 100, 1) if total_events else 0.0
    return {"total_events": total_events, "forwarded_events": forwarded, "total_findings": soc_stats.get("total_findings", len(findings_all)),
            "high_critical_findings": high_critical, "avg_confidence": avg_confidence, "compression_pct": compression_pct}
