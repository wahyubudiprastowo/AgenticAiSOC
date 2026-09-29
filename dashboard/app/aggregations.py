from __future__ import annotations
import ipaddress, json, os, re
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
_SOURCE_CONTEXTUAL_CATEGORIES = {"vulnerability_management", "file_integrity", "supply_chain", "zero_day"}
_ACTION_CONTEXTUAL_CATEGORIES = {"vulnerability_management", "zero_day"}
_USER_REQUIRED_CATEGORIES = {"malware", "ransomware", "phishing", "credential_attack", "file_integrity",
                             "supply_chain", "insider_threat", "data_exfiltration", "cloud_native",
                             "container_kubernetes"}
_CVE_REQUIRED_CATEGORIES = {"vulnerability_management", "zero_day"}
_MANUAL_SOURCE_CATEGORIES = {"cloud_native", "container_kubernetes"}

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
    pending = list(values)
    while pending:
        value = pending.pop(0)
        if value is None: continue
        if isinstance(value, (list, tuple, set)):
            pending[0:0] = list(value); continue
        if isinstance(value, dict): continue
        text = str(value).strip()
        if text and text.lower() not in {"none", "null", "unknown", "n/a", "-"} and text not in seen:
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

def _first_deep(combined: dict, keys: set[str]):
    values = _unique(_deep_values(combined, keys))
    if not values: return None
    return values[0] if len(values) == 1 else values

def _is_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except (TypeError, ValueError):
        return False

def attack_detail(finding: dict, events: list[dict]) -> dict:
    """Build a stable analyst-facing view from a Hermes finding and its source events."""
    evidence = _json_object(finding.get("evidence")); ai_result = _json_object(finding.get("ai_result"))
    event_details, source_ips, source_identities, destinations, destination_ips = [], [], [], [], []
    actors, affected_users, synthetic_events = [], [], []
    cves, sources, event_types, actions = [], [], [], []
    indicators = finding.get("indicators") or evidence.get("indicators") or []
    normalized_indicators = []
    for indicator in indicators:
        if not isinstance(indicator, dict) or not indicator.get("ioc"): continue
        providers = indicator.get("provider_results") or indicator.get("providers") or []
        item = {"ioc": indicator.get("ioc"), "ioc_type": indicator.get("ioc_type") or "unknown",
                "malicious": bool(indicator.get("malicious")), "confidence": float(indicator.get("confidence") or 0),
                "enrichment_status": indicator.get("enrichment_status") or "unknown",
                "verdict_reason": indicator.get("verdict_reason"),
                "providers": [{"name": p.get("name"), "mode": p.get("mode"),
                    "malicious": bool(p.get("malicious")), "score": float(p.get("score") or 0),
                    "detail": p.get("detail")} for p in providers if isinstance(p, dict)]}
        normalized_indicators.append(item)
        if item["ioc_type"] == "cve": cves.append(str(item["ioc"]).upper())
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,8}", re.IGNORECASE)
    for event in events:
        normalized = _json_object(event.get("normalized")); raw_payload = _json_object(event.get("raw_payload"))
        raw_kv = _json_object(normalized.get("raw_kv")) or raw_payload
        raw_event = _json_object(normalized.get("raw"))
        combined = {"event": event, "normalized": normalized, "raw_payload": raw_payload, "raw_event": raw_event}
        source = str(event.get("source") or normalized.get("source") or "unknown")
        event_type = str(event.get("type") or normalized.get("type") or "unknown")
        agent = _json_object(raw_event.get("agent"))
        asset_ips = _unique([event.get("dst_ip"), normalized.get("dst_ip"), normalized.get("destination_ip"),
                             agent.get("ip"),
                             _deep_values(combined, {"dstip", "dst_ip", "destinationip", "destination_ip"})])
        src = _unique([event.get("src_ip"), normalized.get("src_ip"),
                       _deep_values(combined, {"srcip", "src_ip", "sourceip", "source_ip", "clientip", "client_ip",
                                                       "actoripaddress", "ipaddress", "senderip", "originatingip"})])
        src = [value for value in src if value not in asset_ips]
        identities = _unique(_deep_values(combined, {"p1sender", "p2sender", "sender", "senderaddress",
                                                      "from", "sourceusername", "actorupn", "actor_user"}))
        event_actors = _unique([event.get("user_name"), normalized.get("user_name"), raw_kv.get("user_id"),
                                _deep_values(combined, {"userid", "user_id", "username", "user_name", "userprincipalname"})])
        affected = _unique(_deep_values(combined, {"targetusername", "target_user_name", "targetuser",
                                                    "recipient", "recipients", "recipientaddress", "mailboxownerupn",
                                                    "affecteduser", "affected_user"}))
        if event_type in {"phishing", "malware", "mailbox_rule_change"}:
            if not affected:
                affected = _unique([event.get("user_name"), normalized.get("user_name")])
        elif event_type in {"oauth_consent", "data_exfiltration", "insider_risk", "file_download", "privilege_change"}:
            affected = _unique([affected, event.get("user_name"), normalized.get("user_name")])
        dst = _unique([normalized.get("destination"), raw_kv.get("object_id"), agent.get("name"),
                       _deep_values(combined, {"hostname", "devicename", "computer", "agent_name"})])
        asset_ips = _unique([asset_ips, [value for value in dst if _is_ip(value)]])
        dst = [value for value in dst if not _is_ip(value)]
        is_email_event = bool(source in {"m365_audit", "m365_defender_xdr"} or identities
                              or event_type in {"phishing", "mailbox_rule_change"})
        if affected and is_email_event and event_type in {"phishing", "malware", "mailbox_rule_change", "oauth_consent", "data_exfiltration"}:
            # For message/account activity, the affected account is the destination.
            # Fields such as DeviceName="ThreatIntel" describe the M365 workload,
            # not a destination host.
            dst = list(affected)
        raw_text = json.dumps(combined, default=str)
        event_cves = _unique(cve_pattern.findall(raw_text) + _deep_values(combined, {"cve", "vulnerability_id"}))
        event_actions = _unique([normalized.get("action"), raw_kv.get("action"),
                                 _deep_values(combined, {"action", "deliveryaction", "eventaction"})])
        if not event_actions:
            event_actions = _unique([raw_kv.get("fim_event"), raw_kv.get("operation"),
                                     _deep_values(combined, {"outcome", "resultstatus", "severityvalue"})])
        action = event_actions[0] if event_actions else None
        description = event.get("description") or normalized.get("description") or ""
        is_synthetic = bool(normalized.get("is_synthetic_test") or raw_kv.get("is_synthetic_test")
                            or raw_payload.get("is_synthetic_test") or "[COVERAGE_TEST" in str(description))
        technical = {
            "wazuh_rule_id": raw_kv.get("wazuh_rule_id"), "wazuh_rule_level": raw_kv.get("wazuh_rule_level"),
            "wazuh_rule_groups": raw_kv.get("wazuh_rule_groups") or [], "operation": raw_kv.get("operation"),
            "workload": raw_kv.get("workload"), "result_status": raw_kv.get("result_status"),
            "verdict": raw_kv.get("verdict"), "threats": raw_kv.get("threats") or [],
            "package": raw_kv.get("package"), "condition": raw_kv.get("condition"),
            "cve": raw_kv.get("cve"), "cvss_score": raw_kv.get("cvss_score"),
            "is_unfixed": raw_kv.get("is_unfixed"), "is_zero_day": raw_kv.get("is_zero_day"),
            "under_evaluation": raw_kv.get("under_evaluation"), "correlation_count": raw_kv.get("correlation_count"),
            "subject": _first_deep(combined, {"subject"}), "sender": _first_deep(combined, {"p1sender", "p2sender", "sender"}),
            "recipients": affected if event_type in {"phishing", "malware", "mailbox_rule_change"} else None,
            "sender_ip": _first_deep(combined, {"senderip", "originatingip"}),
            "delivery_action": _first_deep(combined, {"deliveryaction"}),
            "delivery_location": _first_deep(combined, {"latestdeliverylocation"}),
            "detection_method": _first_deep(combined, {"detectionmethod"}),
            "event_id": _first_deep(combined, {"eventid"}), "target_user": _first_deep(combined, {"targetusername"}),
            "source_port": _first_deep(combined, {"srcport", "sourceport", "ipport"}),
            "logon_type": _first_deep(combined, {"logontype"}), "failure_reason": _first_deep(combined, {"failurereason"}),
            "status_code": _first_deep(combined, {"status"}), "sub_status": _first_deep(combined, {"substatus"}),
            "process_name": _first_deep(combined, {"processname"}),
            "affected_asset_ip": asset_ips, "fim_path": raw_kv.get("fim_path"), "fim_event": raw_kv.get("fim_event"),
        }
        event_details.append({
            "id": str(event.get("id") or ""), "external_id": event.get("external_id"), "source": source,
            "type": event_type, "severity": event.get("severity") or normalized.get("severity") or "low",
            "timestamp": event.get("created_at") or normalized.get("time"), "description": description,
            "source_ips": src, "source_identities": identities, "destinations": dst, "destination_ips": asset_ips,
            "actors": event_actors, "affected_users": affected, "users": _unique([affected, event_actors]), "cves": event_cves,
            "is_synthetic_test": is_synthetic,
            "action": action, "mitre_techniques": _unique([event.get("mitre_technique") or [], normalized.get("mitre_technique") or []]),
            "technical": {k: v for k, v in technical.items() if v not in (None, "", [])},
            "raw": _redact({"raw_payload": raw_payload, "normalized": normalized}),
        })
        source_ips.extend(src); source_identities.extend(identities); destinations.extend(dst); destination_ips.extend(asset_ips)
        actors.extend(event_actors); affected_users.extend(affected); cves.extend(event_cves)
        sources.append(source); event_types.append(event_type); actions.extend(event_actions); synthetic_events.append(is_synthetic)
    mitre_ids = _unique([finding.get("mitre_technique") or [], *[e.get("mitre_techniques", []) for e in event_details]])
    unique_cves = _unique(cves)
    category = finding.get("category") or "unknown"
    cve_relevant_categories = {"vulnerability_management", "zero_day", "malware", "suspicious_network",
                               "sql_injection", "apt_activity"}
    cve_status = ("observed_in_source_event" if unique_cves else
                  "missing_from_vulnerability_source" if category in {"vulnerability_management", "zero_day"} else
                  "not_reported_by_source" if category in cve_relevant_categories else
                  "not_applicable_to_event_type")
    unique_sources = _unique(sources); unique_src = _unique(source_ips); unique_identities = _unique(source_identities)
    unique_dst = _unique(destinations); unique_dst_ips = _unique(destination_ips)
    unique_affected = _unique(affected_users); unique_actors = _unique(actors)
    unique_users = unique_affected or unique_actors
    email_context = bool(unique_affected and (unique_identities or "phishing" in event_types
                         or any(source in {"m365_audit", "m365_defender_xdr"} for source in unique_sources)))
    if category in {"vulnerability_management", "zero_day"}:
        path = {"kind": "exposure", "kind_label": "Vulnerability exposure", "title": "Attack path", "status": "contextual",
                "origin_label": "Detection source", "origin_values": unique_sources,
                "origin_context": "Vulnerability inventory evidence; an attacker source IP is not expected in this record.",
                "destination_label": "Affected asset", "destination_values": unique_dst,
                "destination_context": "Asset reported by the vulnerability source." if (unique_dst or unique_dst_ips) else "Affected asset was not provided by the source."}
    elif email_context:
        origin_values = _unique([unique_identities, unique_src])
        path = {"kind": "email", "kind_label": "Email/message flow", "title": "Attack path", "status": "complete" if origin_values and unique_affected else "partial",
                "origin_label": "Sender / source", "origin_values": origin_values,
                "origin_context": "Sender identities and source IP observed in the message evidence.",
                "destination_label": "Recipient / affected account", "destination_values": unique_affected,
                "destination_context": "Recipient accounts observed in the source event."}
    elif category in {"file_integrity", "supply_chain"} or "fim_change" in event_types:
        path = {"kind": "endpoint", "kind_label": "Endpoint integrity context", "title": "Attack path", "status": "contextual",
                "origin_label": "Endpoint telemetry", "origin_values": unique_sources,
                "origin_context": "This record reports a local file or registry change; a remote source IP may not exist.",
                "destination_label": "Affected asset", "destination_values": unique_dst,
                "destination_context": "Endpoint and object reported by the integrity sensor." if (unique_dst or unique_dst_ips) else "Affected asset was not provided by the source."}
    else:
        origin_values = _unique([unique_src, unique_identities])
        path = {"kind": "attack", "kind_label": "Network/account activity", "title": "Attack path", "status": "complete" if origin_values and (unique_dst or unique_dst_ips) else "partial",
                "origin_label": "Observed origin", "origin_values": origin_values,
                "origin_context": "Source IP or identity recorded by the sensor." if origin_values else "The source event did not report an attacker IP or identity.",
                "destination_label": "Destination / affected asset", "destination_values": unique_dst,
                "destination_context": "Target asset recorded by the sensor." if (unique_dst or unique_dst_ips) else "The source event did not report a target asset."}
    path.update({"source_ip_values": unique_src, "source_identity_values": unique_identities,
                 "destination_asset_values": unique_affected if path["kind"] == "email" else unique_dst,
                 "destination_ip_values": unique_dst_ips})
    field_status = {
        "source": "observed" if (unique_src or unique_identities) else "not_applicable" if path["kind"] in {"exposure", "endpoint"} else "not_reported",
        "action": "observed" if _unique(actions) else "not_applicable" if path["kind"] == "exposure" else "not_reported",
        "affected_user": "observed" if unique_affected else "not_applicable" if path["kind"] == "exposure" else "not_reported",
        "user": "observed" if unique_users else "not_applicable" if path["kind"] == "exposure" else "not_reported",
        "cve": cve_status,
    }
    cve_explanation = ("CVE identifier observed directly in the linked source event." if unique_cves else
                       "The vulnerability source did not provide a CVE identifier." if cve_status == "missing_from_vulnerability_source" else
                       "The source did not report a CVE for this attack." if cve_status == "not_reported_by_source" else
                       "A CVE is not applicable to this event type unless the source explicitly reports one.")
    is_synthetic = any(synthetic_events)
    if is_synthetic and unique_cves:
        cve_explanation += " This value came from a synthetic coverage-validation event and is not production vulnerability evidence."
    provenance = {"kind": "synthetic_validation" if is_synthetic else "production_telemetry",
                  "label": "Synthetic coverage validation" if is_synthetic else "Production telemetry",
                  "is_synthetic": is_synthetic,
                  "explanation": ("This finding was created by a coverage test. Blank attack-path fields reflect the test payload, not missing production telemetry."
                                  if is_synthetic else "This finding is linked to collected source telemetry.")}
    field_checks = {
        "attack_type": {"label": "Attack type", "status": "observed" if finding.get("threat_classification") else "missing"},
        "source_ip": {"label": "Source IP", "status": "observed" if unique_src else
                      "not_applicable" if category in _SOURCE_CONTEXTUAL_CATEGORIES else "missing"},
        "destination": {"label": "Destination asset or account", "status": "observed" if (unique_dst or unique_dst_ips or unique_affected) else "missing"},
        "action": {"label": "Action", "status": "observed" if _unique(actions) else
                   "not_applicable" if category in _ACTION_CONTEXTUAL_CATEGORIES else "missing"},
        "user": {"label": "User", "status": "observed" if unique_users else
                 "missing" if category in _USER_REQUIRED_CATEGORIES else "not_applicable"},
        "cve": {"label": "CVE", "status": "observed" if unique_cves else
                "missing" if category in _CVE_REQUIRED_CATEGORIES else "not_applicable"},
        "category": {"label": "Category", "status": "observed" if category != "unknown" else "missing"},
        "source_system": {"label": "Source system", "status": "observed" if unique_sources else "missing"},
        "linked_event": {"label": "Linked source event", "status": "observed" if event_details else "missing"},
    }
    applicable = [item for item in field_checks.values() if item["status"] != "not_applicable"]
    observed = [item["label"] for item in field_checks.values() if item["status"] == "observed"]
    missing = [item["label"] for item in field_checks.values() if item["status"] == "missing"]
    not_applicable = [item["label"] for item in field_checks.values() if item["status"] == "not_applicable"]
    completeness = round(sum(item["status"] == "observed" for item in applicable) / len(applicable) * 100) if applicable else 0
    if is_synthetic:
        maturity, maturity_label = "validation_only", "Validation only"
    elif not event_details:
        maturity, maturity_label = "unverified", "Unverified"
    elif missing:
        maturity, maturity_label = "partial_evidence", "Partial source evidence"
    else:
        maturity, maturity_label = "source_evidenced", "Source evidenced"
    limitations = []
    if is_synthetic:
        limitations.append("Synthetic coverage event: proves pipeline routing and field rendering, not source-sensor detection efficacy.")
    if missing:
        limitations.append("Required evidence not reported: " + ", ".join(missing) + ".")
    if len(event_details) == 1:
        limitations.append("Only one linked source event is available; the displayed path is event context, not a correlated multi-stage attack chain.")
    elif not event_details:
        limitations.append("No linked source event is available, so the finding cannot be independently traced to source telemetry.")
    if not normalized_indicators:
        limitations.append("No persisted IOC-enrichment result is attached to this finding.")
    if not mitre_ids:
        limitations.append("No MITRE ATT&CK technique is mapped to this finding.")
    if category in _MANUAL_SOURCE_CATEGORIES:
        limitations.append("This category currently uses manual API ingestion; a native cloud or Kubernetes collector is not connected.")
    if category == "reconnaissance" and any(technique in {"T1047", "T1082"} for technique in mitre_ids):
        limitations.append("Endpoint discovery telemetry is grouped under Reconnaissance; it may not represent external network scanning.")
    quality = {"maturity": maturity, "maturity_label": maturity_label, "completeness_pct": completeness,
               "path_status": path.get("status") or "partial", "linked_event_count": len(event_details),
               "field_checks": field_checks, "observed_fields": observed, "missing_fields": missing,
               "not_applicable_fields": not_applicable, "limitations": limitations}
    return {
        "finding": {"id": str(finding.get("id") or ""), "classification": finding.get("threat_classification") or "Unknown",
                    "category": finding.get("category") or "unknown", "severity": finding.get("severity") or "low",
                    "confidence": float(finding.get("confidence") or 0), "status": finding.get("status") or "open",
                    "created_time": finding.get("created_time"), "recommendation": finding.get("recommendation") or "",
                    "analysis_status": finding.get("analysis_status"), "detection_rule": finding.get("detection_rule"),
                    "detection_source": finding.get("detection_source"), "updated_time": finding.get("updated_time")},
        "attack": {"sources": unique_sources, "source_ips": unique_src, "source_identities": unique_identities,
                   "destinations": unique_dst, "destination_ips": unique_dst_ips, "actors": unique_actors, "affected_users": unique_affected,
                   "users": unique_users, "event_types": _unique(event_types), "actions": _unique(actions),
                   "cves": unique_cves, "cve_status": cve_status, "cve_explanation": cve_explanation,
                   "field_status": field_status, "path": path, "indicators": normalized_indicators},
        "provenance": provenance,
        "quality": quality,
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
