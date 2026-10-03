from __future__ import annotations
import hashlib, json, logging, os, random, re, uuid
from datetime import datetime, timedelta, timezone
import httpx
logger = logging.getLogger("soc-core.wazuh")
WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin"); WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "changeme")
WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"
WAZUH_MOCK_MODE = os.getenv("WAZUH_MOCK_MODE", "true").lower() == "true"
WAZUH_ALERTS_INDEX = os.getenv("WAZUH_ALERTS_INDEX", "wazuh-alerts-*")
WAZUH_VULN_INDEX = os.getenv("WAZUH_VULN_INDEX", "wazuh-states-vulnerabilities-*")
WAZUH_FIM_RULE_GROUP = os.getenv("WAZUH_FIM_RULE_GROUP", "syscheck")
WAZUH_VULN_RULE_GROUP = os.getenv("WAZUH_VULN_RULE_GROUP", "vulnerability-detector")
WAZUH_CAPTURE_ALL_LEVELS = os.getenv("WAZUH_CAPTURE_ALL_LEVELS", "true").lower() == "true"
WAZUH_MAX_PAGES = max(1, int(os.getenv("WAZUH_MAX_PAGES", "25")))
WAZUH_CURSOR_OVERLAP_SECONDS = max(0, int(os.getenv("WAZUH_CURSOR_OVERLAP_SECONDS", "120")))
_auth = (WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD)
def _client(): return httpx.Client(verify=WAZUH_VERIFY_SSL, timeout=20, auth=_auth)
_MOCK_RULE_BANK = [
    {"rule.id": "5712", "rule.description": "SSHD brute force attempt", "rule.level": 10, "rule.mitre.id": ["T1110"], "rule.groups": ["authentication_failed"]},
    {"rule.id": "100002", "rule.description": "Multiple authentication failures followed by success", "rule.level": 12, "rule.mitre.id": ["T1110", "T1078"], "rule.groups": ["authentication_success"]},
    {"rule.id": "554", "rule.description": "File added to the system (possible malware drop)", "rule.level": 9, "rule.mitre.id": ["T1105"], "rule.groups": ["syscheck"]},
    {"rule.id": "100050", "rule.description": "Windows Defender detected ransomware behaviour", "rule.level": 15, "rule.mitre.id": ["T1486"], "rule.groups": ["windows"]},
    {"rule.id": "23506", "rule.description": "Low severity informational event", "rule.level": 3, "rule.mitre.id": [], "rule.groups": ["pci_dss_10.6.1"]},
]
def _mock_alerts(min_level, count=5):
    alerts = []
    for _ in range(count):
        rule = random.choice(_MOCK_RULE_BANK)
        if rule["rule.level"] < min_level: continue
        alerts.append({"_id": uuid.uuid4().hex, "_source": {"@timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": {"name": random.choice(["server01", "server02", "dc01"]), "id": "001"},
            "rule": {"id": rule["rule.id"], "description": rule["rule.description"], "level": rule["rule.level"],
                     "groups": rule["rule.groups"], "mitre": {"id": rule["rule.mitre.id"]}},
            "data": {"srcip": f"185.220.101.{random.randint(2, 250)}"}}})
    return alerts
def _mock_fim_events(count=2):
    paths = ["/etc/passwd", "/etc/shadow", "C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts"]
    return [{"_id": uuid.uuid4().hex, "_source": {"@timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": {"name": random.choice(["server01", "dc01"])},
            "rule": {"id": "550", "description": "Integrity checksum changed", "level": 7, "groups": ["syscheck"]},
            "syscheck": {"path": random.choice(paths), "event": "modified"}}} for _ in range(count)]
def _mock_vulnerabilities(count=2):
    cves = ["CVE-2024-3400", "CVE-2023-4863", "CVE-2025-0001"]
    return [{"_id": uuid.uuid4().hex, "_source": {"@timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": {"name": random.choice(["server01", "server02"])},
            "vulnerability": {"cve": random.choice(cves), "severity": random.choice(["High", "Critical", "Medium"]),
                               "condition": "Package unfixed" if i == 0 else "Package patched",
                               "package": {"name": "openssl", "version": "1.1.1"}}}} for i in range(count)]


def _parse_timestamp(value) -> datetime | None:
    if not value: return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _cursor_start(cursor: dict | None, fallback: datetime) -> datetime:
    parsed = _parse_timestamp((cursor or {}).get("timestamp"))
    return parsed - timedelta(seconds=WAZUH_CURSOR_OVERLAP_SECONDS) if parsed else fallback


def document_cursor(document: dict, *timestamp_paths: str) -> dict | None:
    source = document.get("_source", document)
    timestamp = _nested(source, *timestamp_paths)
    parsed = _parse_timestamp(timestamp)
    if parsed is None: return None
    return {"timestamp": parsed.isoformat(), "document_id": str(document.get("_id") or "")}


def _paged_search(url: str, query: dict, timestamp_field: str, size: int) -> list[dict]:
    hits: list[dict] = []
    with _client() as client:
        for page in range(WAZUH_MAX_PAGES):
            body = {**query, "sort": [{timestamp_field: {"order": "asc"}}],
                    "size": size, "from": page * size, "track_total_hits": False}
            response = client.post(url, json=body); response.raise_for_status()
            page_hits = response.json().get("hits", {}).get("hits", [])
            if not isinstance(page_hits, list): raise ValueError("Wazuh hits must be a list")
            hits.extend(page_hits)
            if len(page_hits) < size: break
    return hits


def fetch_recent_alerts(min_level=None, lookback_minutes=10, size=200, cursor: dict | None = None):
    effective_min_level = 1 if WAZUH_CAPTURE_ALL_LEVELS else (min_level or 7)
    if WAZUH_MOCK_MODE: return _mock_alerts(effective_min_level)
    end_time = datetime.now(timezone.utc)
    since = _cursor_start(cursor, end_time - timedelta(minutes=lookback_minutes)).isoformat()
    relevance = [{"range": {"rule.level": {"gte": effective_min_level}}}]
    if not WAZUH_CAPTURE_ALL_LEVELS:
        relevance.extend([{"exists": {"field": "rule.mitre.id"}}, {"term": {"rule.groups": "attack"}}])
    query = {"query": {"bool": {
                "must": [{"range": {"@timestamp": {"gte": since, "lte": end_time.isoformat()}}}],
                "should": relevance,
                "minimum_should_match": 1,
                "must_not": [{"terms": {"rule.groups": [WAZUH_FIM_RULE_GROUP, WAZUH_VULN_RULE_GROUP, "office365"]}}],
            }}}
    url = f"{WAZUH_INDEXER_URL.rstrip('/')}/{WAZUH_ALERTS_INDEX}/_search"
    try:
        return _paged_search(url, query, "@timestamp", size)
    except Exception: logger.exception("Failed to query Wazuh alerts"); return []
def fetch_recent_fim_events(lookback_minutes=15, size=100, cursor: dict | None = None):
    if WAZUH_MOCK_MODE: return _mock_fim_events()
    end_time = datetime.now(timezone.utc)
    since = _cursor_start(cursor, end_time - timedelta(minutes=lookback_minutes)).isoformat()
    query = {"query": {"bool": {"must": [{"term": {"rule.groups": WAZUH_FIM_RULE_GROUP}},
             {"range": {"@timestamp": {"gte": since, "lte": end_time.isoformat()}}}]}}}
    url = f"{WAZUH_INDEXER_URL.rstrip('/')}/{WAZUH_ALERTS_INDEX}/_search"
    try:
        return _paged_search(url, query, "@timestamp", size)
    except Exception: logger.exception("Failed to query Wazuh FIM events"); return []
def fetch_recent_vulnerabilities(lookback_hours=24, size=200, cursor: dict | None = None):
    if WAZUH_MOCK_MODE: return _mock_vulnerabilities()
    end_time = datetime.now(timezone.utc)
    since = _cursor_start(cursor, end_time - timedelta(hours=lookback_hours)).isoformat()
    query_modern = {"query": {"range": {"vulnerability.detected_at": {"gte": since, "lte": end_time.isoformat()}}}}
    url_modern = f"{WAZUH_INDEXER_URL.rstrip('/')}/{WAZUH_VULN_INDEX}/_search"
    try:
        hits = _paged_search(url_modern, query_modern, "vulnerability.detected_at", size)
        if hits: return hits
    except Exception: logger.warning("Modern Wazuh vulnerability query failed; trying legacy index")
    query_legacy = {"query": {"bool": {"must": [{"term": {"rule.groups": WAZUH_VULN_RULE_GROUP}},
                    {"range": {"@timestamp": {"gte": since, "lte": end_time.isoformat()}}}]}}}
    url_legacy = f"{WAZUH_INDEXER_URL.rstrip('/')}/{WAZUH_ALERTS_INDEX}/_search"
    try:
        return _paged_search(url_legacy, query_legacy, "@timestamp", size)
    except Exception: logger.exception("Failed to query Wazuh vulnerabilities"); return []


def _stable_id(prefix: str, document: dict) -> str:
    doc_id = str(document.get("_id") or "")
    if not doc_id:
        payload = json.dumps(document.get("_source", document), sort_keys=True, separators=(",", ":"), default=str)
        doc_id = hashlib.sha256(payload.encode()).hexdigest()
    return f"evt-wazuh-{hashlib.sha256((prefix + ':' + doc_id).encode()).hexdigest()[:24]}"


def _document_hash(document: dict) -> str:
    payload = json.dumps(document.get("_source", document), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()

def _nested(document: dict, *paths: str):
    for path in paths:
        value = document
        for key in path.split("."):
            if not isinstance(value, dict): value = None; break
            value = value.get(key)
        if value not in (None, "", "-"): return value
    return None


def _infer_alert_type(description: str, groups: list[str], mitre: list[str]) -> str:
    text = (description or "").lower()
    group_set = {str(g).strip().lower() for g in groups}
    group_text = " ".join(group_set)
    techniques = set(mitre or [])
    if techniques & {"T1486", "T1490"} or "ransom" in text:
        return "ransomware"
    if techniques & {"T1110"} or re.search(r"brute[ -]?force|authentication fail|failed password|invalid user", text):
        return "credential_attack"
    if techniques & {"T1498", "T1499"} or re.search(r"\bddos\b|denial[ -]of[ -]service|flood", text):
        return "dos_attack"
    if techniques & {"T1046", "T1595"} or re.search(r"port scan|network scan|nmap|port sweep", text):
        return "reconnaissance"
    if "sql injection" in text or "web attack" in text or "web_attack" in group_text:
        return "web_attack"
    if re.search(r"malware|trojan|virus|rootkit", text):
        return "malware"
    if "syscheck" in group_text:
        return "fim_change"
    if re.search(r"attack (dropped|detected|blocked)|intrusion|exploit", text) or group_set & {"ids", "ips", "attack"}:
        return "network_attack"
    if re.search(r"app (passed|blocked) by firewall|logon success|session opened|authentication success", text):
        return "informational"
    return "security_alert"
def wazuh_alert_to_normalized(alert):
    src = alert.get("_source", alert); rule = src.get("rule", {}); level = rule.get("level", 0)
    groups = rule.get("groups", []) or []; mitre = rule.get("mitre", {}).get("id", []) or []
    description = rule.get("description") or "Wazuh alert"
    severity = "critical" if level >= 14 else "high" if level >= 10 else "medium" if level >= 7 else "low"
    alert_type = _infer_alert_type(description, groups, mitre)
    src_ip = _nested(src, "data.srcip", "data.src_ip", "data.win.eventdata.ipAddress",
                     "data.win.eventdata.sourceNetworkAddress", "win.eventdata.ipAddress", "source.ip")
    user_name = _nested(src, "data.dstuser", "data.srcuser", "data.user",
                        "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName",
                        "win.eventdata.targetUserName", "user.name")
    action = _nested(src, "data.action", "event.action")
    return {"id": _stable_id("alert", alert), "source": "wazuh", "type": alert_type,
            "severity": severity, "src_ip": src_ip, "destination": src.get("agent", {}).get("name"),
            "user_name": user_name, "action": action,
            "description": description, "mitre_technique": mitre,
            "time": src.get("@timestamp", datetime.now(timezone.utc).isoformat()), "raw": src, "raw_hash": _document_hash(alert),
            "raw_kv": {"wazuh_rule_id": rule.get("id"), "wazuh_rule_level": level, "wazuh_rule_groups": groups,
                       "source_provenance": "wazuh_indexer",
                       "security_signal": level >= 7 or alert_type in {"credential_attack", "malware", "ransomware",
                           "network_attack", "reconnaissance", "web_attack", "dos_attack"}}}
def wazuh_fim_to_normalized(event):
    src = event.get("_source", event); rule = src.get("rule", {}); syscheck = src.get("syscheck", {}); level = rule.get("level", 7)
    severity = "critical" if level >= 14 else "high" if level >= 10 else "medium" if level >= 7 else "low"
    path = syscheck.get("path", "unknown")
    return {"id": _stable_id("fim", event), "source": "wazuh", "type": "fim_change", "severity": severity,
            "destination": src.get("agent", {}).get("name"), "description": f"FIM: {syscheck.get('event', 'change')} on {path}",
            "mitre_technique": rule.get("mitre", {}).get("id", []), "time": src.get("@timestamp", datetime.now(timezone.utc).isoformat()),
            "raw": src, "raw_hash": _document_hash(event), "raw_kv": {"fim_path": path, "fim_event": syscheck.get("event"),
            "source_provenance": "wazuh_indexer",
            "wazuh_rule_id": rule.get("id"), "wazuh_rule_level": level, "wazuh_rule_groups": rule.get("groups", []) or []}}
def wazuh_vulnerability_to_normalized(vuln):
    src = vuln.get("_source", vuln); v = src.get("vulnerability", {}); sev = (v.get("severity") or "medium").lower()
    severity = "critical" if sev == "critical" else "high" if sev == "high" else "medium" if sev == "medium" else "low"
    cve = v.get("id") or v.get("cve") or "UNKNOWN-CVE"
    package = src.get("package") or v.get("package") or {}
    scanner = v.get("scanner") or {}
    condition = str(scanner.get("condition") or v.get("condition") or "")
    condition_lower = condition.lower()
    is_unfixed = any(marker in condition_lower for marker in ("unfixed", "not fixed", "no fix", "fix unavailable"))
    is_zero_day = bool(v.get("zero_day") or v.get("is_zero_day")) and is_unfixed
    description = f"{cve} affecting {package.get('name', 'unknown package')} {package.get('version', '')}".strip()
    if is_unfixed:
        description += " (vendor fix unavailable)"
        severity = "critical" if severity in ("high", "critical") else "high"
    return {"id": _stable_id("vulnerability", vuln), "source": "wazuh", "type": "zero_day" if is_zero_day else "vulnerability", "severity": severity,
            "destination": src.get("agent", {}).get("name"), "description": description, "mitre_technique": [],
            "time": v.get("detected_at") or src.get("@timestamp", datetime.now(timezone.utc).isoformat()), "raw": src,
            "raw_hash": _document_hash(vuln),
            "raw_kv": {"cve": cve, "package": package, "condition": condition, "is_unfixed": is_unfixed,
                       "source_provenance": "wazuh_indexer",
                       "is_zero_day": is_zero_day, "under_evaluation": bool(v.get("under_evaluation")),
                       "cvss_score": (v.get("score") or {}).get("base")}}
