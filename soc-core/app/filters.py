from __future__ import annotations
import os
from typing import Iterable
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
MIN_SEVERITY = os.getenv("FILTER_MIN_SEVERITY", "high").lower()
WAZUH_MIN_LEVEL_FOR_AI = int(os.getenv("WAZUH_MIN_LEVEL_FOR_AI", "7"))
ALWAYS_FORWARD_TYPES = {"credential_attack", "malware", "ransomware", "reconnaissance", "web_attack", "dos_attack",
                        "data_exfiltration", "phishing", "insider_risk", "zero_day"}
ACTIONABLE_MITRE = {"T1110", "T1550.002", "T1003", "T1003.001", "T1003.006", "T1558.003",
                    "T1486", "T1490", "T1046", "T1595", "T1190", "T1078", "T1098", "T1041",
                    "T1567", "T1071", "T1105", "T1203", "T1526", "T1580", "T1610", "T1613",
                    "T1082", "T1047", "T1057", "T1018", "T1087", "T1016", "T1049", "T1195",
                    "T1195.002", "T1498", "T1499", "T1566", "T1566.001", "T1566.002"}
def _severity_at_least(severity: str, threshold: str) -> bool: return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(threshold, 2)
def should_forward_to_ai(event: dict, ioc_hits: Iterable[dict] | None = None, mitre_matched: bool = False) -> bool:
    severity = event.get("severity", "low"); event_type = event.get("type", "")
    raw_kv = event.get("raw_kv", {}) or {}
    if event_type == "informational": return bool(ioc_hits and any(hit.get("malicious") for hit in ioc_hits))
    if raw_kv.get("security_signal"): return True
    if event_type in ALWAYS_FORWARD_TYPES: return True
    if _severity_at_least(severity, MIN_SEVERITY): return True
    if event.get("source") == "wazuh":
        wazuh_level = raw_kv.get("wazuh_rule_level")
        if wazuh_level is not None and int(wazuh_level) >= WAZUH_MIN_LEVEL_FOR_AI: return True
    if ioc_hits and any(hit.get("malicious") for hit in ioc_hits): return True
    if set(event.get("mitre_technique") or []) & ACTIONABLE_MITRE: return True
    if event_type == "vulnerability" and severity in ("high", "critical"): return True
    if event_type == "vulnerability" and raw_kv.get("is_unfixed"): return True
    if event_type == "fim_change":
        sensitive_markers = ("passwd", "shadow", "sshd_config", "system32\\drivers\\etc\\hosts")
        path = str(raw_kv.get("fim_path", "")).lower()
        if any(marker in path for marker in sensitive_markers): return True
        supply_chain_markers = ("node_modules", "site-packages", "vendor/", "package-lock", "gemfile.lock")
        if any(marker in path for marker in supply_chain_markers): return True
    if event.get("action") == "allowed" and "after multiple failures" in (event.get("description") or "").lower(): return True
    return False
