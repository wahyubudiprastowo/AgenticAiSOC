from __future__ import annotations

import re
from typing import Optional

from shared.taxonomy import (
    category_display,
    category_family,
    normalize_subtype,
    subtype_display,
    subtype_mitre,
    taxonomy_version,
    valid_mitre,
)


DIRECT_TYPES = {
    "credential_attack": ("credential_attack", "SOC-CRED-001"),
    "malware": ("malware", "SOC-MAL-001"),
    "phishing": ("phishing", "SOC-PHISH-001"),
    "mailbox_rule_change": ("phishing", "SOC-PHISH-002"),
    "oauth_consent": ("credential_attack", "SOC-CRED-004"),
    "ransomware": ("ransomware", "SOC-RANS-001"),
    "network_attack": ("suspicious_network", "SOC-NET-001"),
    "reconnaissance": ("reconnaissance", "SOC-RECON-001"),
    "vulnerability": ("vulnerability_management", "SOC-VULN-001"),
    "dos_attack": ("ddos", "SOC-DDOS-001"),
    "web_attack": ("sql_injection", "SOC-WEB-001"),
    "insider_risk": ("insider_threat", "SOC-INSIDER-001"),
    "external_sharing": ("insider_threat", "SOC-INSIDER-002"),
    "privilege_change": ("credential_attack", "SOC-CRED-003"),
    "data_exfiltration": ("data_exfiltration", "SOC-EXFIL-001"),
    "zero_day": ("zero_day", "SOC-ZERODAY-001"),
    "cloud_alert": ("cloud_native", "SOC-CLOUD-001"),
    "k8s_alert": ("container_kubernetes", "SOC-K8S-001"),
}

SUPPLY_CHAIN_MARKERS = ("node_modules", "site-packages", "vendor/", "package-lock", "requirements.txt",
                        "gemfile.lock", ".nuget", "composer.lock", "yarn.lock")
APT_MARKERS = ("apt", "advanced persistent threat", "nation-state", "nation state", "threat actor",
               "lazarus", "fancy bear", "cozy bear", "sandworm", "volt typhoon", "mustang panda")
CREDENTIAL_MARKERS = ("pass-the-hash", "pass the hash", "credential dumping", "mimikatz", "lsass",
                      "dcsync", "kerberoast", "password spray", "credential stuffing", "brute force")
DISCOVERY_MARKERS = ("system information discovery", "remote system discovery", "account discovery",
                     "process discovery", "network service discovery", "network configuration discovery")
MALWARE_MARKERS = ("malware", "virus", "trojan", "worm")
PHISHING_MARKERS = ("phishing", "phish", "suspicious inbox rule", "malicious email")
RANSOMWARE_MARKERS = ("ransomware", "file encryption", "shadow copy deletion")
EXFILTRATION_MARKERS = ("exfiltration", "data loss prevention", "dlp policy")
NETWORK_MARKERS = ("commandandcontrol", "command and control", "lateral movement",
                   "c2 beacon", "network intrusion")


def _searchable(event: dict) -> str:
    raw = event.get("raw_kv") or {}
    return " ".join((str(event.get("description") or ""), str(event.get("type") or ""),
                     str(event.get("source") or ""), str(event.get("action") or ""), str(raw))).lower()


def _credential_subtype(event_type: str, text: str, mitre: set[str]) -> str:
    if event_type == "oauth_consent" or "oauth consent" in text or "consent to application" in text:
        return "oauth_consent_abuse"
    if event_type == "privilege_change": return "privilege_change"
    if "T1550.002" in mitre or "pass-the-hash" in text or "pass the hash" in text: return "pass_the_hash"
    if "T1003.001" in mitre or "lsass" in text: return "lsass_memory"
    if "T1003.006" in mitre or "dcsync" in text: return "dcsync"
    if "T1558.003" in mitre or "kerberoast" in text: return "kerberoasting"
    if "T1003" in mitre or "credential dumping" in text or "mimikatz" in text: return "credential_dumping"
    if "T1110.003" in mitre or "password spray" in text: return "password_spray"
    if "T1110.004" in mitre or "credential stuffing" in text: return "credential_stuffing"
    if "T1078" in mitre or any(value in text for value in ("unfamiliar sign-in", "impossible travel")):
        return "suspicious_sign_in"
    if "T1110" in mitre or any(value in text for value in ("brute force", "failed password", "authentication fail")):
        return "brute_force"
    return "credential_activity"


def _recon_subtype(text: str, mitre: set[str]) -> str:
    if "T1082" in mitre or "system information discovery" in text: return "endpoint_system_discovery"
    if "T1018" in mitre or "remote system discovery" in text: return "remote_system_discovery"
    if "T1087" in mitre or "account discovery" in text: return "account_discovery"
    if "T1057" in mitre or "process discovery" in text: return "process_discovery"
    if mitre & {"T1016", "T1049"} or "network configuration discovery" in text:
        return "network_configuration_discovery"
    if "T1047" in mitre or "wmi" in text: return "wmi_discovery"
    if "T1595" in mitre or "external scan" in text: return "external_active_scanning"
    return "network_service_scanning"


def _web_subtype(text: str) -> str:
    if re.search(r"sql\s*injection|union\s+(?:all\s+)?select|['\"]\s*or\s+1\s*=\s*1", text):
        return "sql_injection"
    if re.search(r"\bxss\b|cross[\s-]?site scripting|<script", text): return "cross_site_scripting"
    if re.search(r"path traversal|directory traversal|\.\./\.\.", text): return "path_traversal"
    if re.search(r"command injection|shell injection|os command", text): return "command_injection"
    if re.search(r"remote file inclusion|\brfi\b", text): return "remote_file_inclusion"
    return "unknown_web_exploit"


def _subtype(category: str, event_type: str, text: str, mitre: set[str], raw: dict) -> str:
    if category == "credential_attack": return _credential_subtype(event_type, text, mitre)
    if category == "reconnaissance": return _recon_subtype(text, mitre)
    if category == "sql_injection": return _web_subtype(text)
    if category == "phishing":
        if event_type == "mailbox_rule_change": return "mailbox_rule_abuse"
        if "T1566.001" in mitre or "attachment" in text: return "spearphishing_attachment"
        if "T1566.002" in mitre or "phishing link" in text: return "spearphishing_link"
        return "malicious_email"
    if category == "ransomware":
        if "T1490" in mitre or "shadow copy" in text: return "recovery_inhibition"
        return "data_encryption" if "T1486" in mitre or "encrypt" in text else "ransomware_behavior"
    if category == "suspicious_network":
        if "command and control" in text or "c2 beacon" in text: return "command_and_control"
        if "lateral movement" in text: return "lateral_movement"
        if "exploit" in text: return "exploit_attempt"
    if category == "vulnerability_management":
        if raw.get("cisa_kev") or raw.get("actively_exploited"): return "actively_exploited_vulnerability"
        if raw.get("is_unfixed"): return "unpatched_vulnerability"
    if category == "file_integrity" and any(marker in text for marker in ("/etc/passwd", "/etc/shadow", "sshd_config")):
        return "sensitive_file_change"
    if category == "supply_chain": return "package_manager_tampering"
    if category == "ddos":
        if "syn flood" in text or "syn_flood" in text: return "syn_flood"
        if "udp flood" in text or "udp_flood" in text: return "udp_flood"
        if "http flood" in text or "http_flood" in text: return "http_flood"
    if category == "insider_threat":
        if event_type == "external_sharing": return "anonymous_external_sharing"
        if "bulk download" in text or raw.get("correlation_count"): return "bulk_download"
    if category == "data_exfiltration" and "removable media" in text: return "removable_media_exfiltration"
    if category == "zero_day" and raw.get("actively_exploited"): return "actively_exploited_zero_day"
    if category == "cloud_native":
        if "iam" in text or "root account" in text: return "cloud_iam_abuse"
        if "public" in text or "exposure" in text: return "public_cloud_exposure"
    if category == "container_kubernetes":
        if "privileged container" in text or "hostpath" in text: return "privileged_container"
        if "container escape" in text: return "container_escape"
        if "serviceaccount" in text or "service account" in text: return "service_account_abuse"
    return normalize_subtype(category, None)


def _confidence(event: dict, category: str, ioc_hits: list[dict]) -> tuple[float, str]:
    raw = event.get("raw_kv") or {}
    score = 0.52
    if event.get("type") in DIRECT_TYPES or event.get("type") in {"fim_change", "security_alert"}: score += 0.10
    if raw.get("wazuh_rule_id") or raw.get("operation") or raw.get("rule_id"): score += 0.08
    if event.get("mitre_technique"): score += 0.08
    if event.get("src_ip") or event.get("destination") or event.get("user_name"): score += 0.05
    if any(hit.get("malicious") for hit in ioc_hits): score += 0.12
    if event.get("severity") in ("high", "critical"): score += 0.05
    if category == "apt_activity": score = min(score, 0.70)
    score = min(round(score, 2), 0.95)
    return score, "high" if score >= 0.85 else "moderate" if score >= 0.70 else "low"


def classify(event: dict, ioc_hits: list[dict] | None = None) -> Optional[dict]:
    """Return one versioned, evidence-backed deterministic classification."""
    event_type = str(event.get("type") or "").lower()
    text = _searchable(event)
    raw = event.get("raw_kv") or {}
    mitre = set(valid_mitre(event.get("mitre_technique") or []))
    attribution_status = "none"

    if event_type == "fim_change":
        category, rule_id = (("supply_chain", "SOC-SUPPLY-001")
                             if any(value in text for value in SUPPLY_CHAIN_MARKERS)
                             else ("file_integrity", "SOC-FIM-001"))
    elif event_type == "security_alert":
        if any(value in text for value in CREDENTIAL_MARKERS): category, rule_id = "credential_attack", "SOC-CRED-002"
        elif any(value in text for value in PHISHING_MARKERS): category, rule_id = "phishing", "SOC-PHISH-004"
        elif any(value in text for value in RANSOMWARE_MARKERS): category, rule_id = "ransomware", "SOC-RANS-002"
        elif any(value in text for value in EXFILTRATION_MARKERS): category, rule_id = "data_exfiltration", "SOC-EXFIL-002"
        elif any(value in text for value in NETWORK_MARKERS): category, rule_id = "suspicious_network", "SOC-NET-002"
        elif any(value in text for value in DISCOVERY_MARKERS) or mitre & {"T1082", "T1047", "T1057", "T1018", "T1087", "T1016", "T1049"}:
            category, rule_id = "reconnaissance", "SOC-RECON-002"
        elif any(value in text for value in MALWARE_MARKERS): category, rule_id = "malware", "SOC-MAL-002"
        elif any(value in text for value in APT_MARKERS) and (event.get("source") == "threat_intel" or raw.get("attribution_evidence")):
            category, rule_id, attribution_status = "apt_activity", "SOC-APT-001", "provider_reported"
        else: return None
    else:
        match = DIRECT_TYPES.get(event_type)
        if not match: return None
        category, rule_id = match

    subtype = _subtype(category, event_type, text, mitre, raw)
    if category == "apt_activity" and attribution_status == "none": attribution_status = "suspected"
    confidence, evidence_quality = _confidence(event, category, ioc_hits or [])
    canonical_mitre = valid_mitre([*mitre, *subtype_mitre(category, subtype)])
    return {
        "category": category,
        "attack_family": category_family(category),
        "attack_subtype": subtype,
        "classification": subtype_display(category, subtype),
        "category_display": category_display(category),
        "rule_id": rule_id,
        "rule_version": 1,
        "taxonomy_version": taxonomy_version(),
        "classification_method": "deterministic_rule",
        "evidence_quality": evidence_quality,
        "attribution_status": attribution_status,
        "mitre_technique": canonical_mitre,
        "confidence": confidence,
        "recommendation": "Review the cited source evidence and validate the affected account or asset.",
    }
