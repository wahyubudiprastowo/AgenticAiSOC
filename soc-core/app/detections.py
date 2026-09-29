from __future__ import annotations

from typing import Optional


CLASSIFICATION = {
    "credential_attack": "Credential Attack", "malware": "Malware", "phishing": "Phishing",
    "ransomware": "Ransomware", "suspicious_network": "Suspicious Network Activity",
    "reconnaissance": "Reconnaissance", "vulnerability_management": "Vulnerability",
    "file_integrity": "File Integrity", "supply_chain": "Supply Chain Compromise",
    "ddos": "Denial of Service (DDoS)", "sql_injection": "SQL Injection",
    "insider_threat": "Insider Threat", "data_exfiltration": "Data Exfiltration",
    "apt_activity": "APT Activity", "zero_day": "Zero-Day Exploitation",
    "cloud_native": "Cloud-Native Attack", "container_kubernetes": "Container/Kubernetes Threat",
}

DIRECT_TYPES = {
    "credential_attack": ("credential_attack", "SOC-CRED-001"),
    "malware": ("malware", "SOC-MAL-001"),
    "phishing": ("phishing", "SOC-PHISH-001"),
    "mailbox_rule_change": ("phishing", "SOC-PHISH-002"),
    "oauth_consent": ("phishing", "SOC-PHISH-003"),
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
                      "dcsync", "kerberoast", "password spray", "brute force")
DISCOVERY_MARKERS = ("system information discovery", "remote system discovery", "account discovery",
                     "process discovery", "network service discovery")
MALWARE_MARKERS = ("malware", "virus", "trojan", "worm")
PHISHING_MARKERS = ("phishing", "phish", "suspicious inbox rule", "malicious email")
RANSOMWARE_MARKERS = ("ransomware", "file encryption", "shadow copy deletion")
EXFILTRATION_MARKERS = ("exfiltration", "data loss prevention", "dlp policy")
NETWORK_MARKERS = ("commandandcontrol", "command and control", "lateral movement",
                   "c2 beacon", "network intrusion")


def _searchable(event: dict) -> str:
    raw = event.get("raw_kv") or {}
    return " ".join((str(event.get("description") or ""), str(event.get("type") or ""),
                     str(event.get("source") or ""), str(raw))).lower()


def classify(event: dict) -> Optional[dict]:
    """Return one evidence-backed deterministic category, or None.

    This layer deliberately uses normalized types and narrow indicators. It does
    not call Hermes, Jev, Qdrant, or external intelligence providers.
    """
    event_type = str(event.get("type") or "").lower()
    searchable = _searchable(event)
    if event_type == "fim_change":
        category, rule_id = (("supply_chain", "SOC-SUPPLY-001")
                             if any(value in searchable for value in SUPPLY_CHAIN_MARKERS)
                             else ("file_integrity", "SOC-FIM-001"))
    elif event_type == "security_alert":
        if any(value in searchable for value in APT_MARKERS): category, rule_id = "apt_activity", "SOC-APT-001"
        elif any(value in searchable for value in CREDENTIAL_MARKERS): category, rule_id = "credential_attack", "SOC-CRED-002"
        elif any(value in searchable for value in PHISHING_MARKERS): category, rule_id = "phishing", "SOC-PHISH-004"
        elif any(value in searchable for value in RANSOMWARE_MARKERS): category, rule_id = "ransomware", "SOC-RANS-002"
        elif any(value in searchable for value in EXFILTRATION_MARKERS): category, rule_id = "data_exfiltration", "SOC-EXFIL-002"
        elif any(value in searchable for value in NETWORK_MARKERS): category, rule_id = "suspicious_network", "SOC-NET-002"
        elif any(value in searchable for value in DISCOVERY_MARKERS): category, rule_id = "reconnaissance", "SOC-RECON-002"
        elif any(value in searchable for value in MALWARE_MARKERS): category, rule_id = "malware", "SOC-MAL-002"
        else: return None
    else:
        match = DIRECT_TYPES.get(event_type)
        if not match: return None
        category, rule_id = match
    return {"category": category, "classification": CLASSIFICATION[category], "rule_id": rule_id,
            "confidence": 0.7 if event.get("severity") in ("high", "critical") else 0.6,
            "recommendation": "Review the source event and validate the affected account or asset."}
