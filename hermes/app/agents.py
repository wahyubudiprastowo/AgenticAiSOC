from __future__ import annotations
import logging
from . import threat_intel_client
logger = logging.getLogger("hermes.agents")
class TriageAgent:
    def run(self, event: dict, skill: dict) -> dict:
        category = skill.get("category", "suspicious_network") if skill else "suspicious_network"
        severity = event.get("severity", "low"); ioc_hits = event.get("ioc_hits", [])
        malicious_ioc = any(h.get("malicious") for h in ioc_hits); confidence = 0.6
        if severity in ("high", "critical"): confidence += 0.15
        if malicious_ioc: confidence += 0.15
        if event.get("mitre_technique"): confidence += 0.05
        confidence = min(round(confidence, 2), 0.98)
        need_analysis = confidence >= 0.5 or severity in ("high", "critical")
        return {"category": category, "confidence": confidence, "need_analysis": need_analysis}
class InvestigationAgent:
    def run(self, event: dict, skill: dict) -> dict:
        src_ip = event.get("src_ip"); attack_chain = []
        event_type = (event.get("type") or "").lower(); description = (event.get("description") or "").lower()
        if "scan" in event_type or "scan" in description: attack_chain.append("scan")
        if "fail" in description or event_type == "auth_failure": attack_chain.append("bruteforce")
        if "allowed" in (event.get("action") or "").lower() and "after multiple failures" in description: attack_chain.append("login attempt")
        if not attack_chain: attack_chain.append(event_type or "unknown_activity")
        ioc_hits = event.get("ioc_hits", [])
        if not ioc_hits and src_ip:
            fresh = threat_intel_client.enrich_ioc(src_ip, "ip")
            if fresh: ioc_hits = [fresh]
        mitre = skill.get("mitre_technique", []) if skill else []
        return {"attack_chain": attack_chain, "mitre": mitre, "ioc_hits": ioc_hits,
            "historical_note": f"Source IP {src_ip} correlated against {len(ioc_hits)} provider result(s)." if src_ip else "No source IP available."}
class ThreatAnalystAgent:
    _CLASS_BY_CATEGORY = {
        "credential_attack": "Credential Attack", "malware": "Malware", "phishing": "Phishing", "ransomware": "Ransomware",
        "suspicious_network": "Suspicious Network Activity", "reconnaissance": "Reconnaissance", "vulnerability_management": "Vulnerability",
        "file_integrity": "File Integrity", "supply_chain": "Supply Chain Compromise", "ddos": "Denial of Service (DDoS)",
        "sql_injection": "SQL Injection", "insider_threat": "Insider Threat", "data_exfiltration": "Data Exfiltration",
        "apt_activity": "APT Activity", "zero_day": "Zero-Day Exploitation", "cloud_native": "Cloud-Native Attack",
        "container_kubernetes": "Container/Kubernetes Threat",
    }
    def run(self, triage: dict, investigation: dict, event: dict | None = None) -> dict:
        category = triage.get("category", "suspicious_network"); ioc_hits = investigation.get("ioc_hits", []) or []
        malicious_ioc = any(h.get("malicious") for h in ioc_hits)
        credibility = 0.65
        if malicious_ioc: credibility += 0.20
        if len(investigation.get("attack_chain", [])) > 1: credibility += 0.08
        credibility = min(round(credibility, 2), 0.99)
        authority = 0.5; source = (event or {}).get("source", "")
        if source == "wazuh": authority += 0.20
        live_provider_names = {h.get("name") for h in ioc_hits if h.get("mode") == "live"}
        if len(live_provider_names) >= 1: authority += 0.15
        if len(live_provider_names) >= 2: authority += 0.10
        if investigation.get("mitre"): authority += 0.10
        authority = min(round(authority, 2), 0.99)
        relevant = 0.55
        if investigation.get("mitre"): relevant += 0.20
        if (event or {}).get("severity") in ("high", "critical"): relevant += 0.15
        if malicious_ioc: relevant += 0.10
        relevant = min(round(relevant, 2), 0.99)
        avg = (credibility + authority + relevant) / 3
        bucket = "C4" if avg > 0.9 else "C3" if avg > 0.75 else "C2" if avg > 0.5 else "C1"
        return {"threat_classification_bucket": bucket, "credibility": credibility, "authority": authority,
            "relevant": relevant, "type": self._CLASS_BY_CATEGORY.get(category, "Unknown")}
