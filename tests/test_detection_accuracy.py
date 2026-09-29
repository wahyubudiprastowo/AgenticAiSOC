from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]

try:
    import httpx  # noqa: F401
except ModuleNotFoundError:
    sys.modules["httpx"] = types.SimpleNamespace(Client=object)


def load_module(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


m365 = load_module("m365_normalizer_test", "m365-collector/app/normalizer.py")
syslog = load_module("syslog_normalizer_test", "syslog-collector/app/normalizer.py")
wazuh = load_module("wazuh_client_test", "soc-core/app/wazuh_client.py")
skills = load_module("skill_loader_test", "hermes/app/skill_loader.py")
providers = load_module("providers_test", "threat-intel/app/providers.py")
dashboard_agg = load_module("dashboard_aggregations_test", "dashboard/app/aggregations.py")
memory = load_module("hermes_memory_test", "hermes/app/memory.py")
detections = load_module("soc_detections_test", "soc-core/app/detections.py")


class M365NormalizerTests(unittest.TestCase):
    def test_mailbox_access_is_routine_audit(self):
        record = {"Id": "same-id", "Operation": "MailItemsAccessed", "Workload": "Exchange"}
        first = m365.normalize_m365_record(record)
        second = m365.normalize_m365_record(dict(record))
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(first["raw_hash"], second["raw_hash"])
        self.assertEqual(first["type"], "generic")
        self.assertEqual(first["severity"], "low")
        self.assertFalse(first["raw_kv"]["security_signal"])

    def test_mfa_interruption_is_not_credential_attack(self):
        event = m365.normalize_m365_record({"Id": "mfa", "Operation": "UserLoginFailed", "ErrorNumber": "50074"})
        self.assertEqual(event["type"], "auth_interruption")
        self.assertFalse(event["raw_kv"]["security_signal"])

    def test_bad_password_is_correlation_candidate(self):
        event = m365.normalize_m365_record({"Id": "bad-password", "Operation": "UserLoginFailed", "ErrorNumber": "50126"})
        self.assertEqual(event["type"], "auth_failure")
        self.assertTrue(event["raw_kv"]["correlate"])
        self.assertFalse(event["raw_kv"]["security_signal"])

    def test_explicit_security_operation_is_signal(self):
        event = m365.normalize_m365_record({"Id": "phish", "Operation": "PhishNotAllowed", "Workload": "Exchange"})
        self.assertEqual(event["type"], "phishing")
        self.assertTrue(event["raw_kv"]["security_signal"])


class SourceNormalizerTests(unittest.TestCase):
    def test_fortigate_passed_application_is_not_intrusion(self):
        event = syslog.normalize_syslog_line('type=utm subtype=app-ctrl action=pass msg="App passed by firewall"', "fortigate")
        self.assertEqual(event["type"], "generic")

    def test_fortigate_ips_attack_is_intrusion(self):
        event = syslog.normalize_syslog_line('type=utm subtype=ips action=dropped msg="attack detected"', "fortigate")
        self.assertEqual(event["type"], "network_attack")

    def test_modern_wazuh_vulnerability_fields(self):
        document = {"_id": "vuln-doc", "_source": {
            "agent": {"name": "server01"}, "package": {"name": "lxd", "version": "4.0"},
            "vulnerability": {"id": "CVE-2025-54293", "severity": "High", "detected_at": "2026-01-01T00:00:00Z",
                              "scanner": {"condition": "Package less than 5.21.4"}},
        }}
        event = wazuh.wazuh_vulnerability_to_normalized(document)
        self.assertEqual(event["raw_kv"]["cve"], "CVE-2025-54293")
        self.assertEqual(event["raw_kv"]["package"]["name"], "lxd")
        self.assertFalse(event["raw_kv"]["is_unfixed"])
        self.assertNotIn("UNKNOWN-CVE", event["description"])

    def test_wazuh_informational_and_attack_types(self):
        info = {"_id": "1", "_source": {"rule": {"level": 3, "description": "Fortigate: App passed by firewall.", "groups": []}}}
        attack = {"_id": "2", "_source": {"rule": {"level": 8, "description": "Fortigate attack dropped.", "groups": ["ids"]}}}
        self.assertEqual(wazuh.wazuh_alert_to_normalized(info)["type"], "informational")
        self.assertEqual(wazuh.wazuh_alert_to_normalized(attack)["type"], "network_attack")

    def test_ipsec_group_is_not_mistaken_for_ips(self):
        event = {"_id": "3", "_source": {"rule": {"level": 8,
                 "description": "A new external device was recognized by the system", "groups": ["ipsec"],
                 "mitre": {"id": ["T1092"]}}}}
        self.assertEqual(wazuh.wazuh_alert_to_normalized(event)["type"], "security_alert")


class SkillRoutingTests(unittest.TestCase):
    def route(self, event):
        skill = skills.select_skill(event)
        return skill.get("skill") if skill else None

    def test_routine_events_remain_unmatched(self):
        self.assertIsNone(self.route({"type": "generic", "source": "m365_audit",
                                      "description": "Exchange: MailItemsAccessed",
                                      "raw_kv": {"operation": "MailItemsAccessed"}}))
        self.assertIsNone(self.route({"type": "informational", "source": "wazuh",
                                      "description": "Fortigate: App passed by firewall.", "raw_kv": {}}))

    def test_structured_routes(self):
        cases = [
            ({"type": "malware", "description": "MalwareDetected", "raw_kv": {}}, "malware"),
            ({"type": "credential_attack", "description": "Correlated credential failures", "mitre_technique": ["T1110"]}, "brute_force"),
            ({"type": "phishing", "description": "Suspicious phishing email", "raw_kv": {}}, "phishing"),
            ({"type": "network_attack", "description": "Fortigate IPS attack dropped", "raw_kv": {}}, "suspicious_network"),
            ({"type": "reconnaissance", "description": "Nmap port scan detected", "raw_kv": {}}, "reconnaissance"),
            ({"type": "vulnerability", "description": "CVE-9999-0001 vulnerable package", "raw_kv": {}}, "vulnerability_management"),
            ({"type": "mailbox_rule_change", "description": "Exchange: New-InboxRule", "raw_kv": {"operation": "New-InboxRule"}}, "phishing"),
            ({"type": "oauth_consent", "description": "Consent to application", "raw_kv": {"operation": "Consent to application"}}, "phishing"),
            ({"type": "privilege_change", "description": "Add member", "raw_kv": {"operation": "Add member to role"}}, "m365_identity_compromise"),
            ({"type": "ransomware", "description": "Ransomware", "mitre_technique": ["T1486"]}, "ransomware"),
            ({"type": "fim_change", "description": "FIM: modified /etc/passwd", "raw_kv": {"wazuh_rule_groups": ["syscheck"]}}, "file_integrity"),
            ({"type": "fim_change", "description": "FIM: modified /app/node_modules/a.js", "raw_kv": {"wazuh_rule_groups": ["syscheck"]}}, "supply_chain"),
            ({"type": "dos_attack", "description": "SYN flood", "raw_kv": {}}, "ddos"),
            ({"type": "web_attack", "description": "SQL injection UNION SELECT", "raw_kv": {}}, "sql_injection"),
            ({"type": "insider_risk", "description": "Correlated bulk download", "raw_kv": {}}, "insider_threat"),
            ({"type": "data_exfiltration", "description": "DLP rule match", "raw_kv": {}}, "data_exfiltration"),
            ({"type": "security_alert", "description": "APT29 attributed threat actor", "raw_kv": {}}, "apt_activity"),
            ({"type": "zero_day", "description": "CVE-2026-0001 vendor fix unavailable", "raw_kv": {"is_zero_day": True}}, "zero_day"),
            ({"type": "cloud_alert", "description": "AWS root UnauthorizedAccess", "raw_kv": {}}, "cloud_native"),
            ({"type": "k8s_alert", "description": "Privileged container hostPath mount", "raw_kv": {}}, "container_kubernetes"),
            ({"type": "security_alert", "description": "possible pass-the-hash attack", "mitre_technique": ["T1550.002"]}, "credential_access"),
            ({"type": "security_alert", "description": "WMI query for System Information Discovery", "mitre_technique": ["T1082", "T1047"]}, "endpoint_discovery"),
        ]
        for event, expected in cases:
            with self.subTest(expected=expected): self.assertEqual(self.route(event), expected)


class DeterministicFindingTests(unittest.TestCase):
    def test_primary_categories_survive_without_ai(self):
        cases = [
            ({"type": "malware"}, "malware"), ({"type": "ransomware"}, "ransomware"),
            ({"type": "phishing"}, "phishing"), ({"type": "credential_attack"}, "credential_attack"),
            ({"type": "oauth_consent"}, "phishing"),
            ({"type": "privilege_change"}, "credential_attack"),
            ({"type": "network_attack"}, "suspicious_network"),
            ({"type": "reconnaissance"}, "reconnaissance"),
            ({"type": "vulnerability"}, "vulnerability_management"),
            ({"type": "fim_change", "description": "FIM: /etc/passwd"}, "file_integrity"),
            ({"type": "fim_change", "description": "FIM: /app/node_modules/a.js"}, "supply_chain"),
            ({"type": "dos_attack"}, "ddos"), ({"type": "web_attack"}, "sql_injection"),
            ({"type": "insider_risk"}, "insider_threat"),
            ({"type": "data_exfiltration"}, "data_exfiltration"),
            ({"type": "security_alert", "description": "APT29 attributed threat actor"}, "apt_activity"),
            ({"type": "security_alert", "description": "Defender CommandAndControl alert"}, "suspicious_network"),
            ({"type": "security_alert", "description": "Defender ransomware alert"}, "ransomware"),
            ({"type": "zero_day"}, "zero_day"), ({"type": "cloud_alert"}, "cloud_native"),
            ({"type": "k8s_alert"}, "container_kubernetes"),
        ]
        for event, expected in cases:
            event.setdefault("severity", "high"); event.setdefault("raw_kv", {})
            with self.subTest(expected=expected):
                self.assertEqual(detections.classify(event)["category"], expected)

    def test_generic_event_does_not_create_deterministic_finding(self):
        self.assertIsNone(detections.classify({"type": "generic", "description": "routine audit", "raw_kv": {}}))


class ThreatIntelSafetyTests(unittest.TestCase):
    def test_provider_error_does_not_create_mock_malicious_verdict(self):
        old = providers.THREAT_INTEL_MOCK_MODE
        providers.THREAT_INTEL_MOCK_MODE = False
        try:
            result = providers._mock_or_unavailable("virustotal", "8.8.8.8", "timeout")
        finally:
            providers.THREAT_INTEL_MOCK_MODE = old
        self.assertEqual(result["mode"], "unavailable")
        self.assertFalse(result["malicious"])


class DashboardAttackDetailTests(unittest.TestCase):
    def test_attack_detail_joins_and_redacts_source_event(self):
        finding = {"id": "finding-1", "category": "vulnerability_management", "threat_classification": "Vulnerability",
                   "severity": "high", "confidence": 0.88, "mitre_technique": ["T1190"],
                   "evidence": {"finding": "Vulnerable package", "evidence": ["CVE confirmed"]},
                   "ai_result": {"analysis": "confirmed"}, "recommendation": "Patch the package."}
        event = {"id": "event-1", "source": "wazuh", "type": "vulnerability", "severity": "high",
                 "src_ip": "198.51.100.10", "dst_ip": "10.0.0.8", "description": "CVE-2025-54293 affects lxd",
                 "normalized": {"destination": "server01", "raw_kv": {"cve": "CVE-2025-54293",
                     "package": {"name": "lxd", "version": "4.0"}, "password": "must-hide"}}}
        detail = dashboard_agg.attack_detail(finding, [event])
        self.assertEqual(detail["attack"]["source_ips"], ["198.51.100.10"])
        self.assertIn("server01", detail["attack"]["destinations"])
        self.assertEqual(detail["attack"]["cves"], ["CVE-2025-54293"])
        self.assertEqual(detail["mitre"][0]["name"], "Exploit Public-Facing Application")
        self.assertEqual(detail["events"][0]["raw"]["normalized"]["raw_kv"]["password"], "[REDACTED]")


class QdrantMemoryTests(unittest.TestCase):
    def test_point_id_is_stable_per_finding(self):
        finding_id = "36435839-6b58-4976-b3ea-a33d26521105"
        self.assertEqual(memory._point_id(finding_id), finding_id)
        self.assertEqual(memory._point_id("legacy-finding"), memory._point_id("legacy-finding"))


if __name__ == "__main__":
    unittest.main()
