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
ioc_extractor = load_module("soc_ioc_extractor_test", "soc-core/app/ioc_extractor.py")
filters = load_module("soc_filters_test", "soc-core/app/filters.py")


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

    def test_transport_sender_is_observer_not_attack_source(self):
        event = syslog.normalize_syslog_line("sshd service started", source_ip="192.0.2.10")
        self.assertIsNone(event["src_ip"])
        self.assertEqual(event["raw_kv"]["observer_ip"], "192.0.2.10")
        self.assertEqual(event["raw_kv"]["parser_status"], "generic_unclassified")

    def test_wazuh_extracts_windows_source_and_user(self):
        document = {"_id": "win-auth", "_source": {"agent": {"name": "dc01"},
            "rule": {"level": 10, "description": "Multiple Windows Logon Failures", "groups": [],
                     "mitre": {"id": ["T1110"]}},
            "data": {"win": {"eventdata": {"ipAddress": "198.51.100.12", "targetUserName": "alice"}}}}}
        event = wazuh.wazuh_alert_to_normalized(document)
        self.assertEqual(event["src_ip"], "198.51.100.12")
        self.assertEqual(event["user_name"], "alice")

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
            ({"type": "oauth_consent", "description": "Consent to application", "raw_kv": {"operation": "Consent to application"}}, "m365_identity_compromise"),
            ({"type": "privilege_change", "description": "Add member", "raw_kv": {"operation": "Add member to role"}}, "m365_identity_compromise"),
            ({"type": "ransomware", "description": "Ransomware", "mitre_technique": ["T1486"]}, "ransomware"),
            ({"type": "fim_change", "description": "FIM: modified /etc/passwd", "raw_kv": {"wazuh_rule_groups": ["syscheck"]}}, "file_integrity"),
            ({"type": "fim_change", "description": "FIM: modified /app/node_modules/a.js", "raw_kv": {"wazuh_rule_groups": ["syscheck"]}}, "supply_chain"),
            ({"type": "dos_attack", "description": "SYN flood", "raw_kv": {}}, "ddos"),
            ({"type": "web_attack", "description": "SQL injection UNION SELECT", "raw_kv": {}}, "sql_injection"),
            ({"type": "insider_risk", "description": "Correlated bulk download", "raw_kv": {}}, "insider_threat"),
            ({"type": "data_exfiltration", "description": "DLP rule match", "raw_kv": {}}, "data_exfiltration"),
            ({"type": "security_alert", "source": "threat_intel", "description": "APT29 attributed threat actor", "raw_kv": {"attribution_evidence": True}}, "apt_activity"),
            ({"type": "zero_day", "description": "CVE-2026-0001 vendor fix unavailable", "raw_kv": {"is_zero_day": True}}, "zero_day"),
            ({"type": "cloud_alert", "description": "AWS root UnauthorizedAccess", "raw_kv": {}}, "cloud_native"),
            ({"type": "k8s_alert", "description": "Privileged container hostPath mount", "raw_kv": {}}, "container_kubernetes"),
            ({"type": "security_alert", "description": "possible pass-the-hash attack", "mitre_technique": ["T1550.002"]}, "credential_access"),
            ({"type": "security_alert", "description": "WMI query for System Information Discovery", "mitre_technique": ["T1082", "T1047"]}, "endpoint_discovery"),
            ({"type": "security_alert", "description": "Unfamiliar sign-in", "raw_kv": {"alert_categories": ["InitialAccess"]}}, "m365_identity_compromise"),
        ]
        for event, expected in cases:
            with self.subTest(expected=expected): self.assertEqual(self.route(event), expected)


class DeterministicFindingTests(unittest.TestCase):
    def test_primary_categories_survive_without_ai(self):
        cases = [
            ({"type": "malware"}, "malware"), ({"type": "ransomware"}, "ransomware"),
            ({"type": "phishing"}, "phishing"), ({"type": "credential_attack"}, "credential_attack"),
            ({"type": "oauth_consent"}, "credential_attack"),
            ({"type": "privilege_change"}, "credential_attack"),
            ({"type": "network_attack"}, "suspicious_network"),
            ({"type": "reconnaissance"}, "reconnaissance"),
            ({"type": "vulnerability"}, "vulnerability_management"),
            ({"type": "fim_change", "description": "FIM: /etc/passwd"}, "file_integrity"),
            ({"type": "fim_change", "description": "FIM: /app/node_modules/a.js"}, "supply_chain"),
            ({"type": "dos_attack"}, "ddos"), ({"type": "web_attack"}, "sql_injection"),
            ({"type": "insider_risk"}, "insider_threat"),
            ({"type": "data_exfiltration"}, "data_exfiltration"),
            ({"type": "security_alert", "source": "threat_intel", "description": "APT29 attributed threat actor",
              "raw_kv": {"attribution_evidence": True}}, "apt_activity"),
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

    def test_actor_keyword_without_attribution_evidence_is_not_apt(self):
        event = {"type": "security_alert", "source": "wazuh", "severity": "high",
                 "description": "connection attempt mentions APT29", "raw_kv": {}}
        self.assertIsNone(detections.classify(event))
        self.assertIsNone(skills.select_skill(event))

    def test_web_attack_subtypes_are_distinct(self):
        cases = {
            "SQL injection UNION SELECT": "sql_injection",
            "Cross-site scripting XSS payload": "cross_site_scripting",
            "Directory path traversal ../../etc/passwd": "path_traversal",
            "OS command injection attempt": "command_injection",
            "Remote file inclusion RFI": "remote_file_inclusion",
        }
        for description, expected in cases.items():
            finding = detections.classify({"type": "web_attack", "severity": "high",
                                           "description": description, "raw_kv": {}})
            with self.subTest(description=description):
                self.assertEqual(finding["attack_subtype"], expected)


class FilterTests(unittest.TestCase):
    def test_informational_mitre_event_is_not_forwarded(self):
        event = {"type": "informational", "severity": "low", "mitre_technique": ["T1078"],
                 "raw_kv": {"security_signal": True}}
        self.assertFalse(filters.should_forward_to_ai(event, mitre_matched=True))

    def test_actionable_mitre_security_alert_is_forwarded(self):
        event = {"type": "security_alert", "severity": "low", "mitre_technique": ["T1550.002"], "raw_kv": {}}
        self.assertTrue(filters.should_forward_to_ai(event, mitre_matched=True))


class IOCExtractionTests(unittest.TestCase):
    def test_extracts_supported_types_and_excludes_internal_or_transport_hashes(self):
        event = {"src_ip": "8.8.8.8", "destination": "10.0.0.8",
                 "description": "CVE-2024-3400 callback https://bad.example/path",
                 "raw_hash": "a" * 64,
                 "raw_kv": {"sha256": "b" * 64, "domain": "payload.example", "dstip": "192.168.1.2"}}
        values = {(item["ioc_type"], item["ioc"]) for item in ioc_extractor.extract_iocs(event)}
        self.assertIn(("ip", "8.8.8.8"), values)
        self.assertIn(("cve", "CVE-2024-3400"), values)
        self.assertIn(("url", "https://bad.example/path"), values)
        self.assertIn(("domain", "bad.example"), values)
        self.assertIn(("domain", "payload.example"), values)
        self.assertIn(("hash", "b" * 64), values)
        self.assertNotIn(("ip", "10.0.0.8"), values)
        self.assertNotIn(("hash", "a" * 64), values)


class ThreatIntelSafetyTests(unittest.TestCase):
    def test_cyfirma_compound_stix_pattern_extracts_each_indicator(self):
        values = providers._extract_stix_pattern_values(
            "[file:hashes.md5 = 'abc' OR file:hashes.'SHA-256' = 'def' OR ipv4-addr:value = '198.51.100.10']")
        self.assertEqual(values, {"abc", "def", "198.51.100.10"})

    def test_nvd_cve_metadata_is_structured_without_becoming_malicious_ioc(self):
        result = providers._nvd_result("CVE-2025-54293", {"vulnerabilities": [{"cve": {
            "id": "CVE-2025-54293", "vulnStatus": "Analyzed", "published": "2025-01-01T00:00:00Z",
            "lastModified": "2026-01-01T00:00:00Z", "cisaExploitAdd": "2026-02-01",
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            "references": [{"tags": ["Patch"]}],
            "weaknesses": [{"description": [{"value": "CWE-78"}]}],
        }}]})
        self.assertEqual(result["mode"], "live")
        self.assertEqual(result["cvss_score"], 9.8)
        self.assertEqual(result["cvss_severity"], "critical")
        self.assertTrue(result["cisa_kev"])
        self.assertTrue(result["patch_reference"])
        self.assertFalse(result["malicious"])

    def test_provider_error_does_not_create_mock_malicious_verdict(self):
        old = providers.THREAT_INTEL_MOCK_MODE
        providers.THREAT_INTEL_MOCK_MODE = False
        try:
            result = providers._mock_or_unavailable("virustotal", "8.8.8.8", "timeout")
        finally:
            providers.THREAT_INTEL_MOCK_MODE = old
        self.assertEqual(result["mode"], "unavailable")
        self.assertFalse(result["malicious"])

    def test_provider_runtime_keeps_per_type_failures_visible(self):
        previous = providers._provider_runtime.copy()
        try:
            providers._provider_runtime.clear()
            providers._provider_runtime["otx"] = {"by_ioc_type": {
                "ip": {"mode": "live", "last_checked": 1.0, "detail": None},
                "cve": {"mode": "unavailable", "last_checked": 2.0, "detail": "ReadTimeout"},
            }}
            status = providers.provider_statuses()["otx"]
        finally:
            providers._provider_runtime.clear()
            providers._provider_runtime.update(previous)
        self.assertEqual(status["mode"], "partial")
        self.assertEqual(status["by_ioc_type"]["ip"]["mode"], "live")
        self.assertIn("cve: ReadTimeout", status["detail"])


class DashboardAttackDetailTests(unittest.TestCase):
    def test_legacy_finding_taxonomy_is_inferred_without_mutating_input(self):
        finding = {"id": "legacy", "category": "credential_attack", "threat_classification": "Brute Force",
                   "severity": "high", "confidence": 0.8, "evidence": {}, "ai_result": {}}
        original = dict(finding)
        detail = dashboard_agg.attack_detail(finding, [])
        self.assertEqual(detail["finding"]["attack_subtype"], "brute_force")
        self.assertEqual(detail["finding"]["subtype_origin"], "classification_display_match")
        self.assertEqual(finding, original)

    def test_attack_detail_joins_and_redacts_source_event(self):
        finding = {"id": "finding-1", "category": "vulnerability_management", "threat_classification": "Vulnerability",
                   "severity": "high", "confidence": 0.88, "mitre_technique": ["T1190"],
                   "evidence": {"finding": "Vulnerable package", "evidence": ["CVE confirmed"]},
                   "ai_result": {"analysis": "confirmed"}, "recommendation": "Patch the package.",
                   "indicators": [{"ioc": "CVE-2025-54293", "ioc_type": "cve", "malicious": False,
                                   "confidence": 0, "enrichment_status": "partial", "provider_results": []}]}
        event = {"id": "event-1", "source": "wazuh", "type": "vulnerability", "severity": "high",
                 "src_ip": "198.51.100.10", "dst_ip": "10.0.0.8", "description": "CVE-2025-54293 affects lxd",
                 "normalized": {"destination": "server01", "raw_kv": {"cve": "CVE-2025-54293",
                     "package": {"name": "lxd", "version": "4.0"}, "password": "must-hide"}}}
        detail = dashboard_agg.attack_detail(finding, [event])
        self.assertEqual(detail["attack"]["source_ips"], ["198.51.100.10"])
        self.assertIn("server01", detail["attack"]["destinations"])
        self.assertEqual(detail["attack"]["cves"], ["CVE-2025-54293"])
        self.assertEqual(detail["attack"]["cve_status"], "observed_in_source_event")
        self.assertEqual(detail["attack"]["path"]["kind"], "exposure")
        self.assertIn("server01", detail["attack"]["path"]["destination_values"])
        self.assertEqual(detail["attack"]["field_status"]["source"], "observed")
        self.assertEqual(detail["quality"]["maturity"], "source_evidenced")
        self.assertEqual(detail["quality"]["completeness_pct"], 100)
        self.assertIn("Source IP", detail["quality"]["observed_fields"])
        self.assertIn("User", detail["quality"]["not_applicable_fields"])
        self.assertEqual(detail["attack"]["indicators"][0]["ioc_type"], "cve")
        self.assertEqual(detail["mitre"][0]["name"], "Exploit Public-Facing Application")
        self.assertEqual(detail["events"][0]["raw"]["normalized"]["raw_kv"]["password"], "[REDACTED]")

    def test_attack_detail_extracts_mail_sender_recipient_ip_and_delivery(self):
        finding = {"id": "finding-mail", "category": "phishing", "threat_classification": "Phishing",
                   "severity": "high", "confidence": 0.8, "evidence": {}, "ai_result": {}}
        event = {"id": "event-mail", "source": "m365_audit", "type": "phishing", "severity": "high",
                 "description": "ThreatIntelligence: TIMailData", "raw_payload": {"operation": "TIMailData"},
                 "normalized": {"source": "m365_audit", "type": "phishing", "user_name": "ThreatIntel", "raw_kv": {
                     "operation": "TIMailData", "object_id": "opaque-message-id"}, "raw": {
                     "P1Sender": "sender@example.net", "SenderIp": "8.8.8.8",
                     "Recipients": ["analyst@example.org"], "DeliveryAction": "Delivered",
                     "Subject": "Invoice", "DetectionMethod": "Spoof DMARC", "DeviceName": "ThreatIntel"}}}
        detail = dashboard_agg.attack_detail(finding, [event])
        self.assertEqual(detail["attack"]["path"]["kind"], "email")
        self.assertIn("sender@example.net", detail["attack"]["source_identities"])
        self.assertIn("8.8.8.8", detail["attack"]["source_ips"])
        self.assertEqual(detail["attack"]["affected_users"], ["analyst@example.org"])
        self.assertEqual(detail["attack"]["users"], ["analyst@example.org"])
        self.assertEqual(detail["attack"]["destinations"], ["analyst@example.org"])
        self.assertEqual(detail["attack"]["actions"], ["Delivered"])
        self.assertEqual(detail["events"][0]["technical"]["detection_method"], "Spoof DMARC")
        self.assertEqual(detail["quality"]["maturity"], "source_evidenced")

    def test_attack_detail_separates_endpoint_asset_ip_from_source_ip(self):
        finding = {"id": "finding-fim", "category": "file_integrity", "threat_classification": "File Integrity",
                   "severity": "medium", "confidence": 0.7, "evidence": {}, "ai_result": {}}
        event = {"id": "event-fim", "source": "wazuh", "type": "fim_change", "severity": "medium",
                 "description": "FIM: modified on /etc/ssh/sshd_config", "normalized": {
                     "source": "wazuh", "type": "fim_change", "destination": "server01",
                     "raw": {"agent": {"name": "server01", "ip": "10.20.30.40"}},
                     "raw_kv": {"fim_event": "modified", "fim_path": "/etc/ssh/sshd_config"}}}
        detail = dashboard_agg.attack_detail(finding, [event])
        self.assertEqual(detail["attack"]["source_ips"], [])
        self.assertEqual(detail["attack"]["destination_ips"], ["10.20.30.40"])
        self.assertEqual(detail["attack"]["actions"], ["modified"])
        self.assertEqual(detail["attack"]["path"]["kind"], "endpoint")
        self.assertEqual(detail["attack"]["cve_status"], "not_applicable_to_event_type")
        self.assertIn("Source IP", detail["quality"]["not_applicable_fields"])

    def test_attack_detail_marks_sparse_coverage_test_as_synthetic(self):
        finding = {"id": "finding-test", "category": "sql_injection", "threat_classification": "SQL Injection",
                   "severity": "high", "confidence": 0.8, "evidence": {}, "ai_result": {}}
        event = {"id": "event-test", "source": "fortigate", "type": "web_attack", "severity": "high",
                 "description": "[COVERAGE_TEST:11-abc] Synthetic SQL injection", "normalized": {
                     "source": "fortigate", "type": "web_attack", "is_synthetic_test": True,
                     "raw_kv": {"is_synthetic_test": True}}}
        detail = dashboard_agg.attack_detail(finding, [event])
        self.assertTrue(detail["provenance"]["is_synthetic"])
        self.assertEqual(detail["provenance"]["kind"], "synthetic_validation")
        self.assertEqual(detail["attack"]["cve_status"], "not_reported_by_source")
        self.assertEqual(detail["quality"]["maturity"], "validation_only")
        self.assertIn("Destination asset or account", detail["quality"]["missing_fields"])
        self.assertTrue(any("not source-sensor" in item for item in detail["quality"]["limitations"]))

    def test_attribution_distribution_uses_canonical_analyst_label(self):
        rows = dashboard_agg.threat_type_distribution_counts(
            [{"category": "apt_activity", "total": 2}]
        )
        attribution = next(row for row in rows if row["label"] == "Threat Actor Attribution")
        self.assertEqual(attribution["count"], 2)
        self.assertNotIn("APT Activity", {row["label"] for row in rows})

    def test_endpoint_malware_user_does_not_turn_asset_into_mail_recipient(self):
        finding = {"id": "finding-malware", "category": "malware", "threat_classification": "Malware",
                   "severity": "high", "confidence": 0.8, "evidence": {}, "ai_result": {}}
        event = {"id": "event-malware", "source": "wazuh", "type": "malware", "severity": "high",
                 "src_ip": "198.51.100.11", "user_name": "coverage.user", "description": "Malware blocked",
                 "normalized": {"source": "wazuh", "type": "malware", "src_ip": "198.51.100.11",
                                "destination": "coverage-endpoint-01", "user_name": "coverage.user",
                                "raw_kv": {"action": "quarantined"}}}
        detail = dashboard_agg.attack_detail(finding, [event])
        self.assertEqual(detail["attack"]["path"]["kind"], "attack")
        self.assertEqual(detail["attack"]["path"]["destination_asset_values"], ["coverage-endpoint-01"])
        self.assertEqual(detail["attack"]["users"], ["coverage.user"])


class QdrantMemoryTests(unittest.TestCase):
    def test_point_id_is_stable_per_finding(self):
        finding_id = "36435839-6b58-4976-b3ea-a33d26521105"
        self.assertEqual(memory._point_id(finding_id), finding_id)
        self.assertEqual(memory._point_id("legacy-finding"), memory._point_id("legacy-finding"))


if __name__ == "__main__":
    unittest.main()
