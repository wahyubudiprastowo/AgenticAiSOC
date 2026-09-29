# Detection Coverage Validation

Run (UTC): 2026-09-29T13:34:23.080699+00:00

A PASS requires an exact event UUID link, the expected category, and the unique test marker in finding evidence.

| No | Category | Coverage mode | Result | Event UUID | Finding ID | Expected → actual | Analysis | Latency |
|---:|---|---|---|---|---|---|---|---:|
| 1 | Malware | normalized automatic path | PASS - Finding linked and category verified | 12a65994-9305-489c-aa68-1e8f5ca4e8bc | 8ff2fd74-d74b-46f0-b3f8-b019462be59a | malware → malware | pending_ai | 0.022 |
| 2 | Ransomware | normalized automatic path | PASS - Finding linked and category verified | e0fba84b-3626-4eb8-8108-a63d9f9fc4ad | d74f1e35-a63c-47aa-93fd-9c5db737e141 | ransomware → ransomware | pending_ai | 0.023 |
| 3 | Phishing | normalized automatic path | PASS - Finding linked and category verified | 59db5617-9e45-4ba6-8115-f733a7a102f3 | 2032db33-54a1-42ad-8bb2-180fbc317ebe | phishing → phishing | pending_ai | 0.022 |
| 4 | Credential Theft | normalized automatic path | PASS - Finding linked and category verified | 6fc66207-c440-45d0-a60a-f9eadbbbd726 | f035d8e6-5869-42aa-a944-6eaf53f5c89e | credential_attack → credential_attack | pending_ai | 0.019 |
| 5 | Network Intrusion | normalized automatic path | PASS - Finding linked and category verified | 9448b081-3bf5-497e-9d6c-6c7c50c8d535 | ae222b19-d13b-4377-8028-cb79f7de0795 | suspicious_network → suspicious_network | pending_ai | 0.019 |
| 6 | Reconnaissance | normalized automatic path | PASS - Finding linked and category verified | be39cdc0-6b8f-442c-a0a7-8817c9ef44e2 | abd51fcd-742b-4712-9268-e0c7fe17cc3f | reconnaissance → reconnaissance | pending_ai | 0.019 |
| 7 | Vulnerability | normalized automatic path | PASS - Finding linked and category verified | f5920149-5955-4a1e-a42c-bcd8be2cda29 | 57fa3ed6-a126-4ae9-96c3-f755a75ac35f | vulnerability_management → vulnerability_management | pending_ai | 0.02 |
| 8 | File Integrity | normalized automatic path | PASS - Finding linked and category verified | 99077ef9-0676-4a5e-8dc9-0b353d986e61 | 7732cf44-d0d5-4b03-870d-b75ae3c8f8e4 | file_integrity → file_integrity | pending_ai | 0.021 |
| 9 | Supply Chain | normalized automatic path | PASS - Finding linked and category verified | 887ae347-621a-4925-bb97-cb34a9c479bf | abfc4f03-fd6a-4f83-bc35-73a73af32c9d | supply_chain → supply_chain | pending_ai | 0.032 |
| 10 | DDoS | normalized automatic path | PASS - Finding linked and category verified | 6bad9862-2400-4b61-b794-689d205034ac | 728a32b5-3381-4e8a-a486-9c8c3f16c8bd | ddos → ddos | pending_ai | 0.02 |
| 11 | SQL Injection | normalized automatic path | PASS - Finding linked and category verified | fe086466-a000-4cce-8193-9129fe36192f | 9818f5a0-8ebf-4ac3-a91f-69ab69041e27 | sql_injection → sql_injection | pending_ai | 0.021 |
| 12 | Insider Threat | normalized automatic path | PASS - Finding linked and category verified | 1993808e-0cea-4034-88a2-8512a9558f35 | a4472d3c-cc6b-4e48-b979-90d1c27ba6f7 | insider_threat → insider_threat | pending_ai | 0.03 |
| 13 | Data Exfiltration | normalized automatic path | PASS - Finding linked and category verified | e8f4a93a-9d74-49f2-a346-839c28800b44 | 326f1ff3-8887-4263-ba42-61ba50ffa492 | data_exfiltration → data_exfiltration | pending_ai | 0.02 |
| 14 | APT Activity | normalized automatic path | PASS - Finding linked and category verified | fcd2e312-c3a7-498d-99e4-7aae580c578b | f8bd102c-2497-4f62-9eb1-94ceae39568f | apt_activity → apt_activity | pending_ai | 0.022 |
| 15 | Zero-Day | review only | Not testable automatically | - | - | zero_day → - | - | - |
| 16 | Cloud-Native | manual ingest | PASS (manual ingest) - Finding linked and category verified | ba983e66-5dbb-4a25-a264-dc2484dfb472 | 55bedade-e4da-46c8-ab6e-f57164f10484 | cloud_native → cloud_native | pending_ai | 0.021 |
| 17 | Container/Kubernetes | manual ingest | PASS (manual ingest) - Finding linked and category verified | 6e7abb7b-a7bd-4b7c-9e92-bbbb7f0f8767 | 6eb22cff-ddd1-482d-a342-d0e5cd5235b6 | container_kubernetes → container_kubernetes | pending_ai | 0.019 |

## Counts

- Not testable automatically: **1**
- PASS - Finding linked and category verified: **14**
- PASS (manual ingest) - Finding linked and category verified: **2**

## Interpretation

This validates normalized ingestion, deterministic finding persistence, and exact event traceability. The analysis status records whether optional AI enrichment completed. It does not prove that Fortigate, Wazuh, M365, Purview, or other source sensors will emit the normalized event in a real attack. Source-level tests remain required for that claim.
