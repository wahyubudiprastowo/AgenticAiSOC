# Detection Coverage Validation

Run (UTC): 2026-09-29T16:35:29.776614+00:00

A PASS requires an exact event UUID link, the expected category, and the unique test marker in finding evidence.

| No | Category | Coverage mode | Result | Event UUID | Finding ID | Expected → actual | Analysis | Latency |
|---:|---|---|---|---|---|---|---|---:|
| 1 | Malware | normalized automatic path | PASS - Finding linked and category verified | 77f4f6b3-452d-4f29-a4c6-2fecabccd057 | 73d4e001-e330-4435-876c-ca20a4dd090f | malware → malware | pending_ai | 0.032 |
| 2 | Ransomware | normalized automatic path | PASS - Finding linked and category verified | fc664d9b-c89e-4ee2-8582-db5e8dce4577 | 381ffd99-598e-4c35-9e0d-0534f7cb672c | ransomware → ransomware | pending_ai | 0.024 |
| 3 | Phishing | normalized automatic path | PASS - Finding linked and category verified | 5e095a7f-a665-480f-b064-9b741f639007 | b069121d-fd1b-40a8-9c09-0cd51fd964b3 | phishing → phishing | pending_ai | 0.033 |
| 4 | Credential Theft | normalized automatic path | PASS - Finding linked and category verified | c71af8e1-efdd-485c-8d85-1a474669a38a | 732e584b-d2c2-4953-af5e-37e0b5a6a76f | credential_attack → credential_attack | pending_ai | 0.023 |
| 5 | Network Intrusion | normalized automatic path | PASS - Finding linked and category verified | a44cf170-2ca3-436f-b5b4-21c242ae83c6 | acdc2ca9-03a3-4001-886b-9954396dbde5 | suspicious_network → suspicious_network | pending_ai | 0.057 |
| 6 | Reconnaissance | normalized automatic path | PASS - Finding linked and category verified | 52a9d781-d410-4183-b802-d5533f40812f | cfbc04c1-03c9-4313-8d31-ee0ee0a50640 | reconnaissance → reconnaissance | pending_ai | 0.021 |
| 7 | Vulnerability | normalized automatic path | PASS - Finding linked and category verified | 0b4b619e-176c-422d-be40-8c99e9c41e0a | 320d2cb4-822b-428f-ac06-b8199d4b9e08 | vulnerability_management → vulnerability_management | pending_ai | 0.021 |
| 8 | File Integrity | normalized automatic path | PASS - Finding linked and category verified | cb9c6a1c-1b49-42f2-a88e-8a13efc14b77 | 5bbd3ffb-f8e0-41c6-b0a5-f0a320548889 | file_integrity → file_integrity | pending_ai | 0.026 |
| 9 | Supply Chain | normalized automatic path | PASS - Finding linked and category verified | 69d8cc64-6977-46ae-9120-cf64d54320bf | e360876e-8646-4084-a6cf-ee25237f17f0 | supply_chain → supply_chain | pending_ai | 0.024 |
| 10 | DDoS | normalized automatic path | PASS - Finding linked and category verified | 57bcc18d-a91c-4eeb-856b-1a74b68ac188 | 96365a34-8e35-48a0-ad2d-75a8cc2dc963 | ddos → ddos | pending_ai | 0.022 |
| 11 | SQL Injection | normalized automatic path | PASS - Finding linked and category verified | 49eab17f-e6be-4063-a698-5446892f109e | c25733ab-b7de-4067-8d01-176c5fbad345 | sql_injection → sql_injection | pending_ai | 0.023 |
| 12 | Insider Threat | normalized automatic path | PASS - Finding linked and category verified | 2117f512-10af-484c-9aae-ff356ab31855 | afd930c2-6fcd-4c25-8a7d-4fb33af4dfae | insider_threat → insider_threat | pending_ai | 0.023 |
| 13 | Data Exfiltration | normalized automatic path | PASS - Finding linked and category verified | 95c20fd9-f67d-4b4e-a74d-b8e02b0f5f0c | 23b6268f-c192-412f-b2ca-502292375302 | data_exfiltration → data_exfiltration | pending_ai | 0.028 |
| 14 | APT Activity | normalized automatic path | PASS - Finding linked and category verified | e891b8a1-157e-4563-afe5-0e7527a71090 | 647bc550-5e84-4c3c-98d8-263ff4826ce4 | apt_activity → apt_activity | pending_ai | 0.057 |
| 15 | Zero-Day | review only | Not testable automatically | - | - | zero_day → - | - | - |
| 16 | Cloud-Native | manual ingest | PASS (manual ingest) - Finding linked and category verified | 84895665-01fe-4236-8bcc-0d1b173c586d | 307a431d-5846-4dae-8740-41d3c115a13b | cloud_native → cloud_native | pending_ai | 0.022 |
| 17 | Container/Kubernetes | manual ingest | PASS (manual ingest) - Finding linked and category verified | 1deb8f4a-4e25-4be5-92f2-fceb7d34dde9 | 11794828-0238-4a6b-b72c-7df42448864f | container_kubernetes → container_kubernetes | pending_ai | 0.022 |

## Counts

- Not testable automatically: **1**
- PASS - Finding linked and category verified: **14**
- PASS (manual ingest) - Finding linked and category verified: **2**

## Interpretation

This validates normalized ingestion, deterministic finding persistence, and exact event traceability. The analysis status records whether optional AI enrichment completed. It does not prove that Fortigate, Wazuh, M365, Purview, or other source sensors will emit the normalized event in a real attack. Source-level tests remain required for that claim.
