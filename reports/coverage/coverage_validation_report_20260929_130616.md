# Detection Coverage Validation

Run (UTC): 2026-09-29T13:06:16.193543+00:00

A PASS requires an exact event UUID link, the expected category, and the unique test marker in finding evidence.

| No | Category | Coverage mode | Result | Event UUID | Finding ID | Expected → actual | Latency |
|---:|---|---|---|---|---|---|---:|
| 1 | Malware | normalized automatic path | PASS - Finding linked and category verified | fb766113-295c-47d6-9d92-47048c4f8914 | 1c857fa2-ce73-423a-a9fd-344838332916 | malware → malware | 1.086 |
| 2 | Ransomware | normalized automatic path | PASS - Finding linked and category verified | 642715e5-8510-4954-b96a-b230fa8b04ec | 485fa7fa-30b5-40aa-b73b-9a89fab7e035 | ransomware → ransomware | 1.08 |
| 3 | Phishing | normalized automatic path | PASS - Finding linked and category verified | 0bfe6ae2-beff-4e55-96e9-4e376002f052 | 8350eccb-81a8-4b83-8206-9b7eeca0fdf3 | phishing → phishing | 1.121 |
| 4 | Credential Theft | normalized automatic path | PASS - Finding linked and category verified | e7882e11-d824-4943-9662-cad3b8392cc0 | e21e86bd-718f-460a-a0f1-423b51f9de98 | credential_attack → credential_attack | 1.081 |
| 5 | Network Intrusion | normalized automatic path | PASS - Finding linked and category verified | afcc24f2-8d8a-45fd-9dba-bf9680936d65 | 4c8d511c-aff2-47a3-9fab-3f1ab8280a27 | suspicious_network → suspicious_network | 1.113 |
| 6 | Reconnaissance | normalized automatic path | PASS - Finding linked and category verified | 86b19da5-4f4c-4e73-9390-4283f8b80210 | 1e9bcec4-0442-41e2-8e9e-f9e5895e6644 | reconnaissance → reconnaissance | 1.115 |
| 7 | Vulnerability | normalized automatic path | PASS - Finding linked and category verified | 7f9df248-2ecc-4491-9835-c1396f2a78a9 | ad4a48f5-07e7-4a28-b275-b4fbd2fed704 | vulnerability_management → vulnerability_management | 1.08 |
| 8 | File Integrity | normalized automatic path | PASS - Finding linked and category verified | 3cbbb3cf-d09c-433b-a876-7e6f07d3ad1a | 71e1ec90-c9d7-4e06-8212-95f278c79fde | file_integrity → file_integrity | 1.087 |
| 9 | Supply Chain | normalized automatic path | PASS - Finding linked and category verified | bbf70638-b10c-433d-a827-5ef66e5dbe9a | af77fd7d-d287-448f-8597-730d8b87a79f | supply_chain → supply_chain | 1.113 |
| 10 | DDoS | normalized automatic path | PASS - Finding linked and category verified | f2d4cfaf-be30-4915-b34f-08fece01d63c | 6f6858b2-f5a8-4947-abc8-03ce701e71bd | ddos → ddos | 1.115 |
| 11 | SQL Injection | normalized automatic path | PASS - Finding linked and category verified | e5f1c3e1-558f-4ede-a3fe-19b6836d1cd2 | c01a6ff6-ed9a-49be-80db-2d358ba40b27 | sql_injection → sql_injection | 1.081 |
| 12 | Insider Threat | normalized automatic path | PASS - Finding linked and category verified | 02d501f2-c6df-4a02-a576-12b530470e00 | 8b7ad572-72b8-448c-a35c-97f238412759 | insider_threat → insider_threat | 1.093 |
| 13 | Data Exfiltration | normalized automatic path | PASS - Finding linked and category verified | d65a9a5a-1836-4772-8d82-674f39fdac2c | 10ba0b58-eeeb-4250-a275-d36856141a96 | data_exfiltration → data_exfiltration | 1.084 |
| 14 | APT Activity | normalized automatic path | PASS - Finding linked and category verified | 6cc4df83-f718-4d72-af6b-1b420da10c75 | eedf8190-8568-4c48-9a7f-59e680124c0f | apt_activity → apt_activity | 1.103 |
| 15 | Zero-Day | review only | Not testable automatically | - | - | zero_day → - | - |
| 16 | Cloud-Native | manual ingest | PASS (manual ingest) - Finding linked and category verified | 567edb8c-9de6-4be8-84d6-808828e1e392 | 5d160c4d-4c46-4dc5-91ea-067386c5bd25 | cloud_native → cloud_native | 1.079 |
| 17 | Container/Kubernetes | manual ingest | PASS (manual ingest) - Finding linked and category verified | 2b527251-1df2-47e6-99c2-1a77f47ff4e7 | c002359b-6e54-4bb2-8e2e-03c104d98546 | container_kubernetes → container_kubernetes | 1.08 |

## Counts

- Not testable automatically: **1**
- PASS - Finding linked and category verified: **14**
- PASS (manual ingest) - Finding linked and category verified: **2**

## Interpretation

This validates the normalized ingestion-to-finding path. It does not prove that Fortigate, Wazuh, M365, Purview, or other source sensors will emit the normalized event in a real attack. Source-level tests remain required for that claim.
