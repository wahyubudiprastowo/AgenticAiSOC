# End-to-End Pipeline, Source Code, and Runtime Audit

Audit time: 2026-09-29 UTC / 2026-09-30 Asia/Jakarta

## Executive assessment

The platform is receiving and persisting real Wazuh and Microsoft 365 data. It is not currently true that every incoming log can be identified as an attack. Every accepted event can be stored and normalized, but a finding should only be created when evidence matches a detection rule or correlation. Routine and unsupported events must remain non-findings.

The 17 labels are top-level dashboard categories, not the complete universe of attack techniques. The implementation has 20 Hermes skills but only 17 category buckets. MITRE ATT&CK technique and sub-technique IDs are the appropriate extensible dimension beneath those buckets.

At audit time:

- 764,675 events were stored.
- 218,910 events were forwarded to the detection/orchestration layer.
- 91,613 findings existed.
- 127,285 forwarded events had no linked finding in the consistency sample. This closely matches the `triage_no_match` volume and is primarily caused by broad Wazuh forwarding followed by narrower Hermes matching.
- No event was linked to more than one finding, so the current deterministic-plus-Hermes path is not duplicating findings.
- 76,260 historical findings use the legacy schema without `primary_event_id`. New deterministic findings use `primary_event_id` and Hermes updates the same row.

## Actual pipeline behavior

1. Syslog, M365, Defender, CYFIRMA feeds, manual ingest, and three Wazuh index queries produce different normalized event shapes.
2. SOC Core deduplicates, correlates selected event families, extracts IOC values, queries threat intelligence, and applies the forward filter.
3. SOC Core creates a deterministic finding when a deterministic rule matches.
4. The event is pushed to the Redis `filtered_events` list.
5. Hermes selects one best matching skill, optionally calls Jev, and updates the deterministic finding. If no deterministic finding exists, Hermes can create one.
6. PostgreSQL is authoritative for events and findings. Qdrant stores a derived incident-memory representation.

## Overlap and collision findings

### Deterministic rules and Hermes skills

`soc-core/app/detections.py` and `hermes/app/skills/*.yaml` both classify the same event. This is intentional for resilience: SOC Core persists a finding before optional AI. The current path does not create duplicate findings because `findings.primary_event_id` is unique and Hermes receives `finding_id` to update.

The risk is taxonomy drift. Category names and mappings are duplicated in:

- SOC Core deterministic classification;
- 20 Hermes YAML skills;
- Hermes analyst mappings;
- Jev fallback mappings and prompt schema;
- dashboard category order and labels;
- validation scripts.

The audit script checks some of this duplication, but there is no single versioned taxonomy registry.

### Historical and current finding schemas

76,260 findings have no `primary_event_id`; 14,976 findings in the initial audit sample were created by the current SOC Core path. This does not currently duplicate event findings, but historical rows have weaker provenance and IOC attachment than new rows.

### Reconnaissance and endpoint discovery

External network scanning and post-compromise endpoint discovery both map to `reconnaissance`. For example, Wazuh WMI System Information Discovery (`T1082`, `T1047`) is displayed in the same category as a Fortigate/Nmap port scan. The label is therefore too broad for incident interpretation.

### SQL injection and generic web attacks

`web_attack` maps to `sql_injection`, although the syslog parser also recognizes XSS, path traversal, command injection, and remote file inclusion. Those attacks are currently mislabeled as SQL Injection at the top-level category.

### Credential attack scope

Brute force, credential dumping, pass-the-hash, OAuth/service-principal persistence, privilege changes, and unfamiliar sign-ins share one `credential_attack` category. The technique IDs preserve some distinction, but the dashboard label alone does not.

### APT classification

APT can be assigned by SOC Core keywords or by Hermes after IOC provider text contains an actor marker. This is attribution logic, not proof of an APT campaign. It requires explicit provider evidence and should remain visibly marked as attribution confidence.

## Source and data status

| Source | Runtime status | Data status | Main gap |
|---|---|---|---|
| Wazuh alerts | Active | 159k+ stored Wazuh events | Broad MITRE forwarding produced many no-match events; source/user/action extraction was incomplete historically |
| Wazuh FIM | Active | 875 events | Generic FIM is detectable; supply-chain classification depends only on package-path keywords |
| Wazuh vulnerability index | Active | 245 events | CVE data exists, but historical IOC rows are sparse and zero-day cannot be inferred solely from “unfixed” |
| Direct syslog `36514` | Listener healthy | `received=0` after restart; only test/manual syslog rows exist | Devices still send to Wazuh `514`, not this collector |
| M365 audit | Active | 604k+ stored events | Collector re-reads overlapping 15-minute windows and relies on DB dedup; many upstream requests are duplicates |
| Defender XDR | API authorized | Only 6 distinct incidents stored historically | Previous requests omitted `$expand=alerts`, so evidence, IP, user, asset, category, and MITRE were absent |
| CYFIRMA IOC | Active after patch | Live exact IOC match verified | Previous implementation used Bearer auth; this tenant endpoint requires `x-api-key` |
| CYFIRMA org vulnerability | Not active | 0 records | Configured endpoint returns HTTP 401 for Bearer, `x-api-key`, `api-key`, and `Key`; correct vendor authentication/entitlement is not available in current config |
| CYFIRMA research | Not active | 0 records | Configured URL is an HTML website protected by web controls, not a JSON API |
| CYFIRMA TAXII | Disabled | 0 objects | Collection URL and bearer token are empty |
| VirusTotal | Rate limited | Intermittent historical results | Current runtime receives HTTP 429 |
| AbuseIPDB | Authentication failed | Unavailable | Current runtime receives HTTP 401 |
| CrowdSec CTI | Authorization failed | Watchlist still works locally | Current runtime receives HTTP 403 |
| OTX | Partial | Live for several IOC types | Hash calls have timed out and some IP requests return HTTP 400 |
| ThreatFox | Active | Live | No material runtime error in the final check |
| URLhaus | Active | Live | Supports URL/domain, not every IOC type |
| NVD | Active on CVE lookup | Live CVE metadata verified | No historical CVE backfill has been run |
| Jev / 9router | Degraded | Local fallback is producing findings | Upstream returns HTTP 401: all configured chatgpt-web connections are banned and must be reconnected in 9router |
| Qdrant | Reachable | 91k+ points | Uses local hash/trigram vectors, not semantic embeddings; `indexed_vectors_count=0`, so current searches are full scans |

## Why fields are missing

### Source IP

- Wazuh normalization previously read only `data.srcip`; Windows paths such as `data.win.eventdata.ipAddress` were ignored.
- M365 records often contain a user and operation but no attack source IP.
- Defender incidents previously did not include alert evidence.
- Generic syslog previously treated the transport sender as attacker IP. This was inaccurate; it is now stored as `observer_ip` instead.
- Vulnerability and FIM events often have no attacker because they describe asset state or file change, not a network attack.

### Destination or affected asset

- Wazuh generally provides `agent.name`, which is an affected endpoint rather than a destination IP.
- M365 audit records frequently describe a mailbox, file, or tenant object and have no host destination.
- Defender evidence may contain a user/IP without device evidence.
- CYFIRMA global IOC data has no organization-specific affected asset until correlated with a local event.

### User

- Network appliance logs may not include an authenticated identity.
- Wazuh Windows user fields were nested and previously not extracted.
- Vulnerability, DDoS, network scan, and malware signatures may legitimately have no user.

### Action

- Wazuh action exists only for some decoder families.
- M365 uses `Operation`; it was not duplicated into top-level `action`.
- Defender incidents represent a detection state and recommended response, not always an observed allow/block action.

### CVE and CVE status

- CVE is applicable to vulnerability/exploit/package evidence, not to every phishing, login, FIM, or network event.
- NVD enrichment now works for new CVE-bearing events.
- Historical findings were created before `finding_indicators` persistence and therefore remain unenriched unless a controlled backfill is run.

## Detection coverage by current category

| Category | Real production evidence | Assessment |
|---|---|---|
| Malware | Wazuh/M365 present | Active, but artifact/hash coverage depends on source payload |
| Ransomware | No confirmed production sample | Synthetic validation only |
| Phishing | Large M365 TIMailData volume | Active; alert-level aggregation is needed to reduce one-finding-per-record noise |
| Credential Attack | Wazuh present | Active; several identity attack families are combined |
| Suspicious Network | Wazuh present | Active; broad fallback bucket and mostly no MITRE mapping |
| Reconnaissance | Wazuh endpoint discovery present | Active but semantically mixed with external reconnaissance |
| Vulnerability | Wazuh present | Active; historical NVD/IOC attachment incomplete |
| File Integrity | Wazuh present | Active; actor/action context often absent |
| Supply Chain | No confirmed production sample | Path-keyword heuristic and synthetic validation only |
| DDoS | No direct production syslog sample | Synthetic Fortigate validation only |
| SQL Injection | No direct production syslog sample | Synthetic web-attack validation only; category is too narrow |
| Insider Threat | M365 present | Active; based mainly on bulk-download/external-sharing correlation |
| Data Exfiltration | No confirmed production sample | Synthetic DLP validation only |
| APT Activity | No confirmed production attribution | Synthetic/legacy evidence only |
| Zero-Day | No finding | Requires reliable source flag plus no-fix/active-exploitation evidence |
| Cloud-Native | Manual ingest | No AWS/Azure collector |
| Container/Kubernetes | Manual ingest | No Kubernetes audit/Falco collector |

## Reliability and behavior gaps

1. Redis uses destructive `BRPOP` queues without acknowledgement, retry queue, or dead-letter queue. A crash after pop can lose a raw event or optional AI processing.
2. Wazuh polling uses overlapping time windows and fixed result limits without a persistent cursor. Long downtime or bursts beyond the query size can create gaps.
3. M365 polling repeats a 15-minute window every five minutes and does not follow the Management Activity `NextPageUri`. Database dedup prevents duplicate rows, but upstream bandwidth, Redis, and DB lookups are wasted and pagination can miss records.
4. Several collectors catch exceptions and return empty lists. Their `/health` endpoints can remain healthy while the upstream source is unauthorized or unavailable.
5. Jev previously reported healthy when only local fallback was running. The patch now exposes `reasoning.mode=fallback` and the dashboard marks it degraded.
6. Qdrant failures are silently ignored. Hash vectors provide lexical similarity only and `QDRANT_EMBEDDING_MODE` was not used by code.
7. Threat-intelligence provider calls have no global per-provider rate limiter or circuit breaker. VirusTotal 429 responses demonstrate the impact.
8. At least 48 `.env` keys are not referenced by runtime code or compose behavior. Important examples include `FILTER_REQUIRE_IOC_OR_MITRE`, multiple `SOC_*` budget/cache/stream settings, AI enable/cache/lease flags, `WAZUH_ARCHIVES_INDEX`, and `QDRANT_EMBEDDING_MODE`. The Settings page currently makes these look operational.
9. Direct syslog has no RFC3164/RFC5424/vendor parser registry. Unknown messages become `generic` rather than a parse error, so `errors=0` does not mean successful semantic parsing.
10. Existing source data is not automatically updated when a richer normalizer is deployed because duplicate events return early. The new Defender detail therefore applies to new incident IDs unless a controlled backfill is run.

## Priority remediation

### P0 — restore evidence sources and honest status

1. Reconnect the two banned chatgpt-web connections in 9router. Until then Jev is a deterministic local fallback, not remote AI reasoning.
2. Obtain the documented CYFIRMA organization-vulnerability authentication method and entitlement. The existing URL/key combination is rejected independently of common header styles.
3. Replace the CYFIRMA research webpage URL with a supported JSON/TAXII/feed endpoint or disable the feed flag.
4. Send a second device syslog destination to port `36514`, or deploy a relay/fanout before Wazuh. Do not bind a second service to Wazuh-owned port `514`.

### P1 — prevent loss, noise, and hidden source failures

1. Replace Redis list consumption with Redis Streams consumer groups, acknowledgement, retry, and dead-letter handling.
2. Add persistent Wazuh cursors using timestamp plus document ID and page through all results.
3. Implement M365 `NextPageUri`, a durable content cursor, and explicit error/status counters.
4. Add provider circuit breakers and per-provider quotas, especially for VirusTotal.
5. Make source health include last successful poll, last error, newest source timestamp, and lag.

### P2 — improve classification accuracy

1. Move taxonomy, category labels, MITRE mapping, and source requirements into one versioned registry.
2. Add a separate subtype/tactic dimension so endpoint Discovery is not presented as external Reconnaissance.
3. Split generic web attacks into SQL injection, XSS, path traversal, command injection, and other exploit subtypes while retaining a stable parent category.
4. Aggregate related M365 mail evidence into incidents instead of creating one finding for every TIMailData record.
5. Add source-specific parser fixtures from real sanitized Wazuh, Fortigate, Defender, M365, AWS, and Kubernetes payloads.

### P3 — complete coverage

1. Add CloudTrail/Azure Activity collectors and Kubernetes audit/Falco ingestion.
2. Build controlled historical IOC/CVE enrichment and Defender evidence backfill with checkpointing and dry-run counts.
3. Replace hash-vector Qdrant memory with a real embedding model, payload indexes, retention, and stale-point cleanup.
4. Remove or mark unused settings so the Settings page represents actual behavior.

## Patches applied during this audit

- CYFIRMA IOC auth changed to configurable `x-api-key`; a real CYFIRMA hash returned a live malicious hit with confidence 0.95.
- Compound STIX patterns now extract every IOC value instead of only the text after the first equals sign.
- CYFIRMA refresh failures now have backoff and no longer create a request thread for every event.
- Defender requests now use `$expand=alerts`, pagination, evidence extraction, source IP, user, affected device, MITRE, categories, and incident URL.
- Wazuh extracts common nested Windows IP/user/action fields.
- Wazuh informational events no longer become security signals merely because a MITRE ID exists.
- Generic syslog transport peers are stored as `observer_ip`, not falsely displayed as attacker IP.
- Jev records `remote` versus `fallback` mode and exposes the upstream error in health without exposing credentials.
- Defender `InitialAccess` alerts can route to the M365 identity-compromise skill.

Validation after patch: 28 unit tests pass, audit verifier reports 75 PASS / 0 WARN / 0 FAIL, CYFIRMA IOC lookup is live, direct Defender normalization contains 48 expanded alerts and structured evidence, and newly ingested Wazuh informational events show zero forwarded events.
