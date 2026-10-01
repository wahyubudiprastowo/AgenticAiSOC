# End-to-End Pipeline, Source Code, and Runtime Audit

Audit time: 2026-09-29 UTC / 2026-09-30 Asia/Jakarta

Reliability phase-2 update (2026-10-01 UTC): the live database passed
1.10 million events and 140k findings while preserving the earliest finding at
`2026-09-27 21:22:54+07`. The raw queue moved from about 61k to below 57k after
enabling four bounded consumers; processing depth equals the four active
workers, no item is older than ten minutes, and both raw/Hermes dead-letter
counts are zero. M365 reports all five subscriptions enabled, zero poll errors,
bounded pagination, and durable cursors. Historical CVE reconciliation now has
166 distinct structured CVE indicators and zero unavailable CVE links.

Update after accuracy phase 1 (2026-09-30 08:19 UTC): the database held
979,592 events, 247,582 forwarded events, and 117,600 findings. The earliest
finding remained `2026-09-27 21:22:54+07`, proving the historical range was
preserved. Of the findings, 76,261 are legacy rows without `primary_event_id`
and 41,339 use current event-level traceability. One row was briefly
`pending_ai`; the Hermes queue was zero. Counts continue increasing while
collectors run.

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

The original risk was taxonomy drift because category names and mappings were
duplicated in:

- SOC Core deterministic classification;
- 20 Hermes YAML skills;
- Hermes analyst mappings;
- Jev fallback mappings and prompt schema;
- dashboard category order and labels;
- validation scripts.

This is now controlled by `config/detection_taxonomy.yaml` (version
`2026.09.30`). SOC Core, Hermes, Jev, dashboard historical inference, and the
audit verifier load or validate against that registry. Stable category IDs are
retained for compatibility; attack family and subtype carry the precise label.

### Historical and current finding schemas

76,261 findings have no `primary_event_id`; 41,339 findings at the phase-1
snapshot use the current SOC Core path. This does not duplicate event findings,
but historical rows have weaker provenance and IOC attachment than new rows.
They are not rewritten: Attack Details derives conservative taxonomy metadata
at read time and marks whether the subtype was stored, matched from the legacy
classification label, or obtained from the category default.

### Reconnaissance and endpoint discovery

The stable parent remains `reconnaissance`, while `attack_subtype` now separates
external active scanning, network-service scanning, endpoint system discovery,
remote-system discovery, account/process/network discovery, and WMI discovery.
The dashboard displays the subtype, so Wazuh WMI/System Discovery is no longer
presented as a port scan.

### SQL injection and generic web attacks

The backward-compatible category ID remains `sql_injection`, with display name
**Web Application Attack**. Deterministic subtypes now distinguish SQL injection,
XSS, path traversal, command injection, remote file inclusion, and unknown web
exploits.

### Credential attack scope

The stable `credential_attack` parent now has explicit subtypes for brute force,
password spraying, credential stuffing/dumping, LSASS, DCSync, pass-the-hash,
Kerberoasting, OAuth abuse, privilege changes, and suspicious sign-ins.

### APT classification

Actor reporting is stored separately as `attribution_status` plus cited provider
evidence. Hermes cannot replace a deterministic attack category with APT based
on provider text. The parent bucket is now displayed as **Threat Actor
Attribution**, which remains an assessment and not proof of a campaign.

## Source and data status

| Source | Runtime status | Data status | Main gap |
|---|---|---|---|
| Wazuh alerts | Active | 159k+ stored Wazuh events | Broad MITRE forwarding produced many no-match events; source/user/action extraction was incomplete historically |
| Wazuh FIM | Active | 875 events | Generic FIM is detectable; supply-chain classification depends only on package-path keywords |
| Wazuh vulnerability index | Active | 245+ events | CVE source evidence exists; NVD backfill is additive, while zero-day still cannot be inferred solely from “unfixed” |
| Direct syslog `36514` | Listener healthy | `received=0` after restart; only test/manual syslog rows exist | Devices still send to Wazuh `514`, not this collector |
| M365 audit | Active | 872k+ stored events | Subscription/pagination/cursor controls are active; new TIMailData records use bounded incident aggregation while historical findings remain unchanged |
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
| NVD | Active on CVE lookup | Live CVE metadata verified | Controlled historical backfill uses NVD-only requests and additive idempotent indicator upserts |
| Jev / 9router | Intermittent; current health degraded | 985 remote-reasoned findings existed in the 2026-10-01 snapshot; fallback continues during failures | Current upstream failures open a fixed 60-second circuit; 9router connection/auth health must be stabilized |
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
- Historical CVE findings created before `finding_indicators` persistence were
  reconciled on 2026-10-01 by the controlled NVD-only backfill: 161 candidate
  CVEs and 187 missing finding/CVE links were processed. Final normal and
  unavailable-retry dry-runs both report zero candidates. The operation wrote
  indicator rows only.

## Detection coverage by current category

| Category | Real production evidence | Assessment |
|---|---|---|
| Malware | Wazuh/M365 present | Active, but artifact/hash coverage depends on source payload |
| Ransomware | No confirmed production sample | Synthetic validation only |
| Phishing | Large M365 TIMailData volume | Active; new records aggregate by campaign/message/user-time key, while historical one-record findings are preserved |
| Credential Attack | Wazuh present | Active; several identity attack families are combined |
| Suspicious Network | Wazuh present | Active; broad fallback bucket and mostly no MITRE mapping |
| Reconnaissance | Wazuh endpoint discovery present | Active but semantically mixed with external reconnaissance |
| Vulnerability | Wazuh present | Active; historical NVD/IOC attachment is covered by the controlled additive backfill |
| File Integrity | Wazuh present | Active; actor/action context often absent |
| Supply Chain | No confirmed production sample | Path-keyword heuristic and synthetic validation only |
| DDoS | No direct production syslog sample | Synthetic Fortigate validation only |
| Web Application Attack | No direct production syslog sample | Synthetic WAF/IPS validation only; subtype routing is implemented but needs real source samples |
| Insider Threat | M365 present | Active; based mainly on bulk-download/external-sharing correlation |
| Data Exfiltration | No confirmed production sample | Synthetic DLP validation only |
| Threat Actor Attribution | No confirmed production attribution | Synthetic/legacy evidence only; attribution is context, not proof of a campaign |
| Zero-Day | No finding | Requires reliable source flag plus no-fix/active-exploitation evidence |
| Cloud-Native | Manual ingest | No AWS/Azure collector |
| Container/Kubernetes | Manual ingest | No Kubernetes audit/Falco collector |

## Reliability and behavior status

1. **Resolved:** Redis raw and filtered lists now atomically move claimed items
   into processing lists. ACK occurs only after persistent completion; failures
   receive bounded retry, then dead-letter handling, and startup recovers
   unacknowledged items. A bounded raw worker pool prevents routine records from
   waiting behind one slow enrichment operation.
2. **Open:** Wazuh polling uses overlapping time windows and fixed result limits
   without a persistent timestamp/document-ID cursor. Long downtime or bursts
   beyond the query size can create gaps.
3. **Resolved:** M365 uses POST for missing subscriptions, discovers subscriptions
   that are already enabled, follows bounded `NextPageUri`, and stores one Redis
   cursor per content type. Poll/page/blob errors are explicit in `/stats`. New
   TIMailData evidence is grouped into one finding per bounded incident key;
   member events remain individually stored and linked.
4. **Partially resolved:** source-specific stats now expose M365 and CYFIRMA
   failures, but several other collectors still need newest-source timestamp and
   lag in their health contract.
5. **Resolved:** Jev fallback is exposed as `reasoning.mode=fallback`, and the
   dashboard marks it degraded instead of remote-AI healthy. Open-circuit traffic
   no longer extends the cooldown indefinitely; one half-open probe runs after
   the fixed deadline.
6. **Open:** Qdrant uses deterministic hash vectors, not semantic embeddings;
   retention and stale-point cleanup are absent.
7. **Resolved for failure containment:** NVD has a process-wide rate limiter;
   other providers open bounded per-provider circuits after repeated failure.
   Runtime still correctly reports VT 429, AbuseIPDB 401, CrowdSec 403, and OTX
   timeout as unavailable; valid credentials/quotas remain an external task.
8. **Open:** unused/dead environment keys must be removed or marked inactive so
   Settings represents actual behavior.
9. **Open:** direct syslog has no complete RFC3164/RFC5424/vendor parser registry.
   Unknown messages become `generic`, so `errors=0` is not proof of semantic parsing.
10. **Open:** richer normalizers do not rewrite duplicate historical events.
    Any source-evidence migration must remain a separate dry-run/additive job.

## Priority remediation

### P0 — restore evidence sources and honest status

1. Stabilize the configured 9router upstream connection/authentication. Remote
   reasoning is proven by 985 stored remote findings, but current failures still
   trigger an explicit deterministic fallback and degraded health.
2. Obtain the documented CYFIRMA organization-vulnerability authentication method and entitlement. The existing URL/key combination is rejected independently of common header styles.
3. Replace the CYFIRMA research webpage URL with a supported JSON/TAXII/feed endpoint or disable the feed flag.
4. Send a second device syslog destination to port `36514`, or deploy a relay/fanout before Wazuh. Do not bind a second service to Wazuh-owned port `514`.
5. Replace or re-entitle the credentials/quotas currently returning VirusTotal
   429, AbuseIPDB 401, and CrowdSec 403. These remain explicit `unavailable`
   provider results; they are never interpreted as clean IOCs.

### P1 — prevent loss, noise, and hidden source failures

Completed: acknowledged Redis delivery with retry/DLQ/recovery; persisted event
pipeline state; bounded raw consumers; M365 subscription discovery, POST start,
pagination, cursor, and counters.

Remaining priority:

1. Add persistent Wazuh cursors using timestamp plus document ID and page through all results.
2. Make every source health response include last successful poll, last error,
   newest source timestamp, and lag.

### P2 — improve classification accuracy

Completed in phase 1:

1. Versioned canonical taxonomy shared across the classification pipeline.
2. Discovery/reconnaissance, web-exploit, and identity-attack subtypes.
3. Deterministic category authority with Jev proposal/verdict stored separately.
4. Strict Jev response schema with evidence-reference validation and bounded
   upstream timeout/circuit behavior.

Still required:

1. Add source-specific parser fixtures from real sanitized Wazuh, Fortigate,
   Defender, M365, AWS, and Kubernetes payloads.

### P3 — complete coverage

1. Add CloudTrail/Azure Activity collectors and Kubernetes audit/Falco ingestion.
2. Build a controlled Defender evidence backfill; the historical CVE backfill is implemented as an idempotent NVD-only job.
3. Replace hash-vector Qdrant memory with a real embedding model, payload indexes, retention, and stale-point cleanup.
4. Remove or mark unused settings so the Settings page represents actual behavior.
5. Obtain sanitized production sensor samples for ransomware, DDoS, supply
   chain, WAF/web attacks, data exfiltration, and attribution before claiming
   source-level coverage. Current routing tests for these categories are
   synthetic evidence only.
6. Keep Zero-Day at zero until a trusted source supplies explicit no-fix or
   active-exploitation evidence. Absence of an NVD patch reference alone is not
   sufficient to create a Zero-Day finding.

## Patches applied during this audit

- CYFIRMA IOC auth changed to configurable `x-api-key`; a real CYFIRMA hash returned a live malicious hit with confidence 0.95.
- Compound STIX patterns now extract every IOC value instead of only the text after the first equals sign.
- CYFIRMA refresh failures now have backoff and no longer create a request thread for every event.
- Defender requests now use `$expand=alerts`, pagination, evidence extraction, source IP, user, affected device, MITRE, categories, and incident URL.
- Wazuh extracts common nested Windows IP/user/action fields.
- Wazuh informational events no longer become security signals merely because a MITRE ID exists.
- Generic syslog transport peers are stored as `observer_ip`, not falsely displayed as attacker IP.
- Jev records `remote` versus `fallback` mode and exposes the upstream error in health without exposing credentials.
- Jev's fixed cooldown can no longer be extended indefinitely by incoming
  events; health now exposes circuit state and retry delay, and a single
  half-open probe runs when cooldown expires.
- Defender `InitialAccess` alerts can route to the M365 identity-compromise skill.
- Added canonical taxonomy/family/subtype metadata to new findings and strict
  taxonomy validation to Hermes skills and Jev proposals.
- Jev fallback can no longer replace deterministic category, confidence, or
  severity. A transactional repair restored 4,594 rows affected by the former
  zero-confidence fallback behavior; zero affected rows remain.
- Compact list projections and on-demand details reduced a 100-finding response
  from about 722 KB to 192 KB and an All Time overview response from about
  339 KB to 53 KB. PostgreSQL calls run outside the ASGI event loop and wait for
  a bounded pool slot; 18 concurrent dashboard requests returned HTTP 200.
- Historical finding fields are inferred only for display and are marked as
  inferred; stored historical event/finding rows remain unchanged.
- Raw and filtered queues now use atomic claim/ACK, bounded retry, dead-letter,
  and restart recovery. `events.pipeline_status` makes interrupted raw processing
  resumable without rewriting completed history.
- M365 now discovers enabled subscriptions, starts only missing types with POST,
  follows bounded pagination, and persists per-content cursors.
- New M365 TIMailData records derive privacy-safe campaign/message/window keys.
  One finding links all incident members; subsequent members bypass repeat IOC
  and AI work. A temporary two-event integration test produced one finding with
  `correlation_count=2`, then removed every test row.
- Built-in syslog and normalized safe-lab scenarios now carry explicit synthetic
  provenance. A live audit found zero non-synthetic records for ransomware,
  DDoS, supply-chain, web-attack, and data-exfiltration event types, so those
  production sensor gaps remain open.
- `scripts/backfill_cve_indicators.py` adds current NVD metadata to historical
  CVE findings through dry-run-first, NVD-only, idempotent indicator upserts.
  The completed run left 0 missing candidates and 0 unavailable CVE links.
- Repeated threat-intelligence failures now open bounded provider-specific
  circuits, preserving an unavailable verdict while preventing failed APIs from
  continuously occupying the worker pool.

Validation after phase 1: smoke tests confirm all service endpoints are
reachable; dashboard health reports 7/8 healthy because Jev remote is degraded.
The audit verifier reports 92 PASS / 0 WARN / 0 FAIL; the 17-category detail audit found
data in 16 categories and correctly reported Zero-Day as zero data; Hermes queue
depth was zero; and no confidence-zero fallback findings remained. Jev remote
reasoning has produced 985 stored findings but remains intermittent, CYFIRMA
organization vulnerabilities still return HTTP 401, and those external issues
remain visible in Settings.
