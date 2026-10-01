# Attack Details maturity audit — updated 2026-10-01

## Scope and method

This audit checked all 17 taxonomy categories against the live PostgreSQL data,
the `/api/findings/{id}` source-linked detail endpoint, and the rendered browser
UI. Counts below are a 2026-09-30 08:19 UTC snapshot and continue increasing.
Synthetic provenance is resolved from the linked source event as well as its
explicit coverage marker; existing records were not deleted or rewritten.
New TIMailData collected after the 2026-10-01 aggregation deployment links
campaign/message/window members to one finding and displays its incident count.
Historical one-record findings remain unchanged to preserve evidence history.

The normalized pipeline has one 100%-complete, explicitly synthetic validation
finding for every testable category (16/16). Zero-Day remains intentionally not
testable as an unknown-unknown. That result proves routing, persistence, and UI
rendering. It does not establish production sensor efficacy.

## Live category maturity

| Category | Findings | Tagged synthetic | Non-test data | IOC-linked findings | Latest non-test evidence | Material gap |
|---|---:|---:|---:|---:|---|---|
| Malware | 19 | 5 | 14 | 5 | Source evidenced, 100% applicable fields | Low structured artifact/hash coverage |
| Ransomware | 4 | 4 | 0 | 0 | Validation only | No production/source-sensor evidence |
| Phishing | 86,619 | 4 | 86,615 | 25,023 | Source evidenced, 100% | Most older rows predate structured IOC persistence |
| Credential Theft | 23,703 | 4 | 23,699 | 3 | Source evidenced, 100% | Most login evidence has private IP/user context rather than an external IOC |
| Network Intrusion | 2,882 | 4 | 2,878 | 2,725 | Source evidenced, 100% | Path is still based on individual events, not a correlated chain |
| Reconnaissance | 2,780 | 4 | 2,776 | 160 | Partial, 71% | Endpoint Discovery often has destination context but no remote source/action |
| Vulnerability | 189 | 4 | 185 | Snapshot predates backfill | Source evidenced, contextual path, CVE present | Source patch state still requires endpoint validation; NVD metadata is reference data |
| File Integrity | 868 | 4 | 864 | 0 | Partial, 86% | Latest row has no acting user; local FIM context has no remote origin by design |
| Supply Chain | 4 | 4 | 0 | 0 | Validation only | No production package/dependency evidence |
| DDoS | 4 | 4 | 0 | 0 | Validation only | No production Fortigate DoS evidence |
| Web Application Attack | 5 | 5 | 0 | 0 | Validation only | No production WAF/IPS evidence |
| Insider Threat | 496 | 4 | 492 | 163 | Source evidenced, 100% | Behavioral baseline and incident aggregation are not shown |
| Data Exfiltration | 4 | 4 | 0 | 0 | Validation only | No production Purview DLP evidence |
| Threat Actor Attribution | 6 | 4 | 2 | 2 | Source evidenced, 100% | Provider attribution remains context, not campaign proof |
| Zero-Day | 0 | 0 | 0 | 0 | Not testable automatically | Requires anomaly/process review; no guarantee is supportable |
| Cloud-Native | 12 | 4 | 8 | 0 | Partial, 88% in latest audit | Manual API ingestion; no native AWS/Azure collector |
| Container/Kubernetes | 5 | 4 | 1 | 0 | Partial, 50% | Manual API ingestion; no native audit collector |

## What the Attack Details page now states clearly

- Attack path separates source IP, source identity/sender, destination asset or
  account, and destination IP. Vulnerability and FIM rows use contextual paths
  when an attacker origin is not expected.
- Classification shows Attack type, Action, User, CVE, CVE status, Category,
  Source system, normalized type, detection rule, attack family/subtype,
  evidence quality, attribution status, and AI verdict/mode.
- New findings display stored canonical subtypes. Legacy rows derive a
  conservative subtype at read time and explicitly label it as a display-name
  match or category default; the database row is not silently rewritten.
- Evidence quality labels each applicable field as `observed`, `missing`, or
  `not applicable`, reports a completeness percentage, and distinguishes
  production telemetry from synthetic validation.
- Every single-event detail warns that it is event context rather than a
  correlated multi-stage attack chain.
- Direct links to a finding load the requested detail immediately while the
  heavier global overview queries continue in the background.
- Global presets persist in the browser. Filters change only the query scope and
  do not remove events/findings. Full evidence is fetched only for the opened
  finding, keeping All Time lists responsive.

The browser audit inspected production Vulnerability, Credential Theft,
Phishing, and Network Intrusion findings. All required sections and fields were
rendered. The production Vulnerability example correctly showed CVE-2026-32075,
the affected asset, package condition, CVSS source value, and contextual
source/action/user states.

## CVE and IOC integration status

Future Vulnerability and Zero-Day events now enter IOC enrichment at every
severity. NVD API 2.0 is connected through the existing Threat Intel service and
persists per-finding metadata in `finding_indicators`: CVSS score/version/severity,
NVD status, CISA KEV state, weaknesses, publication/modification times, and an
explicit patch-reference flag. A live check of CVE-2024-3400 returned NVD mode
`live`, CVSS 10.0 critical, CISA KEV listed, and OTX live evidence.

Historical synchronization completed on 2026-10-01. The dry-run found 161
distinct candidate CVEs and 187 missing finding/CVE links. The additive job
inserted the first 3 links, then 184 remaining links. Eight temporarily
unavailable NVD responses were retried with an explicit cache bypass and all
completed. Final dry-runs report 0 normal candidates and 0 unavailable retry
candidates; the database has 166 distinct structured CVE indicators including
existing/current rows, with 0 CVE links in `unavailable` state. NVD's patch tag
is shown as a reference, not as proof that the affected endpoint installed a fix.

## Review of the supplied scripts

- `cve_sync_service.py` passes its mock self-test, but its reconciliation reads
  classifier JSONL and only writes a report. It does not reconcile this
  platform's PostgreSQL findings or `finding_indicators`.
- `multi_source_log_classifier.py` cannot run in this repository because
  `rule_detection_engine` is absent. Its schema differs from the active source
  normalizers, and each process owns an isolated in-memory correlation state.
  Installing it as a second classifier would risk duplicate findings and broken
  thresholds.
- The supplied coverage validator is older than the repository validator. It
  searches by marker text; the active version additionally verifies the exact
  database event UUID, expected category, provenance, and Attack Details fields.

## Remaining priority order

1. Replace generic recommendations with category- and evidence-specific actions.
2. Add source-level tests for Ransomware, Supply Chain, DDoS, Web Application
   Attack, Data Exfiltration, and Threat Actor Attribution, which currently
   have only synthetic or unconfirmed production data.
3. Add native CloudTrail/Azure and Kubernetes audit collectors.
4. Build multi-event correlation before calling the displayed context an attack
   chain.

The subtype split is complete: external scanning, network-service scanning, and
endpoint/account/process/network/WMI Discovery remain under a stable parent but
have distinct analyst-facing labels. Web and credential attack subtypes are also
separated in the same registry.
