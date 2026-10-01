# Agentic AI SOC Platform — Unique Ports (v4) + 17 Detection Categories

Full-stack Agentic AI SOC covering 17 attack detection categories across
Syslog, Wazuh, M365/Defender XDR, and 6+ Threat Intelligence providers
→ Two-Tier Filtering → Hermes Orchestrator (20 skills covering 17 categories) → Jev (9router)
Reasoning → Qdrant memory → Visual Dashboard.

## Quick start
```bash
chmod 600 .env
./scripts/verify_environment.sh
docker compose up -d --build
./scripts/smoke_test.sh
python3 scripts/audit_verify.py      # expect: 92 PASS / 0 WARN / 0 FAIL
./scripts/simulate_events.sh all
```
Open **http://localhost:38080** for the dashboard.

## Port Scheme (v4) — Unique Host Ports, Zero Collision

| Service | New unique host port |
|---|---|
| Syslog Collector (UDP+TCP) | **36514** |
| Syslog Collector API | **38001** |
| SOC Core API | **48200** |
| Hermes API | **38003** |
| Threat Intel API | **38005** |
| M365 Collector API | **38006** |
| Qdrant | **36333** |
| Dashboard | **38080** |
| Postgres | **35432** |
| Redis | **36379** |
| Jev (AI reasoning) | not published (internal only) |

Zero overlap with your existing wazuh-manager(514/1514/1515/55000),
wazuh-indexer(9200), wazuh-dashboard(443), wazuh-main-server(3000),
wazuh-mcp-dashboard(8088), wazuh-infokom-mcp(8000), 9router(20129).

Only HOST-side ports changed. Internal container ports are UNCHANGED
(dashboard → `http://soc-core:18200` still works via Docker DNS,
independent of host mapping) — verified automatically by
`scripts/audit_verify.py` Section 1.

## Global dashboard history and exact time ranges

Open the dashboard at `http://localhost:38080`. The **Global Scope**
toolbar applies the same time, severity, category, and timeline bucket
to both **Overview** and **Attack Details**. It queries PostgreSQL on
the server and supports **1 hour,
24 hours, 7 days, 30 days, 1 year, all time**, or a custom start/end
date and time. The timeline can be grouped by hour, day, week, month,
or year. Search inside Attack Details further narrows the current global
scope; findings load 100 at a time.

The selected preset is retained in browser storage. Choosing another preset
only changes the query scope; it never deletes PostgreSQL rows. List endpoints
return compact finding/event summaries, while `/api/findings/{id}` loads the
complete source evidence, IOC provider results, and AI result on demand. SOC
Core runs synchronous PostgreSQL work in FastAPI's worker pool and queues brief
connection bursts (`SOC_DB_POOL_*`), so an All Time refresh does not block
health and detail requests.

The **Settings** menu provides a read-only inventory of the active runtime
configuration, grouped by Wazuh, syslog, SOC pipeline, Hermes/AI,
M365/Defender, threat intelligence, and storage. It also shows live service
latency, Hermes worker/queue state, and the 20 loaded detection skills. Secret
values are never returned by the settings API. Persistent changes remain in
`.env`; recreate the affected service after editing it.

Service health refreshes in the browser every 15 seconds. Each probe retries
once, and a brief timeout after a successful probe is shown as `recovering`
for `DASHBOARD_HEALTH_GRACE_SECONDS` rather than as a false outage. The current
probe timeout is controlled by `DASHBOARD_HEALTH_TIMEOUT_SECONDS`.

Browser-local custom times are converted to ISO/UTC before they are
sent to the API. The end timestamp is inclusive. Example:

```bash
curl --get http://localhost:38080/api/findings/search \
  --data-urlencode 'start=2026-09-29T01:00:00Z' \
  --data-urlencode 'end=2026-09-29T02:00:00Z' \
  --data-urlencode 'limit=100'

curl --get http://localhost:38080/api/findings/analytics \
  --data-urlencode 'start=2026-09-01T00:00:00Z' \
  --data-urlencode 'end=2026-09-30T23:59:59Z' \
  --data-urlencode 'bucket=day'
```

## Evidence-based detection coverage validation

`scripts/validate_detection_coverage.py` validates a finding against the exact
database event UUID returned by SOC Core. A category passes only when the
finding links that UUID, has the expected deterministic category, and contains the
unique test marker in its evidence. This prevents an unrelated recent finding
from producing a false PASS. It also loads the dashboard detail endpoint and
checks the category-specific Attack Path plus Attack type, Action, User, CVE,
CVE Status, Category, and Source system. Vulnerability and local FIM tests treat
a remote source IP as contextual/not applicable instead of inventing one.

Set up the isolated validator dependencies and review all payloads first:

```bash
python3 -m venv .venv
.venv/bin/pip install -r scripts/requirements-coverage.txt
.venv/bin/python scripts/validate_detection_coverage.py \
  --matrix Coverage_Matrix_17_Kategori_Serangan.xlsx \
  --init-matrix --dry-run
```

Run the live normalized-pipeline validation:

```bash
.venv/bin/python scripts/validate_detection_coverage.py \
  --matrix Coverage_Matrix_17_Kategori_Serangan.xlsx \
  --soc-core-url http://localhost:48200 \
  --dashboard-url http://localhost:38080 \
  --timeout 60 --interval 2
```

Outputs are written to `reports/coverage/`, plus
`Coverage_Matrix_17_Kategori_Serangan.validated.xlsx`. The current verified
result is **14/14 testable automated normalized categories PASS**, **2/2
manual-ingest categories PASS**, and **Zero-Day not testable automatically**.
The companion AI-enrichment audit confirms all 16 testable findings reached
`complete` while retaining the same event UUID, finding ID, and evidence marker.

This test proves normalized ingestion, deterministic finding persistence, and
traceability. The report records whether optional AI enrichment is still pending
or complete. It does not prove source-sensor efficacy. Fortigate, Wazuh,
M365, Defender, Purview, and threat-intelligence collectors still require
separate source-level tests using safe lab events and real parser output.

## Finding resilience when AI services are unavailable

SOC Core stores a deterministic finding before an event enters the Hermes queue.
The finding is immediately available to Overview and Attack Details with
`analysis_status=pending_ai`. Hermes later enriches that same finding and changes
the status to `complete`; it does not create a second finding. Dashboard finding
queries use SOC Core, so a Hermes, Jev, Qdrant, or threat-intelligence outage does
not hide already stored findings. Existing rows are preserved by additive schema
changes and are treated as complete.

SOC Core owns the canonical category, subtype, confidence, and severity. Hermes
may add evidence and Jev may return an advisory verdict, but fallback or remote
AI cannot overwrite those canonical values. When the remote Jev provider is
unavailable, `ai_verdict=unavailable` and `ai_reasoning_mode=fallback` remain
visible instead of being presented as successful remote reasoning.
Jev's upstream circuit uses a fixed cooldown: traffic received while it is open
does not extend the deadline. After cooldown, one half-open probe tests the
remote provider; success closes the circuit and failure starts a new cooldown.
The health response exposes `circuit_state` and `retry_after_seconds`.

Raw and filtered Redis queues use atomic claim-to-processing moves, explicit
ACK, bounded retry, dead-letter queues, and startup recovery of unacknowledged
items. `SOC_RAW_EVENT_WORKERS` bounds concurrent raw-event consumers; provider
fan-out remains independently bounded by `SOC_IOC_ENRICH_WORKERS` and
`INTEL_PROVIDER_WORKERS`. Queue depth, in-flight count, and dead-letter count
are exposed in the service statistics endpoints.

## Canonical taxonomy and historical findings

`config/detection_taxonomy.yaml` is the versioned registry used by SOC Core,
Hermes, Jev, and the dashboard. The 17 IDs remain stable dashboard buckets;
precise behavior is stored in `attack_family` and `attack_subtype`. This
separates endpoint Discovery from external scanning, splits web attacks into
SQL injection/XSS/path traversal/command injection/RFI, and separates identity
attack subtypes such as brute force, spraying, dumping, pass-the-hash, OAuth
abuse, and privilege changes. Threat-actor attribution is supporting context
and cannot replace the detected attack type.

Legacy findings are not rewritten. Attack Details derives a conservative
family/subtype at read time and labels its origin as `category_default` or
`classification_display_match`; new rows use `subtype_origin=stored`.

## Structured IOC and CVE synchronization

For security-relevant events, SOC Core extracts up to
`SOC_MAX_IOCS_PER_EVENT` public indicators from normalized source evidence:
public IP addresses, domains, URLs, MD5/SHA-1/SHA-256 hashes, and CVE IDs.
Private/reserved addresses and the platform's transport `raw_hash` are excluded
from external lookups. Provider checks run concurrently with bounded workers so
one event cannot create an unbounded request fan-out. The process-wide limits
are `SOC_IOC_ENRICH_WORKERS` for SOC-to-intel calls and
`INTEL_PROVIDER_WORKERS` for outbound provider calls; they remain fixed even
when multiple collector loops process events at the same time.

Repeated provider failures open a per-provider circuit after
`INTEL_PROVIDER_CIRCUIT_FAILURE_THRESHOLD` failures for
`INTEL_PROVIDER_CIRCUIT_COOLDOWN_SECONDS`. An open circuit remains an explicit
`unavailable` result and is never converted to a clean IOC verdict. NVD and the
locally cached CYFIRMA feed retain their dedicated rate/cache controls.

Every checked indicator is linked to the deterministic finding in
`finding_indicators`, including its provider results, confidence, verdict reason,
and one of these enrichment states: `complete`, `partial`, `stale_cache`, or
`unavailable`. Attack Details shows the same structured evidence. Provider
failures never become clean or malicious mock verdicts when mock mode is off.
The Settings page reports tested runtime state per provider and IOC type; an API
key being configured is not presented as proof that the provider is live.

CVE indicators are checked against NVD API 2.0 and OTX. The persisted NVD
provider evidence includes CVSS version/score/severity, NVD status, published
and modified times, CISA KEV state, weakness IDs, and whether NVD carries an
explicit patch-tagged reference. `NVD_ENABLED=true` works without a key at the
public rate limit; set `NVD_API_KEY` to use an issued NVD key. A patch reference
is supporting evidence, not proof that the affected asset has been patched.

CVE values are evidence fields, so the platform does not invent one for events
that do not contain a CVE. Attack Details distinguishes:

- `observed_in_source_event`: a CVE was present in the linked source evidence.
- `missing_from_vulnerability_source`: a vulnerability event arrived without a
  CVE and its parser/source needs review.
- `not_reported_by_source`: CVE evidence can be relevant to this attack type,
  but the linked source event did not provide one.
- `not_applicable_to_event_type`: CVE identification is not normally applicable
  to the event type, such as a failed login or mailbox operation.

Attack Details always labels the **Attack path** explicitly and separates source
IP, source identity/sender, destination asset/account, and destination IP. Local
FIM and vulnerability inventory records are shown as contextual paths because
they may have no remote attacker IP. Findings generated by the coverage
validator are marked **Synthetic coverage validation**, so intentionally sparse
test payloads are not confused with production telemetry.

The **Evidence quality and limitations** card evaluates each finding separately.
It reports source-evidence maturity, completeness across fields applicable to
that category, observed/missing/not-applicable fields, path status, and explicit
limitations. A single linked event is presented as event context and is not
claimed to be a correlated multi-stage attack chain.

`database/backfill_finding_indicators.sql` can be run repeatedly to add
historical public-IP links. `scripts/backfill_cve_indicators.py` performs a
dry-run by default, groups historical evidence by CVE, requests only NVD through
the local Threat Intel service, and idempotently upserts `finding_indicators`
with `--apply`. Neither backfill updates or deletes source events/findings:

```bash
sudo docker compose exec -T soc-core \
  python /app/scripts/backfill_cve_indicators.py
sudo docker compose exec -T soc-core \
  python /app/scripts/backfill_cve_indicators.py --apply
```

New events are linked automatically. NVD's public rate limit is enforced across
the Threat Intel process; `NVD_API_KEY` can be set to use an issued higher quota.
The 2026-10-01 historical run reconciled all 161 candidate CVEs (187
finding/CVE links); both the normal and unavailable-retry dry-runs now return
zero candidates.

## M365 collection correctness

The collector reads `subscriptions/list` first, accepts already-enabled content
types as healthy, and sends `POST subscriptions/start` only for missing types.
Content collection follows bounded `NextPageUri` pagination and stores a Redis
cursor per content type with a small overlap for late-arriving records. Errors,
page/blob counts, subscription state, and last poll status are visible at
`http://localhost:38006/stats`.

New actionable `TIMailData` records are correlated before repeat AI processing.
The key preference is campaign ID, network-message ID, internet-message ID, then
a hashed sender/recipient/subject fingerprint inside
`M365_INCIDENT_WINDOW_SECONDS`. Every raw record remains in `events`; the first
record creates the finding and later records append to that finding's
`event_ids` and increment `correlation_count`, capped at
`M365_INCIDENT_MAX_LINKED_EVENTS` linked details. Historical findings are not
merged or deleted.

## Safe-lab evidence versus production evidence

Built-in simulation endpoints and `scripts/simulate_events.sh` now mark every
generated event with `is_synthetic_test=true` and a test marker. Use the bounded
safe-lab coverage set with:

```bash
./scripts/simulate_events.sh sensor_coverage
```

This checks ransomware, DDoS, supply-chain, web-attack, and data-exfiltration
routing without performing containment or a real attack. It proves parser and
pipeline behavior only. The 2026-10-01 database audit found zero non-synthetic
events for these five target event types, so production sensor efficacy remains
unproven until sanitized sensor output or an approved lab trigger is ingested.

## Syslog Port Forwarding — Reconfiguration Required

Moving the syslog port does NOT automatically redirect any network
device's log stream. `wazuh-manager` already owns host port `514`. Any
Fortigate/router/switch currently pointed at `<host-ip>:514` will keep
going to wazuh-manager ONLY.

**Action required:** add a SECOND syslog server destination on each
device: `<host-ip>:36514` (keep the existing `:514` entry too — most
enterprise gear supports multiple simultaneous syslog destinations).

Verify: `curl http://localhost:38001/stats` — "received" counter
should increase once a real device is sending to port 36514.

## All 17 Detection Categories

These are **17 top-level dashboard buckets**, not an exhaustive list of all
possible attacks. The platform currently loads 20 Hermes skills and stores
MITRE ATT&CK technique/sub-technique IDs beneath those buckets. A log being
ingested does not automatically mean it is an attack: routine or unsupported
events remain stored events without a finding until a rule, correlation, or
evidence-backed skill matches. Current source-level gaps and overlap are
documented in `reports/pipeline_audit_20260929.md`.

| # | Category | Mechanism | Status |
|---|---|---|---|
| 1 | Malware | Fortigate AV / Wazuh / Defender | Automated |
| 2 | Ransomware | Wazuh behavioural rules | Automated |
| 3 | Phishing | M365 inbox-rule/OAuth ops | Automated |
| 4 | Credential Theft | Syslog + Wazuh + AzureAD | Automated |
| 5 | Network Intrusion | Fortigate/Wazuh IPS attack signals | Automated |
| 6 | Reconnaissance | Fortigate port-scan | Automated |
| 7 | Vulnerability | Wazuh vuln-detector / CYFIRMA | Automated |
| 8 | File Integrity | Wazuh FIM | Automated |
| 9 | Supply Chain | Wazuh FIM package-manager paths | Automated |
| 10 | DDoS | Fortigate DoS sensor | Automated |
| 11 | Web Application Attack | Fortigate WAF/IPS | Automated; subtype distinguishes SQLi/XSS/traversal/command injection/RFI |
| 12 | Insider Threat | M365 mass-download ops | Automated |
| 13 | Data Exfiltration | Microsoft Purview DLP | Automated |
| 14 | Threat Actor Attribution | OTX/ThreatFox attribution evidence | Automated context; not proof of an APT campaign |
| 15 | Zero-Day | Wazuh unfixed + CYFIRMA | Probabilistic / manual review |
| 16 | Cloud-Native | Manual `/events/ingest` | Manual only |
| 17 | Container/Kubernetes | Manual `/events/ingest` | Manual only |

## Manual Ingestion (Cloud-Native & K8s)
```bash
curl -X POST http://localhost:48200/events/ingest -H "Content-Type: application/json" \
  -d '{"source":"aws_cloudtrail","type":"cloud_alert","description":"AWS IAM root UnauthorizedAccess","severity":"critical"}'
curl -X POST http://localhost:48200/events/ingest -H "Content-Type: application/json" \
  -d '{"source":"k8s_audit","type":"k8s_alert","description":"Privileged container hostPath mount","severity":"high"}'
```

## Project layout
```
agentic-soc-platform/
├── AUDIT_REPORT.md, SECURITY_NOTES.md
├── docker-compose.yml   # v4: unique host ports
├── .env
├── syslog-collector/     # port 36514(udp/tcp) + 38001(api)
├── soc-core/              # host 48200, internal 18200 unchanged
├── m365-collector/          # host 38006
├── hermes/app/skills/         # 20 skills covering 17 categories
├── jev-client/                  # internal only
├── threat-intel/                 # host 38005
├── dashboard/                      # host 38080
├── database/init.sql
├── prompts/
└── scripts/
    ├── audit_verify.py             # 11 sections, 92 checks
    ├── verify_environment.sh
    ├── smoke_test.sh
    └── simulate_events.sh
```

## Known scope limits
ServiceNow, automatic firewall blocking, IAM automation, live
Azure/AWS/K8s collectors (manual ingest available) — out of scope;
every Jev output is advisory only.
# AgenticAiSOC
