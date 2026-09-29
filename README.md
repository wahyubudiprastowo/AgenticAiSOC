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
python3 scripts/audit_verify.py      # expect: 75 PASS / 0 WARN / 0 FAIL
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
from producing a false PASS.

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

Every checked indicator is linked to the deterministic finding in
`finding_indicators`, including its provider results, confidence, verdict reason,
and one of these enrichment states: `complete`, `partial`, `stale_cache`, or
`unavailable`. Attack Details shows the same structured evidence. Provider
failures never become clean or malicious mock verdicts when mock mode is off.
The Settings page reports tested runtime state per provider and IOC type; an API
key being configured is not presented as proof that the provider is live.

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

`database/backfill_finding_indicators.sql` can be run repeatedly to add
historical public-IP links without changing existing findings or events. New
events are linked automatically.

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
| 11 | SQL Injection | Fortigate WAF/IPS | Automated |
| 12 | Insider Threat | M365 mass-download ops | Automated |
| 13 | Data Exfiltration | Microsoft Purview DLP | Automated |
| 14 | APT Activity | OTX/ThreatFox attribution | Automated |
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
    ├── audit_verify.py             # 10 sections, 75 checks
    ├── verify_environment.sh
    ├── smoke_test.sh
    └── simulate_events.sh
```

## Known scope limits
ServiceNow, automatic firewall blocking, IAM automation, live
Azure/AWS/K8s collectors (manual ingest available) — out of scope;
every Jev output is advisory only.
# AgenticAiSOC
