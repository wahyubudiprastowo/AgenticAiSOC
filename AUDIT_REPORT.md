# Agentic AI SOC Platform — Coordination Audit Report (v4)

**Status:** 103 PASS / 0 WARN / 0 FAIL
**Verify anytime:** `python3 scripts/audit_verify.py`

## Summary
- v1/v2: 12 original coordination bugs fixed (skill routing tie-breaks,
  CYFIRMA feed wiring, WAZUH_MIN_LEVEL_FOR_AI dead config).
- v3: extended to 17 categories, cross-verified across skill files,
  dashboard, agents.py, jev-client.
- v4 (this revision): unique host-port scheme (+30000 offset) to
  eliminate collision with existing wazuh-mcp-unified stack, plus
  automated Section 10 port-collision audit.
- Resilience patch: SOC Core now persists deterministic findings before
  optional Hermes/Jev processing. Dashboard finding queries remain available
  during a Hermes outage, and Hermes enriches the same finding ID after recovery.
- Evidence validation: 14/14 testable automatic normalized categories and 2/2
  manual-ingest categories produced findings linked to their exact event UUID.
  Zero-Day remains explicitly non-testable automatically.
- IOC/CVE patch: public IP, domain, URL, hash, and CVE evidence is now linked to
  each deterministic finding with provider-level status. A live end-to-end test
  produced all five indicator types and preserved its source CVE; the synthetic
  event/finding was removed after validation.
- Historical migration added 1,242 public-IP finding links without updating or
  deleting existing event/finding rows. A pre-patch finding snapshot was compared
  after deployment and every pre-existing field remained identical.
- Delivery resilience: raw and filtered queues now use atomic claim, ACK,
  bounded retry, dead-letter handling, and restart recovery. Event completion is
  persisted before the raw queue item is acknowledged; four bounded raw workers
  prevent routine records from waiting behind slow external IOC lookups.
- M365 correctness: existing subscriptions are discovered before start calls,
  missing subscriptions use POST, content listing follows bounded `NextPageUri`
  pagination, and each content type has a durable Redis cursor plus status
  counters. OAuth and Defender Graph errors are surfaced, Graph pagination is
  host-restricted, overlapping manual/scheduled polls are serialized, and
  health is reported separately for Management Activity and Defender.
- Wazuh loss prevention: alerts, FIM, and vulnerability queries now page in
  ascending order and persist post-processing Redis cursors with a late-arrival
  overlap. Cursor updates do not modify historical database rows.
- M365 incident aggregation: new TIMailData evidence uses a hashed, bounded
  campaign/message/user-time key. All source records remain stored while one
  finding links the incident members and only its first record enters Hermes/Jev.
  Historical findings are intentionally unchanged.
- Sensor-evidence truthfulness: built-in syslog/manual safe-lab simulations are
  explicitly synthetic. The live audit found zero non-synthetic ransomware,
  DDoS, supply-chain, web-attack, or data-exfiltration event types; no production
  efficacy claim is inferred from routing tests.
- Historical CVE enrichment is additive and idempotent. The backfill is dry-run
  by default and writes only `finding_indicators`; event and finding records are
  never updated or deleted. Discovery now covers normalized event JSON and every
  category, with cache-only, category-scoped, and bounded network batches. At
  the 2026-10-02 checkpoint the database had 7,272 complete, 1,075 partial, and
  zero unavailable CVE links. The last full scan still identified 115 CVEs / 196
  links without an indicator row, so that missing-only backlog remains open.
- Live CVE enrichment reuses persisted NVD evidence for 24 hours and gives CVE
  requests enough time to wait behind NVD's serial rate limiter. A deployed
  cache probe returned complete live evidence from PostgreSQL in 0.097 seconds.
- Runtime truthfulness: Settings now separates configured, live, partial,
  stale-cache, and unavailable intelligence integrations. Upstream HTTP/auth/rate
  failures no longer appear as healthy provider results. Threat Intel service
  health is degraded when an enabled provider/feed fails, while live providers
  remain available.
- Threat Intel database resilience: concurrent feed/UI requests now use a
  bounded `ThreadedConnectionPool`; closed connections are discarded and
  rollback is attempted only on an open connection.
- Provider protection: repeated 429/auth/timeout results open a bounded
  provider-specific circuit. Calls resume after cooldown while findings retain
  an explicit unavailable result during the open interval.
- Jev recovery: events arriving during an open upstream circuit no longer reset
  its cooldown. One half-open probe is admitted after the fixed deadline. The
  2026-10-01 database snapshot contains 985 remote-reasoned findings, proving
  that remote reasoning works. Timeout budgets are now aligned at 180 seconds
  upstream and 195 seconds from Hermes; a live schema-valid probe completed in
  remote mode after the patch.
- CYFIRMA Research now ingests the vendor's public WordPress JSON feed without
  sending the private API key. The first poll persisted 25 articles. TAXII now
  supports username/token Basic auth and correct next-token pagination.
- Accuracy phase 1: one versioned registry now controls 17 stable categories and
  their subtypes across SOC Core, Hermes, Jev, dashboard, and audit validation.
  Endpoint Discovery, web-exploit subtypes, and identity-attack subtypes are no
  longer collapsed into one display label.
- Authority boundary: deterministic evidence owns category/subtype/confidence/
  severity. Jev produces an advisory verdict and cannot overwrite those fields.
  A repair restored 4,594 rows whose confidence had temporarily been set to zero
  by the old fallback path; the post-repair count is zero affected rows.
- Data visibility: All Time list responses are compact, full evidence loads from
  the detail endpoint, and PostgreSQL access now waits for an available pool slot.
  An 18-request parallel dashboard test returned 18 HTTP 200 responses with zero
  pool-exhaustion errors. No event or finding row was deleted.

## Port Collision Matrix — Verified
| Port | Service | Collides? |
|---|---|---|
| 36514 (udp+tcp) | syslog-collector | No |
| 38001 | syslog-collector API | No |
| 48200 | soc-core | No |
| 38003 | hermes | No |
| 38005 | threat-intel | No |
| 38006 | m365-collector | No |
| 36333 | qdrant | No |
| 38080 | dashboard | No |
| 35432 | postgres | No |
| 36379 | redis | No |
| (none) | jev (expose-only) | N/A |

Checked against: wazuh-manager (514/1514/1515/55000), wazuh-indexer
(9200), wazuh-dashboard (443), wazuh-main-server (3000),
wazuh-mcp-dashboard (8088), wazuh-infokom-mcp (8000), 9router (20129).
**Zero overlap confirmed.**

## Key fixes (v1/v2, 8-category era)
1. Hermes skill routing alphabetical tie-break bug — fixed with
   `priority` field for deterministic specificity.
2. Real Wazuh brute-force wording never matched original keyword list —
   fixed.
3. Fortigate port-scan misclassified as generic network_attack — fixed
   via type-inference reordering.
4. `WAZUH_MIN_LEVEL_FOR_AI` was dead config — now genuinely gates
   forwarding.
5. CYFIRMA feeds configured but unimplemented — implemented as 3
   background pollers.

## v3 additions (9 new categories, 17 total)
All 9 new skills use `priority: 10` for specificity tie-breaking. Threat-actor
reporting is now stored as an attribution dimension and never reclassifies a
different observed attack into the Threat Actor Attribution category. Cloud-Native/Container-K8s remain
honestly labeled manual-ingest-only.

## Re-verify anytime
```bash
python3 scripts/audit_verify.py
```
Expected: `SUMMARY: 103 PASS, 0 WARN, 0 FAIL`.
