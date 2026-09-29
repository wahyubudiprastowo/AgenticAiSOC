# Agentic AI SOC Platform — Coordination Audit Report (v4)

**Status:** 72 PASS / 1 WARN (non-blocking) / 0 FAIL
**Verify anytime:** `python3 scripts/audit_verify.py`

## Summary
- v1/v2: 12 original coordination bugs fixed (skill routing tie-breaks,
  CYFIRMA feed wiring, WAZUH_MIN_LEVEL_FOR_AI dead config).
- v3: extended to 17 categories, cross-verified across skill files,
  dashboard, agents.py, jev-client.
- v4 (this revision): unique host-port scheme (+30000 offset) to
  eliminate collision with existing wazuh-mcp-unified stack, plus
  automated Section 10 port-collision audit.

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
All 9 new skills use `priority: 10` for specificity tie-breaking. APT
Activity uses genuine post-enrichment reclassification (not just
keywords). Cloud-Native/Container-K8s honestly labeled manual-ingest-only.

## Re-verify anytime
```bash
python3 scripts/audit_verify.py
```
Expected: `SUMMARY: 72 PASS, 1 WARN, 0 FAIL`. The 1 warning
(`phishing` skill's `event_types: [phishing]` has no automated
normalizer producing that literal type) is a reviewed, non-blocking
design characteristic.
