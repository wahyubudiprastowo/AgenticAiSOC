# Security Notes — READ BEFORE DEPLOYING

Your `.env` contains **live credentials** shared in chat. Action items:

## 1. Rotate these credentials
| Credential | Why |
|---|---|
| `SOC_SMTP_PASSWORD` | Real mailbox password |
| `M365_CLIENT_SECRET` / `DEFENDER_XDR_CLIENT_SECRET` | Real Entra app secret |
| `DASHBOARD_ACCESS_TOKEN` | Dashboard access token |

## 2. Verify not a copy-paste mistake
`THREATFOX_API_KEY`, `URLHAUS_API_KEY`, `ABUSEIPDB_API_KEY` are identical strings — confirm each is correct.

## 3. New unique ports (v4) — firewall implications
All host ports moved to 3xxxx-4xxxx range. If you have an external
firewall, open the NEW ports (36514 udp/tcp for syslog, 38080 for
dashboard), not the old ones.

## 4. Syslog port change — device reconfiguration required
Moving syslog to port 36514 means external devices (Fortigate/routers)
currently pointed at port 514 will NOT automatically reach this
platform (port 514 belongs to wazuh-manager). Add a SECOND syslog
destination on each device: `<host-ip>:36514` (dual-send, keep the
existing `:514` entry too).

## 5. /events/ingest endpoint
No authentication in this MVP (port 48200). Internal use only — do not
expose to the public internet.

## 6. General hygiene
- `chmod 600 .env`
- Re-run `python3 scripts/audit_verify.py` after any config change
  (expect: 72 PASS / 1 WARN / 0 FAIL)
