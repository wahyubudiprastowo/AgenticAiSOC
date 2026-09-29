#!/usr/bin/env bash
set -euo pipefail
COLLECTOR_URL="${COLLECTOR_URL:-http://localhost:38001}"
SOC_CORE_URL="${SOC_CORE_URL:-http://localhost:48200}"
SCENARIO="${1:-vpn_bruteforce}"
run_syslog_scenario () {
  local scenario="$1"
  echo ">> Simulating: ${scenario}"
  curl -sS -X POST "${COLLECTOR_URL}/simulate" -H "Content-Type: application/json" -d "{\"scenario\": \"${scenario}\"}" | python3 -m json.tool
}
run_manual_ingest () {
  local source="$1" type="$2" description="$3" severity="$4"
  echo ">> Manual ingest: ${type}"
  curl -sS -X POST "${SOC_CORE_URL}/events/ingest" -H "Content-Type: application/json" \
    -d "{\"source\": \"${source}\", \"type\": \"${type}\", \"description\": \"${description}\", \"severity\": \"${severity}\"}" | python3 -m json.tool
}
case "${SCENARIO}" in
  all)
    for s in vpn_bruteforce malware_download port_scan linux_ssh_bruteforce ddos_attack sql_injection; do run_syslog_scenario "$s"; sleep 1; done
    run_manual_ingest "aws_cloudtrail" "cloud_alert" "AWS IAM root account UnauthorizedAccess detected" "critical"
    run_manual_ingest "k8s_audit" "k8s_alert" "Privileged container deployed with hostPath mount" "high" ;;
  cloud_native) run_manual_ingest "aws_cloudtrail" "cloud_alert" "AWS IAM root account UnauthorizedAccess detected" "critical" ;;
  container_kubernetes) run_manual_ingest "k8s_audit" "k8s_alert" "Privileged container deployed with hostPath mount" "high" ;;
  *) run_syslog_scenario "${SCENARIO}" ;;
esac
echo ">> Done. Open http://localhost:38080"
