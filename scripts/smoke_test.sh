#!/usr/bin/env bash
set -uo pipefail
declare -A SERVICES=(
  ["syslog-collector"]="http://localhost:38001/health"
  ["soc-core"]="http://localhost:48200/health"
  ["hermes"]="http://localhost:38003/health"
  ["threat-intel"]="http://localhost:38005/health"
  ["m365-collector"]="http://localhost:38006/health"
  ["dashboard"]="http://localhost:38080/health"
  ["qdrant"]="http://localhost:36333/collections"
)
FAILED=0
for name in "${!SERVICES[@]}"; do
  url="${SERVICES[$name]}"
  if curl -sf "$url" > /dev/null; then echo "REACHABLE ${name}"; else echo "UNREACHABLE ${name} (${url})"; FAILED=1; fi
done
if [[ "$FAILED" -eq 0 ]]; then
  echo "All configured endpoints are reachable. Check /api/health for degraded dependencies."
else
  echo "Some endpoints are unreachable. Check: docker compose logs -f <service>"
fi
exit $FAILED
