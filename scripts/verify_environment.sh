#!/usr/bin/env bash
set -uo pipefail
ENV_FILE="${1:-.env}"
if [[ -f "$ENV_FILE" ]]; then set -a; source "$ENV_FILE"; set +a; fi
FAILED=0
echo "== Network check =="
if docker network inspect "${WAZUH_DOCKER_NETWORK:-single-node_default}" > /dev/null 2>&1; then echo "OK network found"
else echo "FAIL network not found"; FAILED=1; fi
echo "== Port checks (unique v4 scheme) =="
for p in 36514 38001 48200 38003 38005 38006 36333 38080 35432 36379; do
  if ss -ltn "( sport = :$p )" 2>/dev/null | grep -q ":$p"; then echo "FAIL port $p in use"; FAILED=1; else echo "OK port $p free"; fi
done
exit $FAILED
