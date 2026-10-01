#!/usr/bin/env bash
# relay counters listen on loopback inside the pod, so they are read through a
# port-forward and never through the service the clients use
set -euo pipefail

. "$(dirname "$0")/lib.sh"

STATS_PORT_BASE="${STATS_PORT_BASE:-19100}"

for h in 1 2 3; do
  port=$((STATS_PORT_BASE + h))
  pod=$(current_pod "relay-$h")
  kubectl -n "$NAMESPACE" port-forward "pod/$pod" "$port:9101" >/dev/null 2>&1 &
  pid=$!
  for _ in $(seq 1 50); do
    curl -s "localhost:$port/stats" >/dev/null 2>&1 && break
    sleep 0.1
  done
  printf 'relay-%s %s\n' "$h" "$(curl -s "localhost:$port/stats")"
  kill "$pid" 2>/dev/null || true
done
