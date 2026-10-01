#!/usr/bin/env bash
# relay counters listen on loopback inside the pod, so they are read through a
# port-forward and never through the service the clients use
set -euo pipefail

. "$(dirname "$0")/lib.sh"

STATS_PORT_BASE="${STATS_PORT_BASE:-19100}"

relay_list=$(relays)
place=0
for relay in $relay_list; do
  place=$((place + 1))
  port=$((STATS_PORT_BASE + place))
  pod=$(current_pod "$relay")
  kubectl -n "$NAMESPACE" port-forward "pod/$pod" "$port:9101" >/dev/null 2>&1 &
  pid=$!
  for _ in $(seq 1 50); do
    curl -s "localhost:$port/stats" >/dev/null 2>&1 && break
    sleep 0.1
  done
  printf '%s %s\n' "$relay" "$(curl -s "localhost:$port/stats")"
  kill "$pid" 2>/dev/null || true
done
