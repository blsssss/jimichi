#!/usr/bin/env bash
# deploy the testbed into the current cluster and pass only if a message makes
# the full round trip through the chain
set -euo pipefail

. "$(dirname "$0")/lib.sh"

kubectl apply -f deploy/base/relay.yaml
for d in relay-1 relay-2 relay-3; do
  kubectl -n "$NAMESPACE" rollout status "deployment/$d" --timeout=180s
done
kubectl apply -f deploy/base/client.yaml
# a client started while the relays were still rolling may have built its circuit
# through the old ones; a fresh one can only reach the relays that are up now
kubectl -n "$NAMESPACE" rollout restart deployment/client-a
kubectl -n "$NAMESPACE" rollout status deployment/client-a --timeout=180s

for _ in $(seq 1 60); do
  client=$(current_pod client-a) || break
  since=$(started_at "$client")
  # only the running container counts, and only from its own start
  if [ -n "$since" ] && kubectl -n "$NAMESPACE" logs "pod/$client" --since-time="$since" 2>/dev/null | grep -Eq "round trip [1-9][0-9]* bytes"; then
    kubectl -n "$NAMESPACE" logs "pod/$client" --tail=3
    for h in 1 2 3; do
      relay=$(current_pod "relay-$h") && kubectl -n "$NAMESPACE" logs "pod/$relay" --tail=1 || true
    done
    exit 0
  fi
  sleep 3
done

echo "no round trip through the chain" >&2
kubectl -n "$NAMESPACE" get pods -o wide >&2 || true
kubectl -n "$NAMESPACE" logs deployment/client-a --tail=30 >&2 || true
exit 1
