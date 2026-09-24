#!/usr/bin/env bash
# deploy the testbed into the current cluster and pass only if a message makes
# the full round trip through the chain
set -euo pipefail

NAMESPACE="${NAMESPACE:-jimichi}"

kubectl apply -f deploy/base/relay.yaml
for d in relay-1 relay-2 relay-3; do
  kubectl -n "$NAMESPACE" rollout status "deployment/$d" --timeout=180s
done
kubectl apply -f deploy/base/client.yaml
kubectl -n "$NAMESPACE" rollout status deployment/client-a --timeout=180s

for _ in $(seq 1 60); do
  # an empty reply means the circuit died, which must not count as a pass
  if kubectl -n "$NAMESPACE" logs deployment/client-a --tail=20 2>/dev/null | grep -Eq "round trip [1-9][0-9]* bytes"; then
    kubectl -n "$NAMESPACE" logs deployment/client-a --tail=3
    for h in 1 2 3; do
      kubectl -n "$NAMESPACE" logs "deployment/relay-$h" --tail=1
    done
    exit 0
  fi
  sleep 3
done

echo "no round trip through the chain" >&2
kubectl -n "$NAMESPACE" get pods -o wide >&2
kubectl -n "$NAMESPACE" logs deployment/client-a --tail=30 >&2 || true
exit 1
