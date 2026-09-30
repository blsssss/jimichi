#!/usr/bin/env bash
# deploy the testbed into the current cluster and pass only if a message makes
# the full round trip through the enrolled chain and a client holding a
# foreign anchor refuses to build one
set -euo pipefail

. "$(dirname "$0")/lib.sh"

SUITE="${SUITE:-c25519}"

kubectl apply -f deploy/base/relay.yaml
for d in relay-1 relay-2 relay-3; do
  kubectl -n "$NAMESPACE" rollout status "deployment/$d" --timeout=180s
done
# enroll.sh restarts a client that already exists, so every client pod counted
# below started after the relays it reaches and the anchor that certifies them
bash scripts/enroll.sh
kubectl apply -f deploy/base/client.yaml
kubectl -n "$NAMESPACE" rollout status deployment/client-a --timeout=180s

round_trip=""
for _ in $(seq 1 60); do
  client=$(current_pod client-a) || break
  since=$(started_at "$client")
  # only the running container counts, and only from its own start
  if [ -n "$since" ] && kubectl -n "$NAMESPACE" logs "pod/$client" --since-time="$since" 2>/dev/null | grep -Eq "round trip [1-9][0-9]* bytes"; then
    kubectl -n "$NAMESPACE" logs "pod/$client" --tail=3
    for h in 1 2 3; do
      relay=$(current_pod "relay-$h") && kubectl -n "$NAMESPACE" logs "pod/$relay" --tail=1 || true
    done
    round_trip=yes
    break
  fi
  sleep 3
done
if [ -z "$round_trip" ]; then
  echo "no round trip through the chain" >&2
  kubectl -n "$NAMESPACE" get pods -o wide >&2 || true
  kubectl -n "$NAMESPACE" logs deployment/client-a --tail=30 >&2 || true
  exit 1
fi

# the same relays, verified against the anchor of a CA that certified none of them
foreign=$("bin/jimichi$(go env GOEXE)" keygen-ca -suite "$SUITE")
nodes="relay-1.$NAMESPACE.svc.cluster.local:9000,relay-2.$NAMESPACE.svc.cluster.local:9000,relay-3.$NAMESPACE.svc.cluster.local:9000"
kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found --wait=true >/dev/null
kubectl -n "$NAMESPACE" run badca --image=jimichi/client:dev --image-pull-policy=IfNotPresent \
  --restart=Never -- -nodes "$nodes" -suite "$SUITE" -ca "$foreign" -count 1 >/dev/null
if ! kubectl -n "$NAMESPACE" wait pod/badca --for=jsonpath='{.status.phase}'=Failed --timeout=120s >/dev/null; then
  echo "a client with a foreign anchor did not fail" >&2
  kubectl -n "$NAMESPACE" logs pod/badca >&2 || true
  kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found >/dev/null
  exit 1
fi
refusal=$(kubectl -n "$NAMESPACE" logs pod/badca | grep "refusing to build the circuit" || true)
kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found >/dev/null
if [ -z "$refusal" ]; then
  echo "a client with a foreign anchor failed without refusing the chain" >&2
  exit 1
fi
echo "foreign anchor: $refusal"
