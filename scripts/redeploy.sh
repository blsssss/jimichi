#!/usr/bin/env bash
# rebuild the images, push them into kind and verify the chain still works
set -euo pipefail

CLUSTER="${CLUSTER:-jimichi}"
NAMESPACE="${NAMESPACE:-jimichi}"

go vet ./...
go test ./...

docker build -q --build-arg TARGET=relay -t jimichi/relay:dev . >/dev/null
docker build -q --build-arg TARGET=client -t jimichi/client:dev . >/dev/null
kind load docker-image jimichi/relay:dev jimichi/client:dev --name "$CLUSTER" >/dev/null

kubectl apply -f deploy/base/relay.yaml >/dev/null
kubectl apply -f deploy/base/client.yaml >/dev/null
kubectl -n "$NAMESPACE" rollout restart deployment/relay-1 deployment/relay-2 deployment/relay-3 deployment/client-a >/dev/null
for d in relay-1 relay-2 relay-3 client-a; do
  kubectl -n "$NAMESPACE" rollout status "deployment/$d" --timeout=120s >/dev/null
done

echo "waiting for a round trip through the chain"
for _ in $(seq 1 30); do
  if kubectl -n "$NAMESPACE" logs deployment/client-a --tail=20 2>/dev/null | grep -q "round trip"; then
    kubectl -n "$NAMESPACE" logs deployment/client-a --tail=3 | grep "round trip"
    exit 0
  fi
  sleep 2
done

echo "no round trip observed, dumping state" >&2
kubectl -n "$NAMESPACE" get pods >&2
kubectl -n "$NAMESPACE" logs deployment/client-a --tail=20 >&2
exit 1
