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

# the client is restarted by e2e.sh once the relays are up
kubectl -n "$NAMESPACE" rollout restart deployment -l app=relay >/dev/null 2>&1 || true
bash scripts/e2e.sh
