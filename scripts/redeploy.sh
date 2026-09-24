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

kubectl -n "$NAMESPACE" rollout restart deployment/relay-1 deployment/relay-2 deployment/relay-3 deployment/client-a >/dev/null 2>&1 || true
bash scripts/e2e.sh
