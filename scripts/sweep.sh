#!/usr/bin/env bash
# run the correlation sweep inside linux, where the clock is fine grained enough
# to time a round trip through the chain
set -euo pipefail

mkdir -p artifacts
docker build -q --build-arg TARGET=lab -t jimichi/lab:dev . >/dev/null
MSYS_NO_PATHCONV=1 docker run --rm   -v "$(pwd)/artifacts:/out"   jimichi/lab:dev -out /out "$@"
