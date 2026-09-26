#!/usr/bin/env bash
# run the correlation sweep inside linux, where the clock is fine grained enough
# to time a round trip through the chain
set -euo pipefail

mkdir -p artifacts
docker build -q --build-arg TARGET=lab -t jimichi/lab:dev . >/dev/null
# untracked sources go into the image too, so they make the revision dirty
sources="go.mod go.sum client cmd crypto lab link relay vault web wire"
rev="$(git rev-parse --short HEAD)"
if [ -n "$(git status --porcelain --untracked-files=normal -- $sources)" ]; then rev="$rev-dirty"; fi
MSYS_NO_PATHCONV=1 docker run --rm   -v "$(pwd)/artifacts:/out"   jimichi/lab:dev -out /out -rev "$rev" "$@"
