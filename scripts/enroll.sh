#!/usr/bin/env bash
# certify the running relays under a fresh CA and hand its anchor to the
# clients; the CA key exists only inside this one run of jimichi enroll, and
# every relay restart needs this script again
set -euo pipefail

. "$(dirname "$0")/lib.sh"

SUITE="${SUITE:-c25519}"
CERT_TTL="${CERT_TTL:-72h}"

mkdir -p bin
jimichi="bin/jimichi$(go env GOEXE)"
go build -o "$jimichi" ./cmd/jimichi

forwards=()
cleanup() {
  for pid in "${forwards[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

args=(-suite "$SUITE" -cert-ttl "$CERT_TTL")
for h in 1 2 3; do
  pod=$(current_pod "relay-$h")
  admin=$((19200 + h))
  info=$((19300 + h))
  # the admin port listens on loopback inside the pod, so only a port-forward
  # through the kube API reaches it
  kubectl -n "$NAMESPACE" port-forward "pod/$pod" "$admin:9101" "$info:9100" >/dev/null 2>&1 &
  forwards+=("$!")
  args+=(-node "relay-$h=relay-$h.$NAMESPACE.svc.cluster.local:9000,admin=127.0.0.1:$admin,info=127.0.0.1:$info")
done

# no mlock or prctl on a Windows host: the CA key sits unlocked for the
# seconds of the run, jimichi enroll warns about it
case "$(uname -s)" in
  MINGW* | MSYS*) args+=(-keymem zero -harden=false) ;;
esac

anchor=$("$jimichi" enroll "${args[@]}")
kubectl -n "$NAMESPACE" create configmap jimichi-ca --from-literal=anchor="$anchor" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
echo "anchor $anchor"

# a client keeps the anchor it started with, so it restarts onto the new one
if kubectl -n "$NAMESPACE" get deployment client-a >/dev/null 2>&1; then
  kubectl -n "$NAMESPACE" rollout restart deployment/client-a >/dev/null
fi
