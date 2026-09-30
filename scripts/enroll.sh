#!/usr/bin/env bash
# certify the running relays under a fresh CA and hand its anchor to the
# clients; the CA key exists only inside this one run of jimichi enroll, and
# every relay restart needs this script again
set -euo pipefail

. "$(dirname "$0")/lib.sh"

SUITE="${SUITE:-c25519}"
CERT_TTL="${CERT_TTL:-72h}"
ADMIN_PORT_BASE="${ADMIN_PORT_BASE:-19200}"
INFO_PORT_BASE="${INFO_PORT_BASE:-19300}"

mkdir -p bin
jimichi="bin/jimichi$(go env GOEXE)"
go build -o "$jimichi" ./cmd/jimichi

logs=$(mktemp -d)
forwards=()
cleanup() {
  local status=$?
  for pid in "${forwards[@]}"; do kill "$pid" 2>/dev/null || true; done
  if [ "$status" -ne 0 ]; then
    for f in "$logs"/*.log; do
      [ -e "$f" ] && { echo "--- $(basename "$f" .log) port-forward" >&2; cat "$f" >&2; }
    done
  fi
  rm -rf "$logs"
}
trap cleanup EXIT

# kubectl prints one line per local port once it listens; waiting for them
# keeps enroll from racing the forward
wait_forward() {
  local pid="$1" log="$2"
  shift 2
  for _ in $(seq 1 150); do
    kill -0 "$pid" 2>/dev/null || { echo "port-forward $(basename "$log" .log) exited" >&2; return 1; }
    local ready=yes
    for port in "$@"; do
      grep -q "Forwarding from 127.0.0.1:$port " "$log" || ready=""
    done
    [ -n "$ready" ] && return 0
    sleep 0.1
  done
  echo "port-forward $(basename "$log" .log) did not come up" >&2
  return 1
}

# the pin comes from the relay's own log, read through the kube API, so a
# request signed by any other key is refused however it reaches the forwarded
# port; the relay prints the line once, before it serves, so anything but one
# match means the wrong container or a log that is not there yet
identity_of() {
  local pod="$1" found count
  for _ in $(seq 1 10); do
    found=$(kubectl -n "$NAMESPACE" logs "pod/$pod" -c relay 2>/dev/null |
      sed -n 's/.* identity_hash=\([0-9a-f]\{64\}\) .*/\1/p')
    count=$(printf '%s\n' "$found" | awk 'NF { n++ } END { print n + 0 }')
    if [ "$count" -eq 1 ]; then
      printf '%s\n' "$found"
      return 0
    fi
    sleep 1
  done
  echo "pod/$pod: $count identity_hash lines in the log of its current container, want exactly one" >&2
  return 1
}

args=(-suite "$SUITE" -cert-ttl "$CERT_TTL" -namespace "$NAMESPACE")
for h in 1 2 3; do
  pod=$(current_pod "relay-$h")
  kubectl -n "$NAMESPACE" wait --for=condition=Ready "pod/$pod" --timeout=120s >/dev/null
  identity=$(identity_of "$pod")
  admin=$((ADMIN_PORT_BASE + h))
  info=$((INFO_PORT_BASE + h))
  log="$logs/relay-$h.log"
  # the admin port listens on loopback inside the pod, so only a port-forward
  # through the kube API reaches it
  kubectl -n "$NAMESPACE" port-forward --address 127.0.0.1 "pod/$pod" "$admin:9101" "$info:9100" >"$log" 2>&1 &
  forwards+=("$!")
  wait_forward "$!" "$log" "$admin" "$info"
  args+=(-node "relay-$h=relay-$h.$NAMESPACE.svc.cluster.local:9000,admin=127.0.0.1:$admin,info=127.0.0.1:$info,identity=$identity")
done
for pid in "${forwards[@]}"; do
  kill -0 "$pid" 2>/dev/null || { echo "a port-forward exited before enrollment" >&2; exit 1; }
done

# no mlock or prctl on a Windows host: the CA key sits unlocked while it
# issues the certificates, jimichi enroll warns about it
case "$(uname -s)" in
  MINGW* | MSYS*) args+=(-keymem zero -harden=false) ;;
esac

# a relay takes one certificate per process, so after a failure every relay
# that holds one, from this run or an earlier one, must restart first
if ! anchor=$("$jimichi" enroll "${args[@]}"); then
  echo "enrollment failed; a relay that holds a valid certificate takes a new one only after a restart:" >&2
  echo "  kubectl -n $NAMESPACE rollout restart deployment/relay-1 deployment/relay-2 deployment/relay-3" >&2
  echo "then run scripts/enroll.sh again" >&2
  exit 1
fi
kubectl -n "$NAMESPACE" create configmap jimichi-ca --from-literal=anchor="$anchor" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
echo "anchor $anchor"

# a client keeps the anchor it started with, so it restarts onto the new one
if kubectl -n "$NAMESPACE" get deployment client-a >/dev/null 2>&1; then
  kubectl -n "$NAMESPACE" rollout restart deployment/client-a >/dev/null
fi
