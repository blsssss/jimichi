#!/usr/bin/env bash
# deploy the testbed into the current cluster and pass only if a message makes
# the full round trip through a chain drawn among the enrolled relays, a client
# holding a foreign anchor refuses to build one, each client asked one relay
# alone for descriptors and no other pod reaches a cell port
set -euo pipefail

. "$(dirname "$0")/lib.sh"

SUITE="${SUITE:-c25519}"
CLUSTER="${CLUSTER:-jimichi}"
REQUIRE_ISOLATION="${REQUIRE_ISOLATION:-${CI:-false}}"
PROBE_IMAGE="busybox:1.37.0"
# the linux/amd64 manifest, not the multi-platform index: kind load cannot import
# an index whose other platforms were never pulled
PROBE_DIGEST="sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4"

kubectl apply -f deploy/base/relay.yaml -f deploy/base/network.yaml
relay_list=$(relays)
relay_count=$(printf '%s\n' "$relay_list" | awk 'END { print NR }')
for relay in $relay_list; do
  kubectl -n "$NAMESPACE" rollout status "deployment/$relay" --timeout=180s
done
# a client left from an earlier run would ask a relay while the counts below
# are taken, so it goes now and comes back once they are; every client pod
# counted below then started after the relays it reaches and the anchor that
# certifies them
kubectl -n "$NAMESPACE" delete deployment client-a --ignore-not-found --wait=true >/dev/null
kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found --wait=true >/dev/null
for _ in $(seq 1 60); do
  [ -z "$(kubectl -n "$NAMESPACE" get pods -l app=client -o name 2>/dev/null)" ] && break
  sleep 2
done
if ! bash scripts/enroll.sh; then
  echo "enrollment failed" >&2
  kubectl -n "$NAMESPACE" get pods -o wide >&2 || true
  kubectl -n "$NAMESPACE" logs -l app=relay --prefix --tail=20 >&2 || true
  exit 1
fi

# one counter of one relay out of the lines scripts/stats.sh prints
counter() {
  printf '%s\n' "$1" | sed -n "s/^$2 .*\"$3\":\([0-9][0-9]*\).*/\1/p"
}

# one counter of every relay as one line, in the order of the list; fails when
# the pass lacks a relay
column() {
  local relay value out=""
  for relay in $relay_list; do
    value=$(counter "$1" "$relay" "$2")
    [ -n "$value" ] || return 1
    out="$out $value"
  done
  printf '%s\n' "${out# }"
}

# the relays whose counter is higher in the second column than in the first
grown() {
  local before after relay place=0 out=""
  read -r -a before <<<"$1"
  read -r -a after <<<"$2"
  for relay in $relay_list; do
    if [ "${after[$place]}" -gt "${before[$place]}" ]; then out="$out $relay"; fi
    place=$((place + 1))
  done
  printf '%s\n' "${out# }"
}

# one pass of scripts/stats.sh that shows every relay, or nothing
stats_pass() {
  local out
  for _ in $(seq 1 10); do
    out=$(bash scripts/stats.sh 2>/dev/null || true)
    if column "$out" mirror_requests >/dev/null; then
      printf '%s\n' "$out"
      return 0
    fi
    sleep 2
  done
  return 1
}

# how many times the container of client-a has started
client_starts() {
  local pod restarts
  pod=$(current_pod client-a) || return 1
  restarts=$(kubectl -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.status.containerStatuses[0].restartCount}')
  echo $((restarts + 1))
}

# a relay fetches the descriptor of each roster peer once and again only at
# half of its life. Two passes in a row that show every relay with all its
# peers and the same counts of descriptor requests mean those fetches are over:
# a single pass could be read while the last relay is still asking. From here
# the requests a relay answers for its own descriptor stay as they are unless a
# client asks it
all_peers=""
for relay in $relay_list; do all_peers="$all_peers $((relay_count - 1))"; done
all_peers="${all_peers# }"
settled=""
asked=""
for _ in $(seq 1 30); do
  stats=$(bash scripts/stats.sh 2>/dev/null || true)
  seen=""
  if [ "$(column "$stats" peers || true)" = "$all_peers" ]; then
    seen=$(column "$stats" descriptor_requests || true)
  fi
  if [ -n "$seen" ] && [ "$seen" = "$asked" ]; then
    settled=yes
    break
  fi
  asked="$seen"
  sleep 2
done
if [ -z "$settled" ]; then
  echo "the relays did not settle with the descriptors of their $((relay_count - 1)) roster peers" >&2
  bash scripts/stats.sh >&2 || true
  kubectl -n "$NAMESPACE" logs -l app=relay --prefix --tail=20 >&2 || true
  exit 1
fi
mirror_0=$(column "$stats" mirror_requests)

kubectl apply -f deploy/base/client.yaml
kubectl -n "$NAMESPACE" rollout status deployment/client-a --timeout=180s

round_trip=""
for _ in $(seq 1 60); do
  client=$(current_pod client-a) || break
  since=$(started_at "$client")
  # only the running container counts, and only from its own start
  if [ -n "$since" ] && kubectl -n "$NAMESPACE" logs "pod/$client" --since-time="$since" 2>/dev/null | grep -Eq "round trip [1-9][0-9]* bytes"; then
    kubectl -n "$NAMESPACE" logs "pod/$client" --tail=3
    for relay in $relay_list; do
      pod=$(current_pod "$relay") && kubectl -n "$NAMESPACE" logs "pod/$pod" --tail=1 || true
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

# every start of a client draws one entry and asks that relay alone for the
# descriptors of all listed nodes, so between two passes the requests for the
# mirror grow at one relay per client start and at no other. The starts are
# read after the counters: a restart in between only widens the bound
entries_of() {
  local what="$1" before="$2" after="$3" starts="$4" entries count
  entries=$(grown "$before" "$after")
  count=$(printf '%s\n' "$entries" | awk '{ print NF }')
  if [ "$count" -lt 1 ] || [ "$count" -gt "$starts" ]; then
    echo "$what started $starts time(s) and $count relays answered a request for the descriptors, want one per start: ${entries:-none}" >&2
    echo "requests for the descriptors per relay before: $before" >&2
    echo "requests for the descriptors per relay after:  $after" >&2
    return 1
  fi
  printf '%s\n' "$entries"
}

stats=$(stats_pass) || { echo "no counters from the relays after the round trip" >&2; exit 1; }
mirror_1=$(column "$stats" mirror_requests)
starts_1=$(client_starts)
entry_a=$(entries_of client-a "$mirror_0" "$mirror_1" "$starts_1")

# the same relays, verified against the anchor of a CA that certified none of them
foreign=$("bin/jimichi$(go env GOEXE)" keygen-ca -suite "$SUITE")
nodes=""
for relay in $relay_list; do nodes="$nodes,$(relay_addr "$relay")"; done
nodes="${nodes#,}"
# the pod runs under the same restrictions as client-a, so its refusal is the
# one a real client gives; the overrides replace the whole container
overrides=$(cat <<JSON
{
  "apiVersion": "v1",
  "spec": {
    "securityContext": {"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
    "containers": [{
      "name": "badca",
      "image": "jimichi/client:dev",
      "imagePullPolicy": "IfNotPresent",
      "args": ["-nodes", "$nodes", "-suite", "$SUITE", "-ca", "$foreign", "-count", "1"],
      "securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}}
    }]
  }
}
JSON
)
kubectl -n "$NAMESPACE" run badca --image=jimichi/client:dev --restart=Never --overrides="$overrides" >/dev/null
if ! kubectl -n "$NAMESPACE" wait pod/badca --for=jsonpath='{.status.phase}'=Failed --timeout=120s >/dev/null; then
  echo "a client with a foreign anchor did not fail" >&2
  kubectl -n "$NAMESPACE" logs pod/badca >&2 || true
  kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found >/dev/null
  exit 1
fi
refusal=$(kubectl -n "$NAMESPACE" logs pod/badca | grep "refusing to build the circuit" | grep "certificate from an unknown CA" || true)
if [ -z "$refusal" ]; then
  echo "a client with a foreign anchor failed without refusing the chain for its unknown CA" >&2
  kubectl -n "$NAMESPACE" logs pod/badca >&2 || true
  kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found >/dev/null
  exit 1
fi
kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found >/dev/null
echo "foreign anchor: $refusal"

# the refused client ran once and asked one relay as well, and no relay
# answered a request for its own descriptor since the counts taken before the
# clients: a client asks no node for a descriptor of that node alone
stats=$(stats_pass) || { echo "no counters from the relays after the clients" >&2; exit 1; }
mirror_2=$(column "$stats" mirror_requests)
starts_2=$(client_starts)
entry_refused=$(entries_of "the refused client, with client-a restarting $((starts_2 - starts_1)) time(s)," "$mirror_1" "$mirror_2" "$((1 + starts_2 - starts_1))")
asked_after=$(column "$stats" descriptor_requests)
if [ "$asked_after" != "$asked" ]; then
  echo "a relay answered a request for its own descriptor after the relays had settled: a client asked a node other than through the descriptors of its entry" >&2
  echo "descriptor requests per relay before the clients: $asked" >&2
  echo "descriptor requests per relay after the clients:  $asked_after" >&2
  printf '%s\n' "$stats" >&2
  exit 1
fi
echo "entry only: client-a asked $entry_a for the descriptors, the refused client $entry_refused, and no relay was asked for its own descriptor"

# a hardened pod that is neither a client nor a relay must not reach any cell
# port; reaching every info port shows that a refusal comes from the policy and
# not from a probe that cannot reach the relays at all
isolation() {
  local script="" code="" relay host
  # pulled by digest on the host and loaded like the testbed images, so the
  # nodes need no registry access and run exactly this image
  docker image inspect "busybox@$PROBE_DIGEST" >/dev/null 2>&1 || docker pull -q "busybox@$PROBE_DIGEST" >/dev/null
  docker tag "busybox@$PROBE_DIGEST" "$PROBE_IMAGE"
  kind load docker-image "$PROBE_IMAGE" --name "$CLUSTER" >/dev/null
  for relay in $relay_list; do
    host="$relay.$NAMESPACE.svc.cluster.local"
    script="$script nc -z -w 3 $host 9100 || exit 2;"
    script="$script if nc -z -w 3 $host 9000; then exit 1; fi;"
  done
  kubectl -n "$NAMESPACE" delete pod isolation-probe --ignore-not-found --wait=true >/dev/null
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: isolation-probe
  namespace: $NAMESPACE
  labels: {app: probe}
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: probe
      image: $PROBE_IMAGE
      imagePullPolicy: Never
      command: ["sh", "-c", "$script"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        requests: {cpu: 10m, memory: 8Mi}
        limits: {cpu: 100m, memory: 32Mi}
EOF
  for _ in $(seq 1 60); do
    code=$(kubectl -n "$NAMESPACE" get pod isolation-probe \
      -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)
    [ -n "$code" ] && break
    sleep 2
  done
  kubectl -n "$NAMESPACE" delete pod isolation-probe --ignore-not-found --wait=false >/dev/null
  case "$code" in
    0) echo "isolation: the cell ports of $relay_count relays closed to other pods, info ports open"; return 0 ;;
    1) echo "isolation: NOT ENFORCED, a pod that is neither a client nor a relay reached a cell port; the network plugin of this cluster ignores the policy (kindnet needs nftables queue support in the kernel, which WSL2 lacks)" >&2 ;;
    2) echo "isolation: the probe reached no info port, so it proves nothing" >&2 ;;
    *) echo "isolation: the probe did not finish" >&2 ;;
  esac
  # CI runs on a kernel that enforces the policy, so there a failed probe fails
  # the run; a development host may lack the support and only gets the warning
  [ "$REQUIRE_ISOLATION" = "true" ] && return 1
  echo "isolation: not required here (REQUIRE_ISOLATION=$REQUIRE_ISOLATION), continuing" >&2
  return 0
}

isolation
