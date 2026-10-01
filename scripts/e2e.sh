#!/usr/bin/env bash
# deploy the testbed into the current cluster and pass only if a message makes
# the full round trip through the enrolled chain, a client holding a foreign
# anchor refuses to build one and no other pod reaches a cell port
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
for d in relay-1 relay-2 relay-3; do
  kubectl -n "$NAMESPACE" rollout status "deployment/$d" --timeout=180s
done
# enroll.sh restarts a client that already exists, so every client pod counted
# below started after the relays it reaches and the anchor that certifies them
if ! bash scripts/enroll.sh; then
  echo "enrollment failed" >&2
  kubectl -n "$NAMESPACE" get pods -o wide >&2 || true
  kubectl -n "$NAMESPACE" logs -l app=relay --prefix --tail=20 >&2 || true
  exit 1
fi
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
kubectl -n "$NAMESPACE" delete pod badca --ignore-not-found --wait=true >/dev/null
kubectl -n "$NAMESPACE" run badca --image=jimichi/client:dev --restart=Never --overrides="$overrides" >/dev/null
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

# a hardened pod that is neither a client nor a relay must not reach any cell
# port; reaching every info port shows that a refusal comes from the policy and
# not from a probe that cannot reach the relays at all
isolation() {
  local script="" code=""
  # pulled by digest on the host and loaded like the testbed images, so the
  # nodes need no registry access and run exactly this image
  docker image inspect "busybox@$PROBE_DIGEST" >/dev/null 2>&1 || docker pull -q "busybox@$PROBE_DIGEST" >/dev/null
  docker tag "busybox@$PROBE_DIGEST" "$PROBE_IMAGE"
  kind load docker-image "$PROBE_IMAGE" --name "$CLUSTER" >/dev/null
  for h in 1 2 3; do
    script="$script nc -z -w 3 relay-$h.$NAMESPACE.svc.cluster.local 9100 || exit 2;"
    script="$script if nc -z -w 3 relay-$h.$NAMESPACE.svc.cluster.local 9000; then exit 1; fi;"
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
    0) echo "isolation: cell ports closed to other pods, info ports open"; return 0 ;;
    1) echo "isolation: NOT ENFORCED, a pod that is not the previous hop reached a cell port; the network plugin of this cluster ignores the policy (kindnet needs nftables queue support in the kernel, which WSL2 lacks)" >&2 ;;
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
