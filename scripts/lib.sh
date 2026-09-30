# sourced by the other scripts
NAMESPACE="${NAMESPACE:-jimichi}"

# prints the one running pod of the newest rollout of a deployment; right after a
# restart the old pods still exist, and kubectl would happily read their logs
current_pod() {
  local deploy="$1" selector hash pods
  selector=$(kubectl -n "$NAMESPACE" get deployment "$deploy" \
    -o go-template='{{range $k, $v := .spec.selector.matchLabels}}{{$k}}={{$v}},{{end}}')
  selector="${selector%,}"
  [ -n "$selector" ] || { echo "no deployment/$deploy" >&2; return 1; }
  for _ in $(seq 1 60); do
    hash=$(kubectl -n "$NAMESPACE" get rs -l "$selector" \
      -o go-template='{{range .items}}{{$rs := .}}{{range .metadata.ownerReferences}}{{if eq .name "'"$deploy"'"}}{{index $rs.metadata.annotations "deployment.kubernetes.io/revision"}} {{index $rs.metadata.labels "pod-template-hash"}}{{"\n"}}{{end}}{{end}}{{end}}' \
      | sort -n | tail -1 | cut -d' ' -f2)
    pods=$(kubectl -n "$NAMESPACE" get pods -l "$selector,pod-template-hash=$hash" \
      -o go-template='{{range .items}}{{if and (eq .status.phase "Running") (not .metadata.deletionTimestamp)}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}')
    if [ -n "$hash" ] && [ -n "$pods" ] && [ "$(printf '%s\n' "$pods" | wc -l)" -eq 1 ]; then
      printf '%s\n' "$pods"
      return 0
    fi
    sleep 1
  done
  echo "no single running pod for deployment/$deploy" >&2
  return 1
}

# when the running container of a pod started, on the cluster clock
started_at() {
  kubectl -n "$NAMESPACE" get pod "$1" -o jsonpath='{.status.containerStatuses[0].state.running.startedAt}'
}
