# sourced by the other scripts
NAMESPACE="${NAMESPACE:-jimichi}"

# prints the one running pod of the newest rollout of a deployment; right after a
# restart the old pods still exist, and kubectl would happily read their logs
current_pod() {
  local deploy="$1" selector hash pods
  selector=$(kubectl -n "$NAMESPACE" get deployment "$deploy" \
    -o go-template='{{range $k, $v := .spec.selector.matchLabels}}{{$k}}={{$v}},{{end}}')
  selector="${selector%,}"
  for _ in $(seq 1 60); do
    hash=$(kubectl -n "$NAMESPACE" get rs -l "$selector" \
      -o go-template='{{range .items}}{{index .metadata.annotations "deployment.kubernetes.io/revision"}} {{index .metadata.labels "pod-template-hash"}}{{"\n"}}{{end}}' \
      | sort -n | tail -1 | cut -d' ' -f2)
    pods=$(kubectl -n "$NAMESPACE" get pods -l "$selector,pod-template-hash=$hash" \
      -o go-template='{{range .items}}{{if and (eq .status.phase "Running") (not .metadata.deletionTimestamp)}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}')
    if [ -n "$pods" ] && [ "$(printf '%s\n' "$pods" | wc -l)" -eq 1 ]; then
      printf '%s\n' "$pods"
      return 0
    fi
    sleep 1
  done
  echo "no single running pod for deployment/$deploy" >&2
  return 1
}
