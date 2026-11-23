#!/usr/bin/env bash
# A chart upgrade must keep an existing Postgres volume: same size, same rows, pod Ready again.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
new_chart="$root/deploy/helm/open-pact"
tmp="$(mktemp -d)"
name="pact-upgrade-$$"
cleanup() {
  kind delete cluster --name "$name" --kubeconfig "$tmp/kubeconfig" > /dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

command -v helm > /dev/null || brew install helm
command -v kind > /dev/null || brew install kind

# The chart as it is on origin/main, so the upgrade starts from what users have installed.
git -C "$root" archive origin/main deploy/helm/open-pact | tar -x -C "$tmp"
old_chart="$tmp/deploy/helm/open-pact"

kind create cluster --name "$name" --kubeconfig "$tmp/kubeconfig" --wait 180s
export KUBECONFIG="$tmp/kubeconfig"

kubectl create secret generic pact-gateway-kek --from-literal=kek="$(openssl rand -base64 32)"
values=(--set gateway.kekSecret.name=pact-gateway-kek --set postgres.password=example-only)

helm install pact "$old_chart" "${values[@]}"
kubectl rollout status statefulset/pact-postgres --timeout=300s
kubectl exec pact-postgres-0 -- psql -U pact -d pact -v ON_ERROR_STOP=1 \
  -c "create table upgrade_check (v text); insert into upgrade_check values ('kept');"

pvc_size() { kubectl get pvc data-pact-postgres-0 -o jsonpath='{.spec.resources.requests.storage}'; }
before="$(pvc_size)"
[ "$before" = 5Gi ] || { echo "FAIL: the origin/main chart made a $before volume, expected 5Gi"; exit 1; }

helm upgrade pact "$new_chart" "${values[@]}"
kubectl rollout status statefulset/pact-postgres --timeout=300s

after="$(pvc_size)"
[ "$after" = "$before" ] || { echo "FAIL: the volume went from $before to $after"; exit 1; }
rows="$(kubectl exec pact-postgres-0 -- psql -U pact -d pact -tA -v ON_ERROR_STOP=1 -c "select v from upgrade_check")"
[ "$rows" = kept ] || { echo "FAIL: the row is gone, psql printed '$rows'"; exit 1; }
echo "the upgrade kept the $after volume and its row, and the Postgres pod is Ready again"
