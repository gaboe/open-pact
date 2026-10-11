#!/usr/bin/env bash
# The chart must refuse to render without the secrets a deployment has to choose itself.
set -euo pipefail
chart="${CHART:-$(cd "$(dirname "$0")/.." && pwd)/deploy/helm/open-pact}"
kek=(--set gateway.kekSecret.name=pact-gateway-kek)

refuses() {
  local why="$1"; shift
  if out="$(helm template t "$chart" "$@" 2>&1)"; then
    echo "FAIL: rendered without $why"; exit 1
  fi
  grep -q "$why" <<< "$out" || { echo "FAIL: unexpected error: $out"; exit 1; }
  echo "refuses without $why"
}

refuses "gateway.kekSecret.name" --set postgres.password=example-only
refuses "postgres.password or postgres.existingSecret" "${kek[@]}"

out="$(helm template t "$chart" "${kek[@]}" --set postgres.password=example-only)"
grep -q 'name: pact-gateway-kek' <<< "$out"
! grep -q 'change-me' <<< "$out"
helm template t "$chart" "${kek[@]}" --set postgres.existingSecret=pact-postgres > /dev/null
helm template t "$chart" "${kek[@]}" --set database.externalUrl=postgres://db.example.com/pact > /dev/null
echo "renders with the KEK secret and a chosen database password, existing secret or external database"
