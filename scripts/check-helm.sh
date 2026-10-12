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
if grep -q 'change-me' <<< "$out"; then echo "FAIL: rendered a placeholder password"; exit 1; fi
helm template t "$chart" "${kek[@]}" --set postgres.existingSecret=pact-postgres > /dev/null
helm template t "$chart" "${kek[@]}" --set database.externalUrl=postgres://db.example.com/pact > /dev/null
base=("${kek[@]}" --set postgres.password=example-only --set witness.enabled=true)
refuses "witness.keySecret.name" "${base[@]}" --set 'witness.logKeys[0]=pact.example.com/log+00000000+AA'
refuses "witness.logKeys" "${base[@]}" --set witness.keySecret.name=pact-witness-key
helm template t "$chart" "${base[@]}" --set witness.keySecret.name=pact-witness-key \
  --set 'witness.logKeys[0]=pact.example.com/log+00000000+AA' | grep -q 'name: WITNESS_LOG_KEYS'

witness_only="$(helm template t "$chart" --set gateway.enabled=false --set witness.enabled=true \
  --set witness.keySecret.name=pact-witness-key --set 'witness.logKeys[0]=pact.example.com/log+00000000+AA' \
  --set-file manifest=<(printf 'name = "Example Co"\n') --set ingress.enabled=true)"
kinds="$(grep '^kind:' <<< "$witness_only" | sort | tr '\n' ' ')"
[ "$kinds" = "kind: Deployment kind: PersistentVolumeClaim kind: Service " ] || { echo "FAIL: witness-only release renders $kinds"; exit 1; }
! grep -q -E 'open-pact-gateway|postgres|kek|t-manifest' <<< "$witness_only" || { echo "FAIL: witness-only release references the gateway"; exit 1; }
echo "a witness-only release needs no gateway or database secret and renders only the witness"

plain="$(helm template t "$chart" "${kek[@]}" --set postgres.password=example-only)"
if grep -q -E 'MANIFEST_PATH|kind: ConfigMap|checksum/manifest' <<< "$plain"; then echo "FAIL: rendered a custom manifest without one"; exit 1; fi
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
printf 'name = "Example Co"\n' > "$tmp/a.toml"
printf 'name = "Example Co 2"\n' > "$tmp/b.toml"
with_a="$(helm template t "$chart" "${kek[@]}" --set postgres.password=example-only --set-file manifest="$tmp/a.toml")"
with_b="$(helm template t "$chart" "${kek[@]}" --set postgres.password=example-only --set-file manifest="$tmp/b.toml")"
grep -q 'kind: ConfigMap' <<< "$with_a"
grep -q 'name = "Example Co"' <<< "$with_a"
grep -q 'value: /etc/open-pact/custom/manifest.toml' <<< "$with_a"
grep -q 'mountPath: /etc/open-pact/custom' <<< "$with_a"
[ "$(grep checksum/manifest <<< "$with_a")" != "$(grep checksum/manifest <<< "$with_b")" ]
echo "a custom manifest renders a ConfigMap, the mount, MANIFEST_PATH, and a checksum that changes with the text; without one, none of them"
# PostgreSQL reads the raw Secret, so the gateway must get it raw too: as PGPASSWORD, never
# inside the URL, where @ : / ? # % change how the URL parses.
password='fict@:/?#%pw'
database_env() { # rendered chart, secret name
  local out="$1" secret="$2"
  grep -q -x '              value: postgres://pact@t-postgres:5432/pact' <<< "$out" \
    || { echo "FAIL: DATABASE_URL must name no password: $(grep -A1 'name: DATABASE_URL' <<< "$out")"; exit 1; }
  ! grep -q 'DB_PASSWORD' <<< "$out" || { echo "FAIL: the password still reaches the URL"; exit 1; }
  for container in PGPASSWORD POSTGRES_PASSWORD; do
    grep -A4 "name: $container\$" <<< "$out" | tr -d ' \n' \
      | grep -q "valueFrom:secretKeyRef:name:${secret}key:password" \
      || { echo "FAIL: $container must come from Secret $secret"; exit 1; }
  done
}
created="$(helm template t "$chart" "${kek[@]}" --set-string "postgres.password=$password")"
grep -q -F "  password: \"$password\"" <<< "$created" || { echo "FAIL: the Secret must hold the raw password"; exit 1; }
database_env "$created" t-postgres
database_env "$(helm template t "$chart" "${kek[@]}" --set postgres.existingSecret=pact-postgres)" pact-postgres
echo "the gateway reads a database password with @:/?#% as PGPASSWORD from the Secret postgres uses"
echo "the witness needs its own key secret and the log keys it witnesses"
echo "renders with the KEK secret and a chosen database password, existing secret or external database"
