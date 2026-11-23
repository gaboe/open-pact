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
# An unset database.maxConnections (a release upgraded with --reuse-values) renders no env entry, so the binary default applies.
unset_max="$(helm template t "$chart" "${kek[@]}" --set postgres.password=example-only --set database.maxConnections=null)"
! grep -q 'name: DATABASE_MAX_CONNECTIONS' <<< "$unset_max" || { echo "FAIL: rendered DATABASE_MAX_CONNECTIONS without a value"; exit 1; }
echo "omits DATABASE_MAX_CONNECTIONS when database.maxConnections is unset"
set_max="$(helm template t "$chart" "${kek[@]}" --set postgres.password=example-only --set database.maxConnections=25)"
grep -A1 'name: DATABASE_MAX_CONNECTIONS' <<< "$set_max" | grep -q 'value: "25"' || { echo "FAIL: database.maxConnections=25 did not render as \"25\""; exit 1; }
echo "renders DATABASE_MAX_CONNECTIONS as \"25\" when database.maxConnections is 25"
echo "the gateway reads a database password with @:/?#% as PGPASSWORD from the Secret postgres uses"
# Metrics are off by default. On, they need a token and a certificate, get their own port and
# Service, and never reach the Ingress.
! grep -q -E 'METRICS_|9090|gateway-metrics' <<< "$plain" || { echo "FAIL: metrics rendered while off"; exit 1; }
grep -q -A1 'name: SLOW_REQUEST_MS' <<< "$plain" || { echo "FAIL: the slow request log has no value"; exit 1; }
metrics_on=("${kek[@]}" --set postgres.password=example-only --set metrics.enabled=true)
refuses "metrics.tokenSecret.name" "${metrics_on[@]}" --set metrics.tlsSecret.name=pact-metrics-tls
refuses "metrics.tlsSecret.name" "${metrics_on[@]}" --set metrics.tokenSecret.name=pact-metrics-token
metrics_args=("${metrics_on[@]}" --set metrics.tokenSecret.name=pact-metrics-token --set metrics.tlsSecret.name=pact-metrics-tls --set ingress.enabled=true)
with_metrics="$(helm template t "$chart" "${metrics_args[@]}")"
document() { awk -v kind="$1" 'BEGIN { RS = "\n---\n" } $0 ~ ("\nkind: " kind "\n") { print }' <<< "$2"; }
metrics_service="$(document Service "$with_metrics" | grep -A12 'name: t-gateway-metrics')"
grep -q 'port: 9090' <<< "$metrics_service" && grep -q 'targetPort: metrics' <<< "$metrics_service" && grep -q 'type: ClusterIP' <<< "$metrics_service" \
  || { echo "FAIL: no separate ClusterIP Service for the metrics port: $metrics_service"; exit 1; }
public_service="$(awk 'BEGIN { RS = "\n---\n" } /\nkind: Service\n/ && /\n  name: t-gateway\n/ { print }' <<< "$with_metrics")"
grep -q 'port: 80$' <<< "$public_service" || { echo "FAIL: found no public Service: $public_service"; exit 1; }
! grep -q -E '9090|metrics' <<< "$public_service" || { echo "FAIL: the public Service exposes the metrics port"; exit 1; }
! document Ingress "$with_metrics" | grep -q -i -E 'metrics|9090' || { echo "FAIL: the Ingress reaches the metrics port"; exit 1; }
grep -q 'containerPort: 9090' <<< "$with_metrics"
grep -q -A1 'name: METRICS_ADDR' <<< "$with_metrics"
grep -A5 'name: METRICS_TOKEN' <<< "$with_metrics" | tr -d ' \n' | grep -q 'secretKeyRef:name:pact-metrics-tokenkey:token' \
  || { echo "FAIL: METRICS_TOKEN must come from the token Secret"; exit 1; }
grep -A3 'name: metrics-tls' <<< "$with_metrics" | grep -q 'secretName: pact-metrics-tls'
grep -B1 -A2 'mountPath: /etc/open-pact/metrics-tls' <<< "$with_metrics" | grep -q 'readOnly: true' \
  || { echo "FAIL: the TLS Secret is not mounted read-only"; exit 1; }
! grep -q 'kind: NetworkPolicy' <<< "$with_metrics" || { echo "FAIL: a NetworkPolicy without sources"; exit 1; }
policy="$(helm template t "$chart" "${metrics_args[@]}" \
  --set 'metrics.networkPolicy.from[0].podSelector.matchLabels.app=prometheus' | awk 'BEGIN { RS = "\n---\n" } /kind: NetworkPolicy/')"
[ "$(grep -c 'port: ' <<< "$policy")" = 2 ] && grep -q 'app: prometheus' <<< "$policy" \
  || { echo "FAIL: unexpected NetworkPolicy: $policy"; exit 1; }
# The public rule has no "from": every source reaches 8080. Only the metrics rule is limited.
[ "$(grep -c 'from:' <<< "$policy")" = 1 ] && grep -B1 -A3 'port: 8080' <<< "$policy" | head -1 | grep -q 'ports:' \
  || { echo "FAIL: the public port is limited: $policy"; exit 1; }
echo "metrics are off by default; on, they need a token and a TLS Secret, get their own Service, and stay out of the Ingress; a NetworkPolicy limits only the metrics port"
echo "the witness needs its own key secret and the log keys it witnesses"
echo "renders with the KEK secret and a chosen database password, existing secret or external database"
fresh="$(helm template t "$chart" "${kek[@]}" --set postgres.password=example-only)"
grep -q 'storage: 20Gi' <<< "$fresh" || { echo "FAIL: a fresh install does not get a 20Gi Postgres volume"; exit 1; }
compact="$(tr -d ' \n' <<< "$fresh")"
grep -q 'limits:memory:512Mirequests:cpu:100mmemory:256Mi' <<< "$compact" || { echo "FAIL: Postgres resources are not the default"; exit 1; }
echo "a fresh install gets a 20Gi Postgres volume and the default Postgres resources"
grep -A1 'name: NONCE_MAX_PER_WINDOW' <<< "$plain" | grep -q '"3000"' || { echo "FAIL: NONCE_MAX_PER_WINDOW is not 3000"; exit 1; }
echo "a fresh render sets NONCE_MAX_PER_WINDOW to 3000"
