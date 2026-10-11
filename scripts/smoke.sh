#!/usr/bin/env bash
set -euo pipefail

url="${1:?usage: smoke.sh <gateway-url>}"
url="${url%/}"
root="$(cd "$(dirname "$0")/.." && pwd)"
manifest="$root/examples/manifest.toml"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsS "$url/healthz" | grep -qx ok
echo "healthz ok"

cargo build -q --manifest-path "$root/Cargo.toml" -p open-pact-client
cargo build -q --manifest-path "$root/Cargo.toml" -p open-pact-core --example dev_claim
client="$root/target/debug/open-pact-client"
dev_claim="$root/target/debug/examples/dev_claim"

out="$("$client" --gateway "$url" --manifest "$manifest" --dev-key "$tmp/device-dev.pem" check || true)"
echo "client: $out"
echo "$out" | grep -Eq '"status":"(accepted|denied)"'
echo "client check got a decision"

nonce() { curl -fsS -X POST "$url/v1/nonce" | sed -E 's/.*"nonce":"([^"]+)".*/\1/'; }
post() { curl -sS -o "$tmp/body" -w '%{http_code}' -X POST -H 'content-type: application/json' -d "{\"jws\":\"$1\"}" "$url/v1/claim"; }
expect() {
  local name="$1" status="$2" pattern="$3" jws="$4" got
  got="$(post "$jws")"
  echo "$name: $got $(cat "$tmp/body")"
  [ "$got" = "$status" ]
  grep -q "$pattern" "$tmp/body"
}

passing=(disk_encryption=full firewall=on screen_lock=le_5min os_supported=yes)

jws="$("$dev_claim" "$manifest" "$(nonce)" linux "${passing[@]}")"
expect "compliant" 200 '"accepted"' "$jws"
expect "replay" 403 'unknown or used nonce' "$jws"

expect "failing check" 403 'disk_encryption = none, full required' \
  "$("$dev_claim" "$manifest" "$(nonce)" linux "${passing[@]}" disk_encryption=none)"

expect "undisclosed key" 403 'installed_apps is not in the manifest' \
  "$("$dev_claim" "$manifest" "$(nonce)" linux "${passing[@]}" installed_apps=slack)"

expect "wrong manifest" 403 'claim is for manifest' \
  "$("$dev_claim" "sha256:$(printf '0%.0s' {1..64})" "$(nonce)" linux "${passing[@]}")"

tampered="$("$dev_claim" "$manifest" "$(nonce)" linux "${passing[@]}" | awk -F. '{print $1"."$2"."substr($3,1,10)"AAAA"substr($3,15)}')"
expect "tampered signature" 403 'signature does not verify' "$tampered"

echo "smoke passed"
