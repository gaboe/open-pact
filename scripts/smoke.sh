#!/usr/bin/env bash
set -euo pipefail

url="${1:?usage: smoke.sh <gateway-url>}"
url="${url%/}"
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
home="$tmp/home"

curl -fsS "$url/healthz" | grep -qx ok
echo "healthz ok"

cargo build -q --manifest-path "$root/Cargo.toml" -p open-pact-client
cargo build -q --manifest-path "$root/Cargo.toml" -p open-pact-core --example dev_claim --example dev_witness
client=("$root/target/debug/open-pact-client" --home "$home")
dev_claim="$root/target/debug/examples/dev_claim"
dev_witness="$root/target/debug/examples/dev_witness"

"${client[@]}" join --gateway "$url" --yes > "$tmp/join"
grep -q '^Enrolled as pseudonym:' "$tmp/join"
grep -q '^Transparency log verified' "$tmp/join"
echo "join: $(grep '^Enrolled' "$tmp/join")"

head_before="$("${client[@]}" log head)"
"${client[@]}" join --gateway "$url" --yes > "$tmp/rejoin"
diff <(grep '^Enrolled' "$tmp/join") <(grep '^Enrolled' "$tmp/rejoin")
[ "$head_before" = "$("${client[@]}" log head)" ]
echo "re-join is idempotent: same pseudonym, no new log entry"

"${client[@]}" log prove > "$tmp/prove"
cat "$tmp/prove"
grep -q '^INCLUDED in the checkpoint' "$tmp/prove"
grep -q '^This entry is your enrolment' "$tmp/prove"
"${client[@]}" log prove 0 | grep -q '"kind":"manifest_published"'
echo "inclusion proofs verify for this device's enrolment and for entry 0"

curl -fsS "$url/v1/log/checkpoint" | "$dev_witness" cosign > "$tmp/cosigned"
curl -fsS -X POST --data-binary "@$tmp/cosigned" "$url/v1/log/witness" | grep -q '"stored"'
curl -fsS "$url/v1/log/checkpoint" | grep -q '^— witness.example.org/demo '
code="$(curl -sS -o "$tmp/body" -w '%{http_code}' -X POST --data-binary @<(curl -fsS "$url/v1/log/checkpoint" | grep -v witness.example.org) "$url/v1/log/witness")"
[ "$code" = 403 ]
echo "witness cosignature stored and served; a checkpoint without one is refused ($code)"

code="$(curl -sS -o "$tmp/body" -w '%{http_code}' "$url/v1/log")"
[ "$code" = 410 ]
echo "old hash-chain endpoint answers 410: $(cat "$tmp/body")"

"${client[@]}" check > "$tmp/check"
cat "$tmp/check"
grep -qx ACCEPTED "$tmp/check"
grep -q '^Transparency log verified' "$tmp/check"
openssl verify -purpose sslclient -CAfile "$home/ca.pem" "$home/vpn-cert.pem"
openssl x509 -in "$home/vpn-cert.pem" -noout -ext extendedKeyUsage | grep -q 'TLS Web Client Authentication'
echo "client certificate verifies against the gateway CA"

sent_b64="$(tail -n 1 "$home/claims.jsonl" | sed -E 's/.*"sent_b64":"([^"]+)".*/\1/')"
printf '%s' "$sent_b64" | openssl base64 -d -A > "$tmp/replayed"
code="$(curl -sS -o "$tmp/body" -w '%{http_code}' -X POST -H 'content-type: application/json' --data-binary "@$tmp/replayed" "$url/v1/claim")"
echo "replayed client claim: $code $(cat "$tmp/body")"
[ "$code" = 403 ]
grep -q 'unknown or used nonce' "$tmp/body"

nonce() { curl -fsS -X POST "$url/v1/nonce" | sed -E 's/.*"nonce":"([^"]+)".*/\1/'; }
post() { curl -sS -o "$tmp/body" -w '%{http_code}' -X POST -H 'content-type: application/json' -d "{\"jws\":\"$1\"}" "$url/v1/claim"; }
expect() {
  local name="$1" status="$2" pattern="$3" jws="$4" got
  got="$(post "$jws")"
  echo "$name: $got $(cat "$tmp/body")"
  [ "$got" = "$status" ]
  grep -q "$pattern" "$tmp/body"
}

manifest="$home/manifest.toml"
device="$home/device-dev.pem"
passing=(disk_encryption=full firewall=on screen_lock=le_5min os_supported=yes)

jws="$("$dev_claim" "$device" "$manifest" "$(nonce)" linux "${passing[@]}")"
expect "compliant" 200 '"accepted"' "$jws"
expect "replay" 403 'unknown or used nonce' "$jws"

expect "unenrolled device" 403 'device not enrolled' \
  "$("$dev_claim" "$tmp/stranger.pem" "$manifest" "$(nonce)" linux "${passing[@]}")"

expect "failing check" 403 'disk_encryption = none, full required' \
  "$("$dev_claim" "$device" "$manifest" "$(nonce)" linux "${passing[@]}" disk_encryption=none)"

expect "undisclosed key" 403 'installed_apps is not in the manifest' \
  "$("$dev_claim" "$device" "$manifest" "$(nonce)" linux "${passing[@]}" installed_apps=slack)"

expect "wrong manifest" 403 'claim is for manifest' \
  "$("$dev_claim" "$device" "sha256:$(printf '0%.0s' {1..64})" "$(nonce)" linux "${passing[@]}")"

tampered="$("$dev_claim" "$device" "$manifest" "$(nonce)" linux "${passing[@]}" | awk -F. '{print $1"."$2"."substr($3,1,10)"AAAA"substr($3,15)}')"
expect "tampered signature" 403 'signature does not verify' "$tampered"

"${client[@]}" log show > "$tmp/show"
grep -q '"results"' "$tmp/show"
echo "local claim log shows what was sent"

expect_status() {
  local name="$1" want="$2" pattern="$3" got
  set +e
  "${client[@]}" check > /dev/null 2> "$tmp/err"
  got=$?
  set -e
  [ "$got" = "$want" ] || { cat "$tmp/err"; return 1; }
  grep -q "$pattern" "$tmp/err"
  echo "$name (exit $got)"
}

cp "$home/log-checkpoint.txt" "$tmp/good-checkpoint"
sed -i.bak '3s/.*/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=/' "$home/log-checkpoint.txt"
expect_status "a different root at the stored size (split view) raises the alarm" 2 'TRANSPARENCY LOG ALARM'

cp "$tmp/good-checkpoint" "$home/log-checkpoint.txt"
sed -i.bak '2s/.*/9999/' "$home/log-checkpoint.txt"
expect_status "a gateway behind the stored checkpoint (rollback) raises the alarm" 2 'TRANSPARENCY LOG ALARM'

cp "$tmp/good-checkpoint" "$home/log-checkpoint.txt"
"${client[@]}" check > /dev/null
echo "the restored checkpoint verifies again"

rm "$home/log-checkpoint.txt"
echo '{"index": 3, "hash": "00"}' > "$home/log-head.json"
expect_status "a v0.1.0 log head asks for re-join instead of an alarm" 1 'log format was upgraded'
"${client[@]}" join --gateway "$url" --yes | grep -q '^Transparency log verified'
[ ! -e "$home/log-head.json" ]
echo "join replaces the old head with a checkpoint"

echo "smoke passed"
