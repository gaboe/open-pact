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

# OPEN_PACT_ADMIN runs the gateway admin CLI elsewhere, e.g. "kubectl exec -i deploy/pact-gateway -- open-pact-gateway".
if [ -n "${OPEN_PACT_ADMIN:-}" ]; then
  read -ra admin_cmd <<< "$OPEN_PACT_ADMIN"
else
  admin_cmd=(docker compose -f "$root/compose.yaml" exec -T gateway open-pact-gateway)
fi
admin() { "${admin_cmd[@]}" "$@"; }
invite() { admin invite --url "$url" --ttl 1h --note "$1" 2> /dev/null; }
# Rewrites one field of an invitation; "flip" changes the last character of the current value.
tamper() {
  python3 - "$@" <<'PY'
import base64, json, sys
inv, field, value = sys.argv[1:]
body = inv.removeprefix("opi1:")
j = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
if value == "flip":
    value = j[field][:-1] + ("0" if j[field][-1] != "0" else "1")
j[field] = value
print("opi1:" + base64.urlsafe_b64encode(json.dumps(j).encode()).decode().rstrip("="))
PY
}
run_status() {
  set +e
  "$@" > "$tmp/out" 2>&1
  local got=$?
  set -e
  echo "$got"
}

inv="$(invite "smoke owner")"
[[ "$inv" == opi1:* ]]
echo "invitation created: ${inv:0:24}..."

got="$(run_status "${client[@]}" join "$(tamper "$inv" company flip)" --yes --software-key)"
[ "$got" = 1 ] || { cat "$tmp/out"; exit 1; }
grep -q 'is not the gateway in your invitation: the company key differs' "$tmp/out"
[ ! -e "$home/company-key.txt" ]
[ ! -e "$home/log-key.txt" ]
[ ! -e "$home/enrolment.json" ]
echo "an invitation with another company key fingerprint is refused before anything is sent or pinned"

got="$(run_status "${client[@]}" join "$(tamper "$inv" gateway http://pact.example.com)" --yes --software-key)"
[ "$got" = 1 ]
grep -q 'refusing plain http://' "$tmp/out"
echo "plain http to a remote gateway is refused"

"${client[@]}" join "$inv" --yes --software-key > "$tmp/join"
grep -q '^Gateway keys match the invitation' "$tmp/join"
grep -q '^Enrolled as pseudonym:' "$tmp/join"
grep -q '^Transparency log verified' "$tmp/join"
grep -q '^Inclusion proofs verified: the manifest you signed (#0) and your enrolment' "$tmp/join"
code="$(sed -nE 's/^Waiting for IT approval. Read this device code to IT: ([0-9a-f]{12})$/\1/p' "$tmp/join")"
[ -n "$code" ]
echo "join with the untouched invitation: $(grep '^Enrolled' "$tmp/join"), pending, device code $code"

got="$(run_status "${client[@]}" check)"
[ "$got" = 1 ]
grep -qx DENIED "$tmp/out"
grep -q 'device awaiting IT approval' "$tmp/out"
echo "check before approval: denied, device awaiting IT approval"

head_before="$("${client[@]}" log head)"
"${client[@]}" join "$inv" --yes --software-key > "$tmp/rejoin"
diff <(grep '^Enrolled' "$tmp/join") <(grep '^Enrolled' "$tmp/rejoin")
[ "$head_before" = "$("${client[@]}" log head)" ]
echo "re-join with the same invitation is idempotent: same pseudonym, no new log entry"

got="$(run_status "$root/target/debug/open-pact-client" --home "$tmp/other" join "$inv" --yes --software-key)"
[ "$got" = 1 ]
grep -q 'invalid or used invitation' "$tmp/out"
echo "another device cannot reuse the invitation: $(grep -o '"reasons":\[[^]]*\]' "$tmp/out")"

race="$(invite "smoke race")"
for i in 1 2 3; do
  ( "$root/target/debug/open-pact-client" --home "$tmp/race$i" join "$race" --yes --software-key > "$tmp/race$i.out" 2>&1; echo $? > "$tmp/race$i.code" ) &
done
wait
winners="$(grep -lx 0 "$tmp"/race?.code | wc -l | tr -d ' ')"
[ "$winners" = 1 ] || { cat "$tmp"/race?.out; exit 1; }
[ "$(grep -l 'invalid or used invitation' "$tmp"/race?.out | wc -l | tr -d ' ')" = 2 ]
echo "three devices racing for one invitation: exactly one enrolled"

got="$(run_status admin devices approve 1234567)"
[ "$got" != 0 ]
grep -q 'at least 8' "$tmp/out"
admin devices approve "$code" | tee "$tmp/approved"
grep -q '^approved pseudonym:'"$code" "$tmp/approved"
admin devices list > "$tmp/devices"
grep -q "^approved  *pseudonym:$code.*smoke owner" "$tmp/devices"
echo "IT approved the device by its code; devices list shows it with the invitation note"

"${client[@]}" log prove > "$tmp/prove"
cat "$tmp/prove"
grep -q '^INCLUDED in the checkpoint' "$tmp/prove"
grep -q '^This entry is your enrolment' "$tmp/prove"
"${client[@]}" log prove 0 > "$tmp/prove0"
grep -q '"kind":"manifest_published"' "$tmp/prove0"
echo "inclusion proofs verify for this device's enrolment and for entry 0"

curl -fsS "$url/v1/log/checkpoint" | "$dev_witness" cosign > "$tmp/cosigned"
curl -fsS -X POST --data-binary "@$tmp/cosigned" "$url/v1/log/witness" | grep -q '"stored"'
curl -fsS "$url/v1/log/checkpoint" | grep -q '^— witness.example.org/demo '
code="$(curl -sS -o "$tmp/body" -w '%{http_code}' -X POST --data-binary @<(curl -fsS "$url/v1/log/checkpoint" | grep -v witness.example.org) "$url/v1/log/witness")"
[ "$code" = 403 ]
echo "witness cosignature stored and served; a checkpoint without one is refused ($code)"

for q in "entries?from=0&to=99999" "entries?from=3&to=2" "proof/inclusion?index=99999" \
  "proof/inclusion?index=0&size=99999" "proof/consistency?from=0" "proof/consistency?from=2&to=1" \
  "proof/consistency?from=1&to=99999"; do
  code="$(curl -sS -o "$tmp/body" -w '%{http_code}' "$url/v1/log/$q")"
  [ "$code" = 400 ] || { echo "$q: $code $(cat "$tmp/body")"; exit 1; }
done
echo "out-of-range log requests answer 400"

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

expect "grace starts at the first failure" 200 'firewall = off, on required, access ends in 2[34]h' \
  "$("$dev_claim" "$device" "$manifest" "$(nonce)" linux "${passing[@]}" firewall=off)"

if [ -z "${OPEN_PACT_ADMIN:-}" ]; then
  docker compose -f "$root/compose.yaml" exec -T db psql -U pact -d pact -qc \
    "UPDATE control_failures SET first_failed_at = now() - interval '25 hours' WHERE control = 'firewall'"
  expect "grace ended a day after the first failure" 403 'firewall = off, on required, grace 1d ended' \
    "$("$dev_claim" "$device" "$manifest" "$(nonce)" linux "${passing[@]}" firewall=off)"
fi

expect "a passing claim clears the failure" 200 '"warnings":\[\]' \
  "$("$dev_claim" "$device" "$manifest" "$(nonce)" linux "${passing[@]}")"

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

cp "$home/enrolment.json" "$tmp/good-enrolment"
python3 - "$home/enrolment.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1]))
e["salt"] = ("1" if e["salt"][0] != "1" else "2") + e["salt"][1:]
json.dump(e, open(sys.argv[1], "w"))
PY
expect_status "a log without this device's enrolment raises the alarm" 2 "is not this device's enrolment"

cp "$tmp/good-enrolment" "$home/enrolment.json"
python3 - "$home/enrolment.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1]))
e["log_entries"]["manifest"] = e["log_entries"]["enrolment"]
json.dump(e, open(sys.argv[1], "w"))
PY
expect_status "a log without the signed manifest at its index raises the alarm" 2 "is not the manifest you signed"

python3 - "$home/enrolment.json" <<'PY'
import json, sys
e = json.load(open(sys.argv[1]))
del e["log_entries"]
json.dump(e, open(sys.argv[1], "w"))
PY
"${client[@]}" check > "$tmp/found" 2>&1
grep -q '^Inclusion proofs verified' "$tmp/found"
grep -q '"log_entries"' "$home/enrolment.json"
echo "without stored indexes the client finds its entries, proves them and stores the indexes"

rm "$home/log-checkpoint.txt"
echo '{"index": 3, "hash": "00"}' > "$home/log-head.json"
expect_status "a v0.1.0 log head asks for re-join instead of an alarm" 1 'log format was upgraded'
"${client[@]}" join "$inv" --yes --software-key > "$tmp/rejoin2"
grep -q '^Transparency log verified' "$tmp/rejoin2"
[ ! -e "$home/log-head.json" ]
echo "join replaces the old head with a checkpoint"

cp "$home/company-key.txt" "$tmp/good-company-key"
echo "sha256:$(printf '0%.0s' {1..64})" > "$home/company-key.txt"
expect_status "a different company key than the pinned one raises the alarm" 2 'the company key changed'
cp "$tmp/good-company-key" "$home/company-key.txt"

pseudonym="$(sed -n 's/^Enrolled as //p' "$tmp/join")"
admin devices revoke "$pseudonym" | grep -q '^revoked '
got="$(run_status "${client[@]}" check)"
[ "$got" = 1 ]
grep -q 'device revoked' "$tmp/out"
expect "revoked device" 403 'device revoked' \
  "$("$dev_claim" "$device" "$manifest" "$(nonce)" linux "${passing[@]}")"
got="$(run_status admin devices approve "$code")"
[ "$got" != 0 ]
[ "$(curl -fsS "$url/v1/log/entries" | grep -o '"kind":"device_revoked"' | wc -l | tr -d ' ')" -ge 1 ]
echo "IT revoked the device: check denied, approval refused, revocation logged"

echo "smoke passed"
