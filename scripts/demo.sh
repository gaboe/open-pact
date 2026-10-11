#!/usr/bin/env bash
set -euo pipefail

url="${1:?usage: demo.sh <gateway-url>   (PAUSE=1 waits for Enter between steps)}"
url="${url%/}"
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
proxy_pid=""
trap '[ -z "$proxy_pid" ] || kill "$proxy_pid" 2> /dev/null; rm -rf "$tmp"' EXIT
home="$tmp/open-pact"

cargo build -q --manifest-path "$root/Cargo.toml" -p open-pact-client
cargo build -q --manifest-path "$root/Cargo.toml" -p open-pact-core --example dev_claim --example dev_attacks
client=("$root/target/debug/open-pact-client" --home "$home")
dev_claim="$root/target/debug/examples/dev_claim"
attacks="$root/target/debug/examples/dev_attacks"
# OPEN_PACT_WITNESS_URL points at the witness elsewhere; by default the compose witness.
witness="${OPEN_PACT_WITNESS_URL:-http://$(docker compose -f "$root/compose.yaml" port witness 8080)}"
witness="${witness%/}"
# OPEN_PACT_ADMIN runs the gateway admin CLI elsewhere, e.g. "kubectl exec -i deploy/pact-gateway -- open-pact-gateway".
if [ -n "${OPEN_PACT_ADMIN:-}" ]; then
  read -ra admin_cmd <<< "$OPEN_PACT_ADMIN"
else
  admin_cmd=(docker compose -f "$root/compose.yaml" exec -T gateway open-pact-gateway)
fi
admin() { "${admin_cmd[@]}" "$@"; }

n=0
step() {
  n=$((n + 1))
  if [ "${PAUSE:-0}" = 1 ] && [ "$n" -gt 1 ]; then
    read -r -p $'\n(press Enter)' _
  fi
  printf '\n\033[1;36m== %d. %s\033[0m\n\n' "$n" "$1"
}

step "The company gateway at $url"
for _ in $(seq 60); do
  curl -fsS "$url/healthz" > /dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$url/healthz" > /dev/null
sed -n 's/.*<dt>\(.*\)<\/dt><dd><code>\(.*\)<\/code><\/dd>.*/\1: \2/p' < <(curl -fsS "$url/")
echo "Summary page: $url/"

for _ in $(seq 60); do
  curl -fsS "$witness/healthz" > /dev/null 2>&1 && break
  sleep 1
done
echo "Witness at $witness: $(curl -fsS "$witness/healthz")"

step "IT creates a one-time invitation: gateway, company key and log key fingerprints, a 256-bit code"
invitation="$(admin invite --url "$url" --ttl 1h --note "demo owner")"
echo "$invitation"

step "The owner joins: the client checks the gateway's keys against the invitation, then shows the manifest"
"${client[@]}" join "$invitation" --yes | tee "$tmp/join"

step "Until IT approves, the gateway refuses the device"
"${client[@]}" check || echo "(check exited with status $?)"

step "IT approves the device by the code the owner reads out"
admin devices approve "$(sed -nE 's/^Waiting for IT approval. Read this device code to IT: ([0-9a-f]{12})$/\1/p' "$tmp/join")"

step "The device runs the checks and sends one signed claim"
"${client[@]}" check
"${client[@]}" log show > "$tmp/sent"
grep -m 1 '"trust_level"' "$tmp/sent" | sed -E 's/.*: "(L[0-9])".*/Trust level in the signed claim: \1/'

step "Any VPN that trusts the gateway CA accepts this short-lived certificate"
openssl x509 -in "$home/vpn-cert.pem" -noout -subject -issuer -enddate -ext extendedKeyUsage
openssl verify -purpose sslclient -CAfile "$home/ca.pem" "$home/vpn-cert.pem"

step "A captured claim cannot be replayed"
tail -n 1 "$home/claims.jsonl" | sed -E 's/.*"sent_b64":"([^"]+)".*/\1/' | openssl base64 -d -A > "$tmp/replayed"
curl -sS -X POST -H 'content-type: application/json' --data-binary "@$tmp/replayed" "$url/v1/claim"
echo

step "A device that never enrolled is refused, even with perfect results"
nonce="$(curl -fsS -X POST "$url/v1/nonce" | sed -E 's/.*"nonce":"([^"]+)".*/\1/')"
jws="$("$dev_claim" "$tmp/stranger.pem" "$home/manifest.toml" "$nonce" linux disk_encryption=full firewall=on screen_lock=le_5min os_supported=yes)"
curl -sS -X POST -H 'content-type: application/json' -d "{\"jws\":\"$jws\"}" "$url/v1/claim"
echo

step "Everything that left the device, kept locally byte for byte"
"${client[@]}" log show | sed -n '1,/^-- response/p'

step "The transparency log checkpoint (Merkle tree size and root), signed by the gateway and cosigned by the witness"
"${client[@]}" log head
curl -fsS "$url/v1/log/checkpoint" > "$tmp/cosigned"

step "A log signs a fork (another root for a size the witness already cosigned): the witness refuses it"
echo "(a test log whose key this script holds plays the gateway)"
add_checkpoint() { curl -sS -o "$tmp/witnessed" -w '%{http_code}' --data-binary @- "$witness/add-checkpoint"; }
size=1
[ "$("$attacks" add 0 1 | add_checkpoint)" = 409 ] && size="$(cat "$tmp/witnessed")"
next=$((size + 1))
echo "honest checkpoint of size $next: $("$attacks" add "$size" "$next" | add_checkpoint)"
cat "$tmp/witnessed"
echo "forked checkpoint of size $next: $("$attacks" fork "$next" | add_checkpoint)"
cat "$tmp/witnessed"

step "So a forking gateway can show its victims only checkpoints without the cosignature: the client raises the alarm"
python3 "$root/scripts/checkpoint-proxy.py" "$tmp/proxy-port" "$url" "$tmp/served" &
proxy_pid=$!
for _ in $(seq 50); do [ -s "$tmp/proxy-port" ] && break; sleep 0.1; done
cp "$home/enrolment.json" "$tmp/real-enrolment"
python3 - "$home/enrolment.json" "http://127.0.0.1:$(cat "$tmp/proxy-port")" <<'PY2'
import json, sys
e = json.load(open(sys.argv[1]))
e["gateway"] = sys.argv[2]
json.dump(e, open(sys.argv[1], "w"))
PY2
grep -v '^— witness.example.org/' "$tmp/cosigned" > "$tmp/served"
"${client[@]}" check > /dev/null || echo "(check exited with status $?)"

step "A frozen checkpoint, replayed with a cosignature from two hours ago, raises the alarm too"
"$attacks" stale "$(( $(date +%s) - 7200 ))" < "$tmp/cosigned" > "$tmp/served"
"${client[@]}" check > /dev/null || echo "(check exited with status $?)"
cp "$tmp/real-enrolment" "$home/enrolment.json"
kill "$proxy_pid"
wait "$proxy_pid" 2> /dev/null || true
proxy_pid=""

step "The record of my enrolment is provably in the log"
"${client[@]}" log prove

step "Simulated split view: this device holds a different root than the gateway now proves"
sed -i.bak '3s/.*/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=/' "$home/log-checkpoint.txt"
"${client[@]}" check > /dev/null || echo "(check exited with status $?)"

step "Stopping"
"${client[@]}" stop
