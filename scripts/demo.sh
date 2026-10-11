#!/usr/bin/env bash
set -euo pipefail

url="${1:?usage: demo.sh <gateway-url>   (PAUSE=1 waits for Enter between steps)}"
url="${url%/}"
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
home="$tmp/open-pact"

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

n=0
step() {
  n=$((n + 1))
  if [ "${PAUSE:-0}" = 1 ] && [ "$n" -gt 1 ]; then
    read -r -p $'\n(press Enter)' _
  fi
  printf '\n\033[1;36m== %d. %s\033[0m\n\n' "$n" "$1"
}

step "The company gateway at $url"
curl -fsS "$url/healthz" > /dev/null
sed -n 's/.*<dt>\(.*\)<\/dt><dd><code>\(.*\)<\/code><\/dd>.*/\1: \2/p' < <(curl -fsS "$url/")
echo "Summary page: $url/"

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

step "The transparency log checkpoint (Merkle tree size and root), signed by the gateway"
"${client[@]}" log head

step "An independent witness cosigns the checkpoint; the gateway serves it with the cosignature"
curl -fsS "$url/v1/log/checkpoint" | "$dev_witness" cosign > "$tmp/cosigned"
curl -fsS -X POST --data-binary "@$tmp/cosigned" "$url/v1/log/witness"
echo
curl -fsS "$url/v1/log/checkpoint"

step "The record of my enrolment is provably in the log"
"${client[@]}" log prove

step "Simulated split view: this device holds a different root than the gateway now proves"
sed -i.bak '3s/.*/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=/' "$home/log-checkpoint.txt"
"${client[@]}" check > /dev/null || echo "(check exited with status $?)"

step "Stopping"
"${client[@]}" stop
