#!/usr/bin/env bash
set -euo pipefail

url="${1:?usage: demo.sh <gateway-url>   (PAUSE=1 waits for Enter between steps)}"
url="${url%/}"
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
home="$tmp/open-pact"

cargo build -q --manifest-path "$root/Cargo.toml" -p open-pact-client
cargo build -q --manifest-path "$root/Cargo.toml" -p open-pact-core --example dev_claim
client=("$root/target/debug/open-pact-client" --home "$home")
dev_claim="$root/target/debug/examples/dev_claim"

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

step "The owner reads the manifest and signs its hash; the device enrols"
"${client[@]}" join --gateway "$url" --yes

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

step "The transparency log head, signed by the gateway, to compare with colleagues"
"${client[@]}" log head

step "Simulated split view: the local head no longer matches the gateway history"
sed -i.bak -E 's/"hash": "[0-9a-f]{8}/"hash": "00000000/' "$home/log-head.json"
"${client[@]}" check > /dev/null || echo "(check exited with status $?)"

step "Stopping"
"${client[@]}" stop
