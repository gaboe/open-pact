#!/usr/bin/env bash
set -euo pipefail

url="${1:?usage: smoke.sh <gateway-url>}"
url="${url%/}"
root="$(cd "$(dirname "$0")/.." && pwd)"

curl -fsS "$url/healthz" | grep -qx ok
echo "healthz ok"

cargo run -q --manifest-path "$root/Cargo.toml" -p open-pact-client -- --gateway "$url" check | tee /dev/stderr | grep -q '"accepted"'
echo "client check accepted"

nonce="$(curl -fsS -X POST "$url/v1/nonce" | sed -E 's/.*"nonce":"([^"]+)".*/\1/')"
claim='{"manifest":"sha256:poc","device":"pseudonym:smoke","nonce":"'"$nonce"'","time":"2026-01-01T00:00:00Z","client":"smoke","results":{"disk_encryption":"full"}}'

first="$(curl -sS -X POST -H 'content-type: application/json' -d "$claim" "$url/v1/claim")"
echo "first: $first"
echo "$first" | grep -q '"accepted"'

second="$(curl -sS -o /dev/stderr -w '%{http_code}' -X POST -H 'content-type: application/json' -d "$claim" "$url/v1/claim")"
echo
echo "replay status: $second"
[ "$second" = 403 ]

echo "smoke passed"
