#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ] || [[ ! "$1" =~ ^v[0-9][0-9A-Za-z.-]*$ ]]; then
  echo "usage: $0 <tag>" >&2
  exit 2
fi
for tool in gh cosign; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 127; }
done
if command -v sha256sum >/dev/null; then
  checksum_tool=sha256sum
elif command -v shasum >/dev/null; then
  checksum_tool=shasum
else
  echo "sha256sum or shasum is required" >&2
  exit 127
fi

tag=$1
repo=${GH_REPO:-gaboe/open-pact}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

gh release download "$tag" --repo "$repo" --dir "$work"
cd "$work"

for file in \
  open-pact-client-aarch64-apple-darwin \
  open-pact-client-x86_64-apple-darwin \
  open-pact-client-x86_64-unknown-linux-musl \
  open-pact-client-x86_64-pc-windows-msvc.exe; do
  [ -f "$file" ] || { echo "missing release asset: $file" >&2; exit 1; }
  [ -f "$file.sigstore.json" ] || { echo "missing signature bundle: $file.sigstore.json" >&2; exit 1; }
done
[ -f NOTICE ] || { echo "missing NOTICE" >&2; exit 1; }
[ -f NOTICE.sigstore.json ] || { echo "missing signature bundle: NOTICE.sigstore.json" >&2; exit 1; }
[ -f SHA256SUMS ] || { echo "missing SHA256SUMS" >&2; exit 1; }
[ -f SHA256SUMS.sigstore.json ] || { echo "missing signature bundle: SHA256SUMS.sigstore.json" >&2; exit 1; }

if [ "$checksum_tool" = sha256sum ]; then
  sha256sum --check --strict SHA256SUMS
else
  shasum -a 256 --check SHA256SUMS
fi

identity="https://github.com/$repo/.github/workflows/client-release.yml@refs/tags/$tag"
for file in \
  open-pact-client-aarch64-apple-darwin \
  open-pact-client-x86_64-apple-darwin \
  open-pact-client-x86_64-unknown-linux-musl \
  open-pact-client-x86_64-pc-windows-msvc.exe \
  NOTICE \
  SHA256SUMS; do
  cosign verify-blob \
    --bundle "$file.sigstore.json" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$file"
done
