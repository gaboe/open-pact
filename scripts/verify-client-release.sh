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
work=$(cd "$work" && pwd -P)
keep_work=0
cleanup() {
  if [ "$keep_work" -eq 0 ]; then
    rm -rf "$work"
  fi
}
trap cleanup EXIT

assets=(
  open-pact-client-aarch64-apple-darwin
  open-pact-client-x86_64-apple-darwin
  open-pact-client-x86_64-unknown-linux-musl
  open-pact-client-x86_64-pc-windows-msvc.exe
  NOTICE
  SHA256SUMS
)
download_patterns=()
for file in "${assets[@]}"; do
  download_patterns+=(--pattern "$file" --pattern "$file.sigstore.json")
done
gh release download "$tag" --repo "$repo" --dir "$work" "${download_patterns[@]}"
cd "$work"

for file in "${assets[@]}"; do
  [ -f "$file" ] || { echo "missing release asset: $file" >&2; exit 1; }
  [ -f "$file.sigstore.json" ] || { echo "missing signature bundle: $file.sigstore.json" >&2; exit 1; }
done

if [ "$checksum_tool" = sha256sum ]; then
  sha256sum --check --strict SHA256SUMS
else
  shasum -a 256 --check SHA256SUMS
fi

identity="https://github.com/$repo/.github/workflows/client-release.yml@refs/tags/$tag"
for file in "${assets[@]}"; do
  cosign verify-blob \
    --bundle "$file.sigstore.json" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$file"
done

verified_dir=$(pwd -P)
printf 'verified files: %s\n' "$verified_dir"
keep_work=1
