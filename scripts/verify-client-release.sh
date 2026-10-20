#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [[ ! "$1" =~ ^v[0-9][0-9A-Za-z.-]*$ ]]; then
  echo "usage: $0 <tag> [<out-dir>]" >&2
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
out_dir=${2:-}
if [ -n "$out_dir" ]; then
  if [[ "$out_dir" != /* ]]; then
    out_dir="$PWD/$out_dir"
  fi
  while [[ "$out_dir" != / && "$out_dir" == */ ]]; do
    out_dir=${out_dir%/}
  done
fi
repo=${GH_REPO:-gaboe/open-pact}
work=$(mktemp -d)
stage=
cleanup() {
  rm -rf "$work"
  if [ -n "$stage" ]; then
    rm -rf "$stage"
  fi
}
trap cleanup EXIT

mkdir "$work/download"
gh release download "$tag" --repo "$repo" --dir "$work/download"
cd "$work/download"

assets=(
  open-pact-client-aarch64-apple-darwin
  open-pact-client-x86_64-apple-darwin
  open-pact-client-x86_64-unknown-linux-musl
  open-pact-client-x86_64-pc-windows-msvc.exe
  NOTICE
  SHA256SUMS
)
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

if [ -z "$out_dir" ]; then
  exit 0
fi

if [ "$out_dir" = / ]; then
  echo "out-dir must not be the filesystem root" >&2
  exit 2
fi
out_parent=$(dirname "$out_dir")
out_name=$(basename "$out_dir")
if [ "$out_name" = . ] || [ "$out_name" = .. ]; then
  echo "out-dir must name a directory" >&2
  exit 2
fi
mkdir -p "$out_parent"
if [ -L "$out_dir" ]; then
  echo "out-dir must not be a symlink" >&2
  exit 1
fi
if [ -e "$out_dir" ] && [ -n "$(find "$out_dir" -mindepth 1 -print -quit)" ]; then
  echo "out-dir must be empty: $out_dir" >&2
  exit 1
fi
stage=$(mktemp -d "$out_parent/.${out_name}.verified.XXXXXX")
for file in "${assets[@]}"; do
  mv -- "$file" "$file.sigstore.json" "$stage/"
done

if [ -d "$out_dir" ]; then
  rmdir "$out_dir"
fi
mv -- "$stage" "$out_dir"
stage=
echo "verified release files saved to $out_dir"
