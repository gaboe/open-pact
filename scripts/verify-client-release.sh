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
out_identity=
out_created=0
rollback=1
published_files=()

stat_identity() {
  if stat -c '%d:%i' "$1" >/dev/null 2>&1; then
    stat -c '%d:%i' "$1"
  else
    stat -f '%d:%i' "$1"
  fi
}

out_dir_is_same() {
  [ "$out_created" -eq 1 ] && [ -n "$out_identity" ] &&
    [ ! -L "$out_dir" ] && [ -d "$out_dir" ] &&
    [ "$(stat_identity "$out_dir")" = "$out_identity" ]
}

out_dir_contains_only_published() {
  local entry name published found
  shopt -s dotglob nullglob
  for entry in "$out_dir"/*; do
    name=${entry##*/}
    [ -f "$entry" ] && [ ! -L "$entry" ] || return 1
    found=0
    for published in "${published_files[@]:-}"; do
      if [ "$name" = "$published" ]; then
        found=1
        break
      fi
    done
    [ "$found" -eq 1 ] || return 1
  done
}

cleanup() {
  local file
  if [ "$rollback" -eq 1 ]; then
    for file in "${published_files[@]:-}"; do
      if [ -f "$out_dir/$file" ] && [ ! -L "$out_dir/$file" ]; then
        rm -f -- "$out_dir/$file"
      fi
    done
    if out_dir_is_same && out_dir_contains_only_published; then
      rmdir "$out_dir"
    fi
  fi
  rm -rf "$work"
}
trap cleanup EXIT

if [ -n "$out_dir" ]; then
  if [ "$out_dir" = / ]; then
    echo "out-dir must not be the filesystem root" >&2
    exit 2
  fi
  out_name=$(basename "$out_dir")
  if [ "$out_name" = . ] || [ "$out_name" = .. ]; then
    echo "out-dir must name a directory" >&2
    exit 2
  fi
  if ! mkdir "$out_dir" 2>/dev/null; then
    echo "out-dir must not exist: $out_dir" >&2
    exit 1
  fi
  out_created=1
  out_identity=$(stat_identity "$out_dir") || {
    echo "could not record out-dir identity: $out_dir" >&2
    exit 1
  }
fi

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

if ! out_dir_is_same || ! out_dir_contains_only_published; then
  echo "out-dir changed before publication: $out_dir" >&2
  exit 1
fi

for file in "${assets[@]}"; do
  for published_file in "$file" "$file.sigstore.json"; do
    target="$out_dir/$published_file"
    published_path=$published_file
    if [ -e "$target" ] || [ -L "$target" ]; then
      echo "out-dir target already exists: $target" >&2
      exit 1
    fi
    if mv -n -- "$published_file" "$target"; then
      move_status=0
    else
      move_status=$?
    fi
    if [ -d "$target" ] && [ ! -L "$target" ] && [ -f "$target/$published_file" ]; then
      published_path="$published_file/$published_file"
    fi
    if [ ! -e "$published_file" ] && [ -f "$out_dir/$published_path" ] &&
      [ ! -L "$out_dir/$published_path" ]; then
      published_files+=("$published_path")
    fi
    if [ "$move_status" -ne 0 ] || [ -e "$published_file" ] ||
      [ "$published_path" != "$published_file" ] || [ ! -f "$target" ] || [ -L "$target" ]; then
      echo "could not publish release file: $published_file" >&2
      exit 1
    fi
    if ! out_dir_is_same || ! out_dir_contains_only_published; then
      echo "out-dir changed during publication: $out_dir" >&2
      exit 1
    fi
  done
done

rollback=0
echo "verified release files saved to $out_dir"
