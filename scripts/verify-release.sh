#!/usr/bin/env bash
# Rebuild a release tag from the public source and print the image digest.
# With <image-ref>, exit 1 unless the published image has the same digest.
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/gaboe/open-pact.git}"
# CI labels the image with this URL; the label is part of the image config and so of the digest.
SOURCE_URL="${SOURCE_URL:-${REPO_URL%.git}}"

target=""
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --target) [ $# -ge 2 ] || { echo "--target needs a value" >&2; exit 2; }; target=$2; shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
set -- ${args[@]+"${args[@]}"}
case "${target:-gateway}" in
  gateway) target_args=() ;;
  witness) target_args=(--target witness) ;;
  *) echo "--target must be gateway or witness" >&2; exit 2 ;;
esac

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 [--target gateway|witness] <tag> [<image-ref>]" >&2
  exit 2
fi
tag=$1
image_ref=${2:-}

work=$(mktemp -d)
builder="op-verify-$$"
cleanup() {
  docker buildx rm "$builder" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

git clone --quiet --depth 1 --branch "$tag" "$REPO_URL" "$work/src"
epoch=$(git -C "$work/src" log -1 --format=%ct)

docker buildx create --name "$builder" --driver docker-container >/dev/null
docker buildx --builder "$builder" build \
  --no-cache \
  ${target_args[@]+"${target_args[@]}"} \
  --platform linux/amd64 \
  --provenance=false --sbom=false \
  --build-arg SOURCE_DATE_EPOCH="$epoch" \
  --label "org.opencontainers.image.source=$SOURCE_URL" \
  --output "type=oci,dest=$work/image.tar,rewrite-timestamp=true,oci-mediatypes=true" \
  --metadata-file "$work/meta.json" \
  "$work/src"

local_digest=$(sed -n 's/.*"containerimage.digest": *"\(sha256:[0-9a-f]*\)".*/\1/p' "$work/meta.json")
[ -n "$local_digest" ] || { echo "no digest in build metadata" >&2; exit 1; }
echo "local digest:     $local_digest"

[ -n "$image_ref" ] || exit 0

if command -v crane >/dev/null 2>&1; then
  remote_digest=$(crane digest --platform linux/amd64 "$image_ref")
else
  remote_digest=$(docker buildx imagetools inspect "$image_ref" --format '{{.Manifest.Digest}}')
fi
echo "published digest: $remote_digest"

if [ "$local_digest" = "$remote_digest" ]; then
  echo "MATCH"
else
  echo "MISMATCH" >&2
  exit 1
fi
