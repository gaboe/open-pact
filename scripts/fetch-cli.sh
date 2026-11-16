#!/bin/sh
# Downloads open-pact-client release assets and proves them before anything uses them.
#
#   scripts/fetch-cli.sh <out-dir> <asset-name>...
#
# The release is the one in `cli-version`. SHA256SUMS must carry a valid Sigstore signature from
# the open-pact release workflow for that tag, and each asset must match its line in SHA256SUMS.
# Needs curl and cosign. OPEN_PACT_CLI_VERSION overrides cli-version.
set -eu
cd "$(dirname "$0")/.."
out=${1:?Usage: scripts/fetch-cli.sh <out-dir> <asset-name>...}
shift
[ "$#" -gt 0 ] || { echo "fetch-cli: name at least one asset" >&2; exit 1; }
version=${OPEN_PACT_CLI_VERSION:-$(tr -d ' \r\n' < cli-version)}
[ -n "$version" ] || { echo "fetch-cli: cli-version is empty" >&2; exit 1; }
base="https://github.com/gaboe/open-pact/releases/download/v$version"
mkdir -p "$out"
for name in SHA256SUMS SHA256SUMS.sigstore.json "$@"; do
  curl -fsSL --retry 3 -o "$out/$name" "$base/$name"
done
cosign verify-blob \
  --bundle "$out/SHA256SUMS.sigstore.json" \
  --certificate-identity "https://github.com/gaboe/open-pact/.github/workflows/client-release.yml@refs/tags/v$version" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$out/SHA256SUMS"
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1; else shasum -a 256 "$1" | cut -d ' ' -f 1; fi
}
for name in "$@"; do
  want=$(awk -v n="$name" '$2 == n { print $1 }' "$out/SHA256SUMS")
  [ -n "$want" ] || { echo "fetch-cli: SHA256SUMS has no line for $name" >&2; exit 1; }
  got=$(sha256 "$out/$name")
  [ "$want" = "$got" ] || { echo "fetch-cli: $name does not match SHA256SUMS" >&2; exit 1; }
  echo "verified $name"
done
