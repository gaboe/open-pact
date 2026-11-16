#!/bin/sh
# Prints the scoop manifest for one release.
#
#   scripts/scoop-manifest.sh <version> <sha256-of-the-windows-zip>
#
# Copy the output to bucket/open-pact-desktop.json in the scoop bucket. `checkver` and
# `autoupdate` let the bucket's own tooling follow later releases.
set -eu
version=${1:?Usage: scripts/scoop-manifest.sh <version> <sha256>}
hash=${2:?Usage: scripts/scoop-manifest.sh <version> <sha256>}
case "$hash" in
  *[!0-9a-f]* | "") echo "scoop-manifest: the hash must be lower case hex" >&2; exit 1 ;;
esac
[ "${#hash}" -eq 64 ] || { echo "scoop-manifest: the hash must have 64 digits" >&2; exit 1; }
repo=https://github.com/gaboe/open-pact-desktop
cat <<EOF
{
  "version": "$version",
  "description": "Desktop apps for open-pact: join a company and check this device, and edit deployment manifests",
  "homepage": "$repo",
  "license": "MIT",
  "architecture": {
    "64bit": {
      "url": "$repo/releases/download/v$version/open-pact-desktop-$version-windows-x64.zip",
      "hash": "$hash"
    }
  },
  "bin": "open-pact-client.exe",
  "shortcuts": [
    ["open-pact.exe", "open-pact"],
    ["open-pact-admin.exe", "open-pact admin"]
  ],
  "checkver": "github",
  "autoupdate": {
    "architecture": {
      "64bit": {
        "url": "$repo/releases/download/v\$version/open-pact-desktop-\$version-windows-x64.zip",
        "hash": {
          "url": "\$url.sha256"
        }
      }
    }
  }
}
EOF
