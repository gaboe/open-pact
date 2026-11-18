#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# OPEN_PACT_APP_DIR names a folder that already holds the built open-pact and open-pact-admin
# executables (the release workflow puts universal ones there). Without it, this builds them.
cli=${1:?Usage: scripts/build-macos.sh /path/to/open-pact-client}
case "$cli" in /*) ;; *) cli="$(pwd)/$cli" ;; esac
test -x "$cli"
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
test -n "$version"
if [ -n "${OPEN_PACT_APP_DIR:-}" ]; then
  built="$OPEN_PACT_APP_DIR"
else
  cargo build --release --workspace
  built="$(cargo metadata --format-version 1 --no-deps | bun -e 'console.log((await Bun.stdin.json()).target_directory)')/release"
fi
mkdir -p dist
for binary in open-pact open-pact-admin; do
  bundle="dist/$binary.app"
  rm -rf "$bundle"
  mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Helpers" "$bundle/Contents/Resources"
  cp "$built/$binary" "$bundle/Contents/MacOS/$binary"
  cp "assets/$binary.icns" "$bundle/Contents/Resources/$binary.icns"
  cat > "$bundle/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>$binary</string>
<key>CFBundleIconFile</key><string>$binary</string>
<key>CFBundleIdentifier</key><string>org.open-pact.$binary</string>
<key>CFBundleName</key><string>$binary</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
  cp -f "$cli" "$bundle/Contents/Helpers/open-pact-client"
  codesign --force --sign - "$bundle/Contents/Helpers/open-pact-client"
  codesign --force --sign - "$bundle"
  codesign --verify --deep --strict "$bundle"
done
