#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cli=${1:?Usage: scripts/build-macos.sh /path/to/open-pact-client}
case "$cli" in /*) ;; *) cli="$(pwd)/$cli" ;; esac
test -x "$cli"
cargo build --release --workspace
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
test -n "$version"
target=$(cargo metadata --format-version 1 --no-deps | bun -e 'console.log((await Bun.stdin.json()).target_directory)')
mkdir -p dist
for binary in open-pact open-pact-admin; do
  bundle="dist/$binary.app"
  mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Helpers"
  cp "$target/release/$binary" "$bundle/Contents/MacOS/$binary"
  cat > "$bundle/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>$binary</string>
<key>CFBundleIdentifier</key><string>org.open-pact.$binary</string>
<key>CFBundleName</key><string>$binary</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
  if [ "$binary" = open-pact ]; then
    cp -f "$cli" "$bundle/Contents/Helpers/open-pact-client"
    codesign --force --sign - "$bundle/Contents/Helpers/open-pact-client"
  fi
  codesign --force --sign - "$bundle"
  codesign --verify --deep --strict "$bundle"
done
