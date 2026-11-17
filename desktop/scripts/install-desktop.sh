#!/bin/sh
# Install or update the open-pact desktop apps on macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/gaboe/open-pact-desktop/main/scripts/install-desktop.sh | sh
#
# The apps are not notarized by Apple. A zip downloaded in a browser is marked as coming from the
# internet, and macOS then blocks an app it cannot verify. A download made here with curl carries
# no such mark, so the apps open without that dialog. The zip is checked against the SHA-256
# published with the same release, and each app's signature is verified, before anything is
# replaced.
#
# Run the same line again to update. OPEN_PACT_DESKTOP_VERSION=0.1.0 installs one version;
# OPEN_PACT_INSTALL_DIR changes the folder (default ~/Applications); OPEN_PACT_NO_OPEN=1 skips
# opening the client.
set -eu
# The apps start this script to update themselves and then quit. A closed output pipe must not
# stop the update halfway.
trap '' PIPE

repo=gaboe/open-pact-desktop
dir=${OPEN_PACT_INSTALL_DIR:-$HOME/Applications}
apps="open-pact open-pact-admin"

say() { printf '%s\n' "$*" || true; }
fail() { printf 'open-pact: %s\n' "$*" >&2 || true; exit 1; }

[ "$(uname -s)" = Darwin ] || fail "this installer is for macOS. On Windows use scoop or install-desktop.ps1."

if [ -n "${OPEN_PACT_DESKTOP_VERSION:-}" ]; then
  api="https://api.github.com/repos/$repo/releases/tags/v$OPEN_PACT_DESKTOP_VERSION"
else
  api="https://api.github.com/repos/$repo/releases/latest"
fi
release=$(curl -fsSL "$api" 2>/dev/null) || fail "no such release on GitHub: ${OPEN_PACT_DESKTOP_VERSION:-latest}."
url=$(printf '%s' "$release" | grep -o '"browser_download_url": *"[^"]*/open-pact-desktop-[^"/]*-macos\.zip"' | head -n 1 | sed 's/.*"\(http[^"]*\)"$/\1/')
[ -n "$url" ] || fail "the release has no desktop apps for Mac."
name=$(basename "$url")

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

say "Downloading $name"
if [ -t 2 ]; then progress=--progress-bar; else progress=-sS; fi
curl -fL $progress -o "$work/$name" "$url" || fail "the download failed."
curl -fsSL -o "$work/$name.sha256" "$url.sha256" || fail "the checksum file is missing for $name."
want=$(awk '{print $1}' "$work/$name.sha256")
got=$(shasum -a 256 "$work/$name" | awk '{print $1}')
[ -n "$want" ] && [ "$want" = "$got" ] || fail "the download does not match its checksum. Nothing was installed."
say "Checksum matches."

ditto -x -k "$work/$name" "$work/app"
for app in $apps; do
  [ -d "$work/app/$app.app" ] || fail "the archive has no $app.app."
  codesign --verify --deep --strict "$work/app/$app.app" 2>/dev/null || fail "the signature of $app.app is broken. Nothing was installed."
done

running() {
  ps -axww -o command= | OPEN_PACT_EXE="$dir/$1.app/Contents/MacOS/$1" awk '
    BEGIN { exe = ENVIRON["OPEN_PACT_EXE"] }
    index($0, exe) == 1 && (length($0) == length(exe) || substr($0, length(exe) + 1, 1) == " ") { found = 1 }
    END { exit !found }'
}
for app in $apps; do
  if running "$app"; then
    say "Closing the running $app"
    osascript -e "tell application \"$dir/$app.app\" to quit" >/dev/null 2>&1 || true
  fi
done
for app in $apps; do
  i=0
  while running "$app"; do
    i=$((i + 1))
    [ "$i" -le 20 ] || fail "$app is still running. Quit it and run this line again."
    sleep 0.5
  done
done

mkdir -p "$dir"
for app in $apps; do
  if [ -e "$dir/$app.app" ]; then
    mv "$dir/$app.app" "$work/$app.previous.app"
  fi
  if ! mv "$work/app/$app.app" "$dir/$app.app"; then
    [ -e "$work/$app.previous.app" ] && mv "$work/$app.previous.app" "$dir/$app.app"
    fail "could not move $app.app into $dir. The previous version is back in place."
  fi
  xattr -dr com.apple.quarantine "$dir/$app.app" 2>/dev/null || true
  say "Installed $dir/$app.app"
done

if [ -z "${OPEN_PACT_NO_OPEN:-}" ]; then
  open "$dir/open-pact.app" || true
  say "open-pact is opening."
fi
