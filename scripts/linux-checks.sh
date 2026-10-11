#!/usr/bin/env bash
# Runs the Linux checks for real inside Ubuntu and Fedora containers, one
# container per state variant, and prints a distro/variant table.
# Exits nonzero when a container build or run exits nonzero, a check panics,
# the run takes over LIMIT_MS, or any check differs from the value that
# tests/linux/expected.txt lists for that distro and variant.
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=tests/linux/expect.sh
. tests/linux/expect.sh

PLATFORM=${PLATFORM:-}
[ -n "$PLATFORM" ] || case $(uname -m) in arm64 | aarch64) PLATFORM=linux/arm64 ;; *) PLATFORM=linux/amd64 ;; esac

COLS=(disk_encryption firewall screen_lock os_supported os_patch_age auto_login secure_boot antimalware_active)
CHECKED=("${COLS[@]}" password_set)
VARIANTS=(baseline firewalld-installed ufw-active ufw-active-disabled ufw-inactive
    gnome-default gnome-lock-5min gnome-lock-15min gnome-lock-off
    kde-5min kde-30min kde-off
    patch-real patch-stale patch-rotated eol autologin-gdm autologin-sddm autologin-lightdm autologin-off
    clamav-active clamav-inactive)
LIMIT_MS=${LIMIT_MS:-3000}

printf '%-8s %-20s' distro variant
for c in "${COLS[@]}"; do printf ' %-12s' "${c:0:12}"; done
printf ' %s\n' ms

fail=0
for distro in ubuntu fedora; do
    img=open-pact-linux-$distro
    docker build --quiet --platform "$PLATFORM" -f "tests/linux/Dockerfile.$distro" -t "$img" . >/dev/null \
        || { echo "build failed: $distro" >&2; exit 1; }
    for v in "${VARIANTS[@]}"; do
        out=$(docker run --rm --platform "$PLATFORM" "$img" "$v" 2>&1)
        rc=$?
        val() { printf '%s\n' "$out" | sed -n "s/^$1 = //p" | head -1; }
        problems=""
        [ "$rc" -eq 0 ] || problems+=" exit=$rc"
        for c in "${CHECKED[@]}"; do
            want=$(expected "$distro" "$v" "$c")
            matches "$(val "$c")" "$want" || problems+=" $c=$(val "$c")(want $want)"
        done
        ms=$(val elapsed_ms); ms=${ms:-999999}
        [ "$ms" -le "$LIMIT_MS" ] || problems+=" slow"
        [ -z "$(val panic)" ] || problems+=" panic"
        printf '%-8s %-20s' "$distro" "$v"
        for c in "${COLS[@]}"; do printf ' %-12s' "$(val "$c")"; done
        printf ' %s\n' "$ms"
        if [ -n "$problems" ]; then
            echo "  FAIL $distro/$v:$problems" >&2
            fail=1
        fi
    done
done
exit $fail
