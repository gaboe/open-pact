#!/usr/bin/env bash
# Runs the Linux checks for real inside Ubuntu and Fedora containers, one
# container per state variant, and prints a distro/variant table.
# Exits nonzero when a check panics, the run takes over 3s, or a value is
# outside its allowed enum (Appendix A outputs, plus "unknown", which every
# check may report).
set -uo pipefail
cd "$(dirname "$0")/.."

PLATFORM=${PLATFORM:-}
[ -n "$PLATFORM" ] || case $(uname -m) in arm64 | aarch64) PLATFORM=linux/arm64 ;; *) PLATFORM=linux/amd64 ;; esac

allowed() {
    case $1 in
        disk_encryption) echo "full partial none unknown" ;;
        firewall | secure_boot) echo "on off unknown" ;;
        screen_lock) echo "le_5min le_15min gt_15min off unknown" ;;
        os_supported | password_set | antimalware_active) echo "yes no unknown" ;;
        os_patch_age) echo "le_14d le_30d gt_30d unknown" ;;
        auto_login) echo "off on unknown" ;;
    esac
}
COLS=(disk_encryption firewall screen_lock os_supported os_patch_age auto_login secure_boot antimalware_active)
VARIANTS=(baseline firewalld-installed ufw-active ufw-inactive
    gnome-default gnome-lock-5min gnome-lock-15min gnome-lock-off
    kde-5min kde-30min kde-off
    patch-real patch-stale patch-rotated eol autologin-gdm autologin-sddm autologin-lightdm autologin-off
    clamav-active clamav-inactive)
LIMIT_MS=${LIMIT_MS:-3000}

printf '%-8s %-18s' distro variant
for c in "${COLS[@]}"; do printf ' %-12s' "${c:0:12}"; done
printf ' %s\n' ms

fail=0
for distro in ubuntu fedora; do
    img=open-pact-linux-$distro
    docker build --quiet --platform "$PLATFORM" -f "tests/linux/Dockerfile.$distro" -t "$img" . >/dev/null \
        || { echo "build failed: $distro" >&2; exit 1; }
    for v in "${VARIANTS[@]}"; do
        out=$(docker run --rm --platform "$PLATFORM" "$img" "$v" 2>&1)
        val() { printf '%s\n' "$out" | sed -n "s/^$1 = //p" | head -1; }
        problems=""
        for c in "${COLS[@]}" password_set; do
            [[ " $(allowed "$c") " == *" $(val "$c" || true)"" "* && -n "$(val "$c")" ]] || problems+=" $c=$(val "$c")"
        done
        ms=$(val elapsed_ms); ms=${ms:-999999}
        [ "$ms" -le "$LIMIT_MS" ] || problems+=" slow"
        [ -z "$(val panic)" ] || problems+=" panic"
        printf '%-8s %-18s' "$distro" "$v"
        for c in "${COLS[@]}"; do printf ' %-12s' "$(val "$c")"; done
        printf ' %s\n' "$ms"
        if [ -n "$problems" ]; then
            echo "  FAIL $distro/$v:$problems" >&2
            fail=1
        fi
    done
done
exit $fail
