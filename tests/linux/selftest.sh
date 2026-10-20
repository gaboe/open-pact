#!/usr/bin/env bash
# Proves scripts/linux-checks.sh rejects wrong results and failed processes.
# A fake `docker` on PATH answers every build and run, so no container starts.
# Modes: ok (the expected values, exit 0), corrupt (one wrong cell, exit 0),
# unknowns (every check "unknown", exit 0), exit77 (the expected values, exit 77).
set -uo pipefail
cd "$(dirname "$0")/../.."
. tests/linux/expect.sh

bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
cat >"$bin/docker" <<'FAKE'
#!/usr/bin/env bash
. tests/linux/expect.sh
[ "$1" = build ] && exit 0
variant=${*: -1}
img=${*: -2:1}
distro=${img##*-}
for c in disk_encryption firewall screen_lock os_supported os_patch_age_days password_set auto_login secure_boot antimalware_active; do
    want=$(expected "$distro" "$variant" "$c")
    value=${want%%|*}
    value=${value%%..*}
    [ "$FAKE_MODE" != unknowns ] || value=unknown
    [ "$FAKE_MODE-$distro-$variant-$c" != corrupt-ubuntu-ufw-active-firewall ] || value=off
    echo "$c = $value"
done
echo "elapsed_ms = 10"
[ "$FAKE_MODE" != exit77 ] || exit 77
exit 0
FAKE
chmod +x "$bin/docker"

status=0
for value in 0 14 3650; do
    matches "$value" "0..3650" || status=1
done
for value in -1 3651 unknown 1.5 01 999999999999999999999999; do
    if matches "$value" "0..3650"; then
        echo "FAIL range accepted $value"
        status=1
    fi
done
check() { # mode, expect "pass" or "fail"
    FAKE_MODE=$1 PATH="$bin:$PATH" scripts/linux-checks.sh >/dev/null 2>&1
    rc=$?
    if { [ "$2" = pass ] && [ $rc -eq 0 ]; } || { [ "$2" = fail ] && [ $rc -ne 0 ]; }; then
        echo "ok   $1 -> exit $rc"
    else
        echo "FAIL $1 -> exit $rc, wanted $2"
        status=1
    fi
}
check ok pass
check corrupt fail
check unknowns fail
check exit77 fail
exit $status
