#!/usr/bin/env bash
# Sourced by scripts/linux-checks.sh and tests/linux/selftest.sh.
# expected DISTRO VARIANT CHECK prints the allowed values ("a|b") for one cell
# of tests/linux/expected.txt. The most specific row wins: variant over
# default, then exact distro over "*".
EXPECTED_FILE=${EXPECTED_FILE:-$(dirname "${BASH_SOURCE[0]}")/expected.txt}

expected() {
    awk -v dist="$1" -v var="$2" -v col="$3" '
        /^#/ || NF < 3 { next }
        ($1 == dist || $1 == "*") && ($2 == var || $2 == "default") {
            score = ($2 == var ? 10 : 0) + ($1 == dist ? 1 : 0)
            for (i = 3; i <= NF; i++) {
                split($i, kv, "=")
                if (kv[1] == col && score > best) { best = score; val = substr($i, length(col) + 2) }
            }
        }
        END { if (best) print val }
    ' "$EXPECTED_FILE"
}

# True for a declared string value or an integer in an inclusive min..max range.
matches() {
    if [[ "$2" =~ ^([0-9]+)\.\.([0-9]+)$ ]]; then
        [[ "$1" =~ ^(0|[1-9][0-9]{0,3})$ ]] || return 1
        local low=${2%%..*} high=${2##*..}
        [ "$1" -ge "$low" ] && [ "$1" -le "$high" ]
        return
    fi
    [ -n "$2" ] && [[ "|$2|" == *"|$1|"* ]]
}
