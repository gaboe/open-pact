#!/usr/bin/env bash
set -euo pipefail

script=$(cd "$(dirname "$0")/.." && pwd)/scripts/verify-client-release.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mock_bin="$tmp/bin"
mkdir "$mock_bin"
real_mktemp=$(command -v mktemp)
if command -v sha256sum >/dev/null; then
  checksum_command=sha256sum
else
  checksum_command=shasum
fi
cat > "$mock_bin/mktemp" <<'MOCK_MKTEMP'
#!/usr/bin/env bash
set -euo pipefail
dir=$("$REAL_MKTEMP" "$@")
dir=$(cd "$dir" && pwd -P)
printf '%s\n' "$dir" > "$MOCK_WORK_PATH_FILE"
printf '%s\n' "$dir"
MOCK_MKTEMP
cat > "$mock_bin/gh" <<'MOCK_GH'
#!/usr/bin/env bash
set -euo pipefail
if [ "${MOCK_GH_FAIL:-}" = 1 ]; then
  echo "mock GitHub download failed" >&2
  exit 9
fi
[ "$1" = release ] && [ "$2" = download ] || exit 90
shift 2
[ "$1" = v1.2.3 ] || exit 91
shift
patterns=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) [ "$2" = example/project ] || exit 92; shift 2 ;;
    --dir) dest=$2; shift 2 ;;
    --pattern) patterns+=("$2"); shift 2 ;;
    *) exit 93 ;;
  esac
done
assets=(
  open-pact-client-aarch64-apple-darwin
  open-pact-client-x86_64-apple-darwin
  open-pact-client-x86_64-unknown-linux-musl
  open-pact-client-x86_64-pc-windows-msvc.exe
  NOTICE
  SHA256SUMS
)
expected_patterns=()
for file in "${assets[@]}"; do
  expected_patterns+=("$file" "$file.sigstore.json")
done
[ "${#patterns[@]}" -eq "${#expected_patterns[@]}" ] || exit 94
for ((i=0; i < ${#expected_patterns[@]}; i++)); do
  [ "${patterns[$i]}" = "${expected_patterns[$i]}" ] || exit 95
done
for file in "${assets[@]}"; do
  [ "${MOCK_MISSING:-}" = "$file" ] && continue
  printf 'fictional release asset %s\n' "$file" > "$dest/$file"
  [ "${MOCK_MISSING_BUNDLE:-}" = "$file" ] || printf '{"fictional":true}\n' > "$dest/$file.sigstore.json"
done
(
  cd "$dest"
  if [ "${MOCK_MISSING:-}" != SHA256SUMS ]; then
    : > SHA256SUMS
    for file in "${assets[@]}"; do
      [ "$file" = SHA256SUMS ] && continue
      if [ -f "$file" ]; then
        if [ "$CHECKSUM_COMMAND" = sha256sum ]; then
          "$CHECKSUM_COMMAND" "$file" >> SHA256SUMS
        else
          "$CHECKSUM_COMMAND" -a 256 "$file" >> SHA256SUMS
        fi
      fi
    done
  fi
)
if [ "${MOCK_BAD_CHECKSUM:-}" = 1 ]; then
  printf 'modified after checksum\n' >> "$dest/NOTICE"
fi
MOCK_GH
cat > "$mock_bin/cosign" <<'MOCK_COSIGN'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = verify-blob ] || exit 90
for ((i=1; i <= $#; i++)); do
  if [ "${!i}" = --bundle ]; then
    j=$((i + 1))
    [ -f "${!j}" ] || exit 91
  fi
done
last=${!#}
if [ "${MOCK_COSIGN_FAIL:-}" = "$(basename "$last")" ]; then
  echo "mock signature verification failed for $last" >&2
  exit 9
fi
MOCK_COSIGN
chmod +x "$mock_bin/mktemp" "$mock_bin/gh" "$mock_bin/cosign"
export REAL_MKTEMP="$real_mktemp"
export CHECKSUM_COMMAND="$checksum_command"
export PATH="$mock_bin:$PATH"
export GH_REPO=example/project

fail() {
  echo "FAIL: $*" >&2
  exit 1
}
run_success() {
  local name=$1
  local output="$tmp/$name.output"
  local marker="$tmp/$name.work-path"
  local out
  env -u MOCK_GH_FAIL -u MOCK_MISSING -u MOCK_MISSING_BUNDLE \
    -u MOCK_BAD_CHECKSUM -u MOCK_COSIGN_FAIL \
    "MOCK_WORK_PATH_FILE=$marker" "$script" v1.2.3 > "$output"
  out=$(sed -n '$s/^verified files: //p' "$output")
  [ -n "$out" ] || fail "$name did not print its verified directory last"
  [[ "$out" = /* ]] || fail "$name did not print an absolute path"
  [ "$(cat "$marker")" = "$out" ] || fail "$name printed a different directory"
  [ -d "$out" ] || fail "$name did not keep its verified directory"
  [ "$(stat -f '%Lp' "$out")" = 700 ] || fail "$name directory mode was not 700"
  [ -z "$(find "$out" -mindepth 1 ! -type f -print -quit)" ] || fail "$name directory contains a non-file"
  find "$out" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; | sort > "$tmp/$name.actual"
  cat > "$tmp/$name.expected" <<'EXPECTED'
NOTICE
NOTICE.sigstore.json
SHA256SUMS
SHA256SUMS.sigstore.json
open-pact-client-aarch64-apple-darwin
open-pact-client-aarch64-apple-darwin.sigstore.json
open-pact-client-x86_64-apple-darwin
open-pact-client-x86_64-apple-darwin.sigstore.json
open-pact-client-x86_64-pc-windows-msvc.exe
open-pact-client-x86_64-pc-windows-msvc.exe.sigstore.json
open-pact-client-x86_64-unknown-linux-musl
open-pact-client-x86_64-unknown-linux-musl.sigstore.json
EXPECTED
  cmp -s "$tmp/$name.expected" "$tmp/$name.actual" || fail "$name directory did not contain exactly the verified files"
}
run_failure() {
  local name=$1
  shift
  local marker="$tmp/$name.work-path"
  if env "MOCK_WORK_PATH_FILE=$marker" "$@" "$script" v1.2.3 >/dev/null 2>&1; then
    fail "$name unexpectedly succeeded"
  fi
  [ -s "$marker" ] || fail "$name did not create a working directory"
  local out
  out=$(cat "$marker")
  [ ! -e "$out" ] && [ ! -L "$out" ] || fail "$name left its working directory"
}
run_missing_asset() {
  local file=$1
  local marker="$tmp/missing-$file.work-path"
  local expected="$tmp/expected-diagnostic"
  local actual="$tmp/actual-diagnostic"
  printf 'missing release asset: %s\n' "$file" > "$expected"
  if env "MOCK_MISSING=$file" "MOCK_WORK_PATH_FILE=$marker" "$script" v1.2.3 >/dev/null 2>"$actual"; then
    fail "missing-$file unexpectedly succeeded"
  fi
  cmp -s "$expected" "$actual" || fail "missing-$file returned the wrong diagnostic"
  local out
  out=$(cat "$marker")
  [ ! -e "$out" ] && [ ! -L "$out" ] || fail "missing-$file left its working directory"
}

run_success successful-download
run_failure github-download MOCK_GH_FAIL=1
run_failure bad-checksum MOCK_BAD_CHECKSUM=1
run_failure signature-check MOCK_COSIGN_FAIL=NOTICE
for file in \
  open-pact-client-aarch64-apple-darwin \
  open-pact-client-x86_64-apple-darwin \
  open-pact-client-x86_64-unknown-linux-musl \
  open-pact-client-x86_64-pc-windows-msvc.exe \
  NOTICE \
  SHA256SUMS; do
  run_missing_asset "$file"
  run_failure "missing-bundle-$file" "MOCK_MISSING_BUNDLE=$file"
done

echo "mocked release verification passed"
