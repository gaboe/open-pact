#!/usr/bin/env bash
set -euo pipefail

script=$(cd "$(dirname "$0")/.." && pwd)/scripts/verify-client-release.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mock_bin="$tmp/bin"
mkdir "$mock_bin"
real_mv=$(command -v mv)
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
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) [ "$2" = example/project ] || exit 92; shift 2 ;;
    --dir) dest=$2; shift 2 ;;
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
      [ -f "$file" ] && sha256sum "$file" >> SHA256SUMS
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
cat > "$mock_bin/mv" <<'MOCK_MV'
#!/usr/bin/env bash
set -euo pipefail
if [ -n "${MOCK_MV_RACE_KIND:-}" ] && mkdir "$MOCK_MV_RACE_MARKER" 2>/dev/null; then
  case "$MOCK_MV_RACE_KIND" in
    file) printf 'foreign file\n' > "$MOCK_MV_RACE_OUT/keep.txt" ;;
    symlink)
      rmdir "$MOCK_MV_RACE_OUT"
      ln -s "$MOCK_MV_RACE_TARGET" "$MOCK_MV_RACE_OUT"
      ;;
    *) exit 94 ;;
  esac
fi
exec "$REAL_MV" "$@"
MOCK_MV
chmod +x "$mock_bin/gh" "$mock_bin/cosign"
chmod +x "$mock_bin/mv"
export REAL_MV="$real_mv"
export PATH="$mock_bin:$PATH"
export GH_REPO=example/project

fail() {
  echo "FAIL: $*" >&2
  exit 1
}
run_success() {
  local out=$1
  shift
  env -u MOCK_GH_FAIL -u MOCK_MISSING -u MOCK_MISSING_BUNDLE \
    -u MOCK_BAD_CHECKSUM -u MOCK_COSIGN_FAIL \
    "$script" v1.2.3 "$out" >/dev/null
  [ "$(find "$out" -maxdepth 1 -type f | wc -l | tr -d ' ')" -eq 12 ] || fail "expected 12 release files in $out"
  [ -f "$out/open-pact-client-aarch64-apple-darwin" ] || fail "verified binary missing"
  [ -f "$out/SHA256SUMS.sigstore.json" ] || fail "checksum bundle missing"
}
run_failure() {
  local name=$1
  shift
  local out="$tmp/$name"
  if env "$@" "$script" v1.2.3 "$out" >/dev/null 2>&1; then
    fail "$name unexpectedly succeeded"
  fi
  [ ! -e "$out" ] && [ ! -L "$out" ] || fail "$name left its output directory"
}
run_missing_asset() {
  local file=$1
  local out="$tmp/missing-$file"
  local expected="$tmp/expected-diagnostic"
  local actual="$tmp/actual-diagnostic"
  printf 'missing release asset: %s\n' "$file" > "$expected"
  if env "MOCK_MISSING=$file" "$script" v1.2.3 "$out" >/dev/null 2>"$actual"; then
    fail "missing-$file unexpectedly succeeded"
  fi
  cmp -s "$expected" "$actual" || fail "missing-$file returned the wrong diagnostic"
  [ ! -e "$out" ] && [ ! -L "$out" ] || fail "missing-$file left its output directory"
}
run_destination_race() {
  local kind=$1
  local out="$tmp/destination-race-$kind"
  local target="$tmp/destination-race-target-$kind"
  mkdir "$target"
  if env \
    "MOCK_MV_RACE_KIND=$kind" \
    "MOCK_MV_RACE_OUT=$out" \
    "MOCK_MV_RACE_TARGET=$target" \
    "MOCK_MV_RACE_MARKER=$tmp/destination-race-$kind.injected" \
    "$script" v1.2.3 "$out" >/dev/null 2>&1; then
    fail "$kind destination change unexpectedly succeeded"
  fi
  if [ "$kind" = file ]; then
    [ "$(cat "$out/keep.txt")" = "foreign file" ] || fail "file race changed its injected file"
    [ "$(find "$out" -type f | wc -l | tr -d ' ')" -eq 1 ] || fail "file race published release files"
  else
    [ -L "$out" ] || fail "symlink race did not preserve the injected symlink"
    [ -z "$(find "$target" -type f -print -quit)" ] || fail "symlink race published release files"
  fi
}

run_success "$tmp/success"
mkdir "$tmp/existing-empty"
if "$script" v1.2.3 "$tmp/existing-empty" >/dev/null 2>&1; then
  fail "existing output directory unexpectedly succeeded"
fi
[ -d "$tmp/existing-empty" ] || fail "existing output directory was removed"
if "$script" v1.2.3 "$tmp/missing-parent/output" >/dev/null 2>&1; then
  fail "missing output parent unexpectedly succeeded"
fi
"$script" v1.2.3 >/dev/null
run_success "$tmp/relative output"
run_success "$tmp/trailing-slash/"
if "$script" latest "$tmp/invalid-tag" >/dev/null 2>&1; then
  fail "invalid tag unexpectedly succeeded"
fi
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
run_destination_race file
run_destination_race symlink

echo "mocked release verification passed"
