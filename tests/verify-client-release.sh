#!/usr/bin/env bash
set -euo pipefail

script=$(cd "$(dirname "$0")/.." && pwd)/scripts/verify-client-release.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mock_bin="$tmp/bin"
mkdir "$mock_bin"
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
  : > SHA256SUMS
  for file in "${assets[@]}"; do
    [ "$file" = SHA256SUMS ] && continue
    [ -f "$file" ] && sha256sum "$file" >> SHA256SUMS
  done
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
chmod +x "$mock_bin/gh" "$mock_bin/cosign"
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
  mkdir "$out"
  if env "$@" "$script" v1.2.3 "$out" >/dev/null 2>&1; then
    fail "$name unexpectedly succeeded"
  fi
  [ -z "$(find "$out" -mindepth 1 -print -quit)" ] || fail "$name left files in the output directory"
}

run_success "$tmp/success"
mkdir "$tmp/empty-existing"
run_success "$tmp/empty-existing"
"$script" v1.2.3 >/dev/null
run_success "$tmp/relative output"
run_success "$tmp/trailing-slash/"
mkdir "$tmp/non-empty"
printf 'keep\n' > "$tmp/non-empty/keep.txt"
if "$script" v1.2.3 "$tmp/non-empty" >/dev/null 2>&1; then
  fail "non-empty output directory unexpectedly succeeded"
fi
[ "$(cat "$tmp/non-empty/keep.txt")" = keep ] || fail "non-empty output directory changed"
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
  run_failure "missing-$file" "MOCK_MISSING=$file"
  run_failure "missing-bundle-$file" "MOCK_MISSING_BUNDLE=$file"
done

echo "mocked release verification passed"
