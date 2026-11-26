#!/usr/bin/env bash
# Opens the pull request that adds one stable release to microsoft/winget-pkgs.
# It verifies the release first (scripts/verify-client-release.sh), checks that the winget
# manifests attached to the release name exactly the MSI that SHA256SUMS covers, and then pushes
# the manifests to your fork of winget-pkgs. Microsoft validates and moderates the pull request.
set -euo pipefail

usage() {
  echo "usage: $0 <tag> [--dry-run]" >&2
  exit 2
}
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
tag=$1
dry_run=0
if [ "$#" -eq 2 ]; then
  [ "$2" = --dry-run ] || usage
  dry_run=1
fi
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "$tag is not a stable release tag: winget gets stable releases only" >&2
  exit 2
}
for tool in gh git; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 127; }
done

repo=${GH_REPO:-gaboe/open-pact}
version=${tag#v}
msi=open-pact-client-x86_64-pc-windows-msvc.msi
scripts=$(cd "$(dirname "$0")/.." && pwd -P)

verified=$("$scripts/verify-client-release.sh" "$tag" | tail -n 1)
verified=${verified#verified files: }
[ -f "$verified/SHA256SUMS" ] || { echo "the release check gave no SHA256SUMS" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work" "$verified"' EXIT

gh release download "$tag" --repo "$repo" --dir "$work/manifests" --pattern '*.yaml'
manifests=("$work"/manifests/*.yaml)
[ "${#manifests[@]}" -eq 3 ] || { echo "expected 3 winget manifests, found ${#manifests[@]}" >&2; exit 1; }
# One manifest of each type: version, installer, defaultLocale.
types=$(for manifest in "${manifests[@]}"; do sed -n 's/^ManifestType: *//p' "$manifest"; done | sort | tr '\n' ' ')
[ "$types" = "defaultLocale installer version " ] || { echo "unexpected manifest types: $types" >&2; exit 1; }

field() { sed -n "s/^\( *- \)\{0,1\} *$1: *\"\{0,1\}\([^\"]*\)\"\{0,1\} *$/\2/p" "$2" | head -n 1; }
installer=$(grep -l '^ManifestType: *installer *$' "${manifests[@]}")
id=$(field PackageIdentifier "$installer")
[ -n "$id" ] || { echo "no PackageIdentifier in $installer" >&2; exit 1; }
[ "$(basename "$installer")" = "$id.installer.yaml" ] || { echo "$installer is not named $id.installer.yaml" >&2; exit 1; }
# Exactly one installer: a second entry would go unchecked.
if [ "$(grep -c 'InstallerUrl:' "$installer")" -ne 1 ] || [ "$(grep -c 'InstallerSha256:' "$installer")" -ne 1 ]; then
  echo "$installer must list exactly one installer" >&2
  exit 1
fi
for manifest in "${manifests[@]}"; do
  [ "$(field PackageIdentifier "$manifest")" = "$id" ] || { echo "$manifest names another package" >&2; exit 1; }
  [ "$(field PackageVersion "$manifest")" = "$version" ] || { echo "$manifest names another version" >&2; exit 1; }
done

expected_url="https://github.com/$repo/releases/download/$tag/$msi"
[ "$(field InstallerUrl "$installer")" = "$expected_url" ] || {
  echo "InstallerUrl is not $expected_url" >&2
  exit 1
}
sum=$(awk -v f="$msi" '$2 == f { print $1 }' "$verified/SHA256SUMS")
manifest_sum=$(field InstallerSha256 "$installer" | tr '[:upper:]' '[:lower:]')
[ -n "$sum" ] && [ "$manifest_sum" = "$sum" ] || {
  echo "InstallerSha256 $manifest_sum does not match SHA256SUMS ($sum)" >&2
  exit 1
}

# winget-pkgs keeps manifests/<first letter>/<identifier parts>/<version>.
first=$(printf '%s' "${id:0:1}" | tr '[:upper:]' '[:lower:]')
dir="manifests/$first/${id//.//}/$version"
login=$(gh api user --jq .login)
email="$(gh api user --jq .id)+$login@users.noreply.github.com"
branch="$id-$version"
if gh api "repos/microsoft/winget-pkgs/contents/manifests/$first/${id//.//}" >/dev/null 2>&1; then
  title="New version: $id version $version"
else
  title="New package: $id version $version"
fi

echo "verified: $id $version, $msi sha256 $sum"
echo "pull request: $title, branch $login:$branch, path $dir"
if [ "$dry_run" -eq 1 ]; then
  exit 0
fi
existing=$(gh pr list --repo microsoft/winget-pkgs --author "$login" --head "$branch" --state open --json url --jq '.[0].url // empty')
if [ -n "$existing" ]; then
  echo "already open: $existing"
  exit 0
fi

gh repo fork microsoft/winget-pkgs --clone=false >/dev/null 2>&1 || true
# GitHub creates a fork asynchronously: wait until its master branch exists.
for _ in $(seq 1 30); do
  gh api "repos/$login/winget-pkgs/branches/master" >/dev/null 2>&1 && break
  sleep 5
done
gh repo sync "$login/winget-pkgs" --branch master
gh repo clone "$login/winget-pkgs" "$work/winget-pkgs" -- --quiet --depth 1 --filter=blob:none --no-checkout --branch master
cd "$work/winget-pkgs"
git sparse-checkout set "$dir"
git checkout --quiet master
git checkout --quiet -b "$branch"
mkdir -p "$dir"
cp "${manifests[@]}" "$dir/"
git add "$dir"
GIT_AUTHOR_NAME=$login GIT_AUTHOR_EMAIL=$email GIT_COMMITTER_NAME=$login GIT_COMMITTER_EMAIL=$email \
  git -c user.name="$login" -c user.email="$email" commit --quiet -m "$title"
# The branch belongs to this script in the caller's fork: a rerun after a failed PR step replaces it.
git push --quiet --force -u origin "$branch"
gh pr create --repo microsoft/winget-pkgs --head "$login:$branch" --base master --title "$title" --body \
  "Release: https://github.com/$repo/releases/tag/$tag. The manifests are the ones attached to the release. The installer hash matches the Sigstore-verified SHA256SUMS of the release."
