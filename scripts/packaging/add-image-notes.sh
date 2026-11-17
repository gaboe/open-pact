#!/usr/bin/env bash
# Add the image digests to the notes of the release that client-release.yml
# created for this tag. This script never creates a release and never changes
# its draft or prerelease state: client-release.yml alone creates, checks and
# publishes it.
#
# Needs GH_TOKEN, GH_REPO, TAG, GATEWAY_IMAGE, WITNESS_IMAGE, GATEWAY_DIGEST and
# WITNESS_DIGEST. WAIT_ATTEMPTS (default 30) and WAIT_SECONDS (default 20) bound
# the wait for the release.
set -euo pipefail

: "${TAG:?TAG is required}"
: "${GATEWAY_IMAGE:?GATEWAY_IMAGE is required}"
: "${WITNESS_IMAGE:?WITNESS_IMAGE is required}"
: "${GATEWAY_DIGEST:?GATEWAY_DIGEST is required}"
: "${WITNESS_DIGEST:?WITNESS_DIGEST is required}"
attempts=${WAIT_ATTEMPTS:-30}
pause=${WAIT_SECONDS:-20}

found=
for ((attempt = 1; attempt <= attempts; attempt++)); do
  if gh release view "$TAG" >/dev/null 2>&1; then
    found=1
    break
  fi
  if ((attempt < attempts)); then
    echo "No release for $TAG yet (attempt $attempt of $attempts). Waiting $pause s."
    sleep "$pause"
  fi
done
if [[ -z "$found" ]]; then
  echo "::error::No release for $TAG appeared after $attempts attempts. client-release.yml creates it; check that run." >&2
  exit 1
fi

gateway_ref="${GATEWAY_IMAGE}@${GATEWAY_DIGEST}"
witness_ref="${WITNESS_IMAGE}@${WITNESS_DIGEST}"
body=$(gh release view "$TAG" --json body --jq .body)
if [[ "$body" == *"$gateway_ref"* && "$body" == *"$witness_ref"* ]]; then
  echo "The notes of $TAG already name both image digests."
  exit 0
fi

note="Image digests (each rebuilt independently, identical):
- gateway: \`$gateway_ref\`
- witness: \`$witness_ref\`
Verify with \`scripts/verify-release.sh $TAG $gateway_ref\` and \`scripts/verify-release.sh --target witness $TAG $witness_ref\`."
if [[ -n "$body" ]]; then
  note="$body"$'\n\n'"$note"
fi
gh release edit "$TAG" --notes "$note"
