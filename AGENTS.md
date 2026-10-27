# Agent instructions

## Release the client

1. Set the workspace version in `Cargo.toml`, merge to `main`, and wait for green CI.
2. Push an annotated tag `vX.Y.Z` on that `main` commit. `client-release.yml` builds, packages, signs, and attaches the release assets.
3. The repository has no `PACKAGING_TOKEN` secret on purpose: Actions holds no write token for other repositories. The release job prints a warning and attaches `open-pact.rb` and `open-pact.json` to the release. Do not add the secret unless the owner asks for it.
4. Publish the package metadata by hand after the release job succeeds:
   1. Download `open-pact.rb`, `open-pact.json`, `SHA256SUMS`, and `SHA256SUMS.sigstore.json` from the release.
   2. Verify `SHA256SUMS` with Cosign, as in [docs/client.md](docs/client.md#verify-a-release).
   3. Check that every hash in the formula and the manifest matches `SHA256SUMS`.
   4. Commit `open-pact.rb` as `Formula/open-pact.rb` in [gaboe/homebrew-tap](https://github.com/gaboe/homebrew-tap) and push.
   5. Commit `open-pact.json` as `bucket/open-pact.json` in [gaboe/scoop-bucket](https://github.com/gaboe/scoop-bucket) and push.
5. A prerelease tag, such as `v0.3.2-rc.1`, publishes assets only. Skip step 4 for it.
