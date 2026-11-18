# Agent instructions

## Release the client and the desktop apps

One annotated tag publishes the CLI, the gateway image, and both desktop apps from this repository.

1. Set the same version in the root `Cargo.toml` and in `desktop/Cargo.toml` (`[workspace.package]`), refresh `desktop/Cargo.lock` (`cd desktop && cargo metadata --format-version 1 > /dev/null`), merge to `main`, and wait for green CI. The release stops at its first job when the tag and both versions differ.
2. Push an annotated tag `vX.Y.Z` on that `main` commit. `client-release.yml` builds the CLI, packages it, builds both desktop apps from the same run, signs every asset in a separate `sign` job, uploads them to a draft release, checks every asset, and then publishes it. Only that workflow creates and publishes the release. `image.yml` checks the same version gate before it pushes a tag image, then waits for the release and adds the image digests to its notes. `SHA256SUMS` and its Cosign bundle cover the desktop zips. The `sign` job is the only job with `id-token: write`. It runs only the download, upload, and Cosign installer actions, each pinned by commit SHA, so no build or release tool can mint the signature. Update a pin only with the commit SHA of the new release tag.
3. The repository has no `PACKAGING_TOKEN` secret on purpose: Actions holds no write token for other repositories. The release job prints a warning and attaches `open-pact.rb`, `open-pact.json`, and `open-pact-desktop.json` to the release. Do not add the secret unless the owner asks for it.
4. Publish the package metadata by hand after the release job succeeds:
   1. Download `open-pact.rb`, `open-pact.json`, `open-pact-desktop.json`, `SHA256SUMS`, and `SHA256SUMS.sigstore.json` from the release.
   2. Verify `SHA256SUMS` with Cosign, as in [docs/client.md](docs/client.md#verify-a-release).
   3. Check that every hash in the formula and the manifests matches `SHA256SUMS`.
   4. Commit `open-pact.rb` as `Formula/open-pact.rb` in [gaboe/homebrew-tap](https://github.com/gaboe/homebrew-tap) and push.
   5. Commit `open-pact.json` as `bucket/open-pact.json` and `open-pact-desktop.json` as `bucket/open-pact-desktop.json` in [gaboe/scoop-bucket](https://github.com/gaboe/scoop-bucket) and push.
5. A prerelease tag, such as `v0.3.2-rc.1`, publishes assets only. Skip step 4 for it. Set the prerelease version in both `Cargo.toml` files before you tag.
