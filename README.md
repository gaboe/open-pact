# open-pact desktop apps

Optional desktop apps for [open-pact](https://github.com/gaboe/open-pact). `open-pact` joins a company, reviews manifests, and sends device checks. `open-pact-admin` edits deployment manifests and manages devices.

The apps only run `open-pact-client`, `kubectl`, and `git`. They never call the gateway or Kubernetes APIs directly. The collapsed Terminal panel shows each command, its output, and its exit code.

## Build the apps

Install Rust 1.99 or later. Windows also needs LLVM with `llvm-rc` on PATH.

```sh
cargo build --workspace
cargo run -p open-pact-app
cargo run -p open-pact-admin
```

For an unbundled client build, put `open-pact-client` next to the app executable. The app compares CLI versions. A matching CLI on PATH skips installation. Otherwise the app installs the bundled CLI to `~/.local/bin` on macOS or `%LOCALAPPDATA%\open-pact` on Windows.

On macOS, make ad hoc signed bundles with the installed CLI.

```sh
scripts/build-macos.sh "$(command -v open-pact-client)"
```

The bundles appear in `dist`. The client bundle contains the CLI in `Contents/Helpers`.

## Set up the admin app

Install `git` and `kubectl`. Enter the deployment repository, a relative manifest file path, a kube context, and a namespace. Leave the file empty to find the single YAML file with open-pact Helm values and a literal `manifest` block. The app saves settings in the OS config directory under `open-pact-admin/settings.json`.

Form and TOML edit one text. Review shows the diff and commands before applying. The deployment repository must have no local changes. Apply pulls with `--ff-only`, writes the manifest block, commits, pushes, and waits for a deployment restart and the expected manifest hash.

A failed push can leave the outcome unknown. Inspect the repository and refresh gateway status before retrying. Gateway JSON commands require the open-pact `cli-json` changes.

## Verify changes

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --features snapshot
```

Tests use fictional JSON and command fixtures. They need no cluster or network. Shell command fixtures run on Unix. Manifest tests also run on Windows. On macOS, set `OPEN_PACT_SHOTS` to an existing directory when running either snapshot binary through the approved GPUI snapshot runner.

Ubuntu CI is not enabled. It needs Linux graphics development packages and a separate successful build receipt.
