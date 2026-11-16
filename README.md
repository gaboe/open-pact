# open-pact desktop apps

Optional desktop apps for [open-pact](https://github.com/gaboe/open-pact). `open-pact` joins a company, reviews manifests, and sends device checks. `open-pact-admin` edits deployment manifests and manages devices.

The apps only run `open-pact-client` and `kubectl`. They never call the gateway or Kubernetes APIs directly. The Terminal strip at the bottom of each window opens to show each command, its input, output, and exit code.

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

Install `kubectl`. Enter the cluster, namespace, and local backup folder. The default backup folder is `open-pact-admin/backups` in the OS app data directory. The app saves settings in the OS config directory under `open-pact-admin/settings.json`.

Form and TOML edit one text. Review shows the diff and commands before applying. Apply saves the active TOML locally, pipes the new TOML to `manifest set --note <note> --json` through `kubectl exec -i`, and polls gateway status for up to 60 seconds. The gateway picks up the change without a restart.

History sync runs on app open and with **Sync now**. It downloads every missing server version and checks its hash. Each server version and local backup has a **Restore** action. Restore shows a diff against the active manifest and asks once. Server versions use `manifest activate`; a local file absent from server history uses `manifest set`. Every write backs up the active manifest first.

A lost write response leaves the outcome unknown. Refresh gateway status before retrying. The app needs the gateway manifest version commands and the client JSON commands.

## Verify changes

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --features snapshot
```

Tests use fictional JSON and command fixtures. They need no cluster or network. Shell command fixtures run on Unix. Manifest tests also run on Windows. On macOS, set `OPEN_PACT_SHOTS` to an existing directory when running either snapshot binary through the approved GPUI snapshot runner.

Ubuntu CI is not enabled. It needs Linux graphics development packages and a separate successful build receipt.
