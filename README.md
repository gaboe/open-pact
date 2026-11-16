# open-pact desktop apps

Optional desktop apps for [open-pact](https://github.com/gaboe/open-pact). `open-pact` joins a company, reviews manifests, and sends device checks. `open-pact-admin` edits deployment manifests and manages devices.

The apps only run `open-pact-client` and `kubectl`. They never call the gateway or Kubernetes APIs directly. The Terminal strip at the bottom of each window opens to show each command, its input, output, and exit code.

## Build the apps

Install Rust 1.99 or later. The macOS bundle script also needs `bun`. Windows also needs LLVM with `llvm-rc` on PATH.

```sh
cargo build --workspace
cargo run -p open-pact-app
cargo run -p open-pact-admin
```

For an unbundled client build, put `open-pact-client` next to the app executable. At start, each app reads the login shell PATH once (`$SHELL -lc`, 5 second limit; Homebrew and `/usr/local/bin` are added when that fails), because an app started from Finder has only the short system PATH. Every child process gets that PATH. The client then compares CLI versions. A CLI on that PATH, or in the install folder, that is as new as the bundled one skips installation. With none, or only an older one, the app installs the bundled CLI to `~/.local/bin` on macOS or `%LOCALAPPDATA%\open-pact` on Windows.

On macOS, make ad hoc signed bundles with the installed CLI.

```sh
scripts/build-macos.sh "$(command -v open-pact-client)"
```

The bundles appear in `dist`. The client bundle contains the CLI in `Contents/Helpers`.

## Set up the admin app

Install `kubectl`. Enter the cluster and namespace. Leave the kubectl path empty to search PATH, or enter the full path. Leave the local backup folder empty to use `open-pact-admin/backups/<cluster>/<namespace>` in the OS app data directory, or enter an absolute path. The app saves settings in the OS config directory under `open-pact-admin/settings.json`.

Form and TOML edit one text. Review shows the diff and commands before applying. Apply saves the active TOML locally, pipes the new TOML to `manifest set --note=<note> --json` through `kubectl exec -i`, and polls gateway status for up to 60 seconds. The gateway loads the stored manifest within 10 seconds, without a restart. Every kubectl call stops after 60 seconds. If another admin made a different manifest active after your review, the app says so and names its hash. That manifest stays in the server history.

History sync runs on app open and with **Sync now**. It downloads every missing server version and checks its hash. A backup file whose content does not match the hash in its name is skipped with a warning and is never offered for restore. Each server version and local backup has a **Restore** action. Restore shows a diff against the active manifest and asks once. Server versions use `manifest activate`; a local file absent from server history uses `manifest set`. Every write backs up the active manifest first.

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
