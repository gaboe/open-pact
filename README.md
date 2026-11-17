# open-pact desktop apps

Optional desktop apps for [open-pact](https://github.com/gaboe/open-pact). `open-pact` joins a company, reviews manifests, and sends device checks. `open-pact-admin` edits deployment manifests and manages devices.

The apps only run `open-pact-client`, `kubectl`, and the OS folder opener (`open` or `explorer`, for the admin backup folder). They never call the gateway or Kubernetes APIs directly. The Terminal strip at the bottom of each window opens to show each command, its input, output, and exit code.

## Install

The apps are not code signed (Windows) and not notarized by Apple (macOS). The installers below avoid the macOS dialog that blocks a browser download: `curl` leaves no quarantine mark, and each installer checks the download against the SHA-256 published with the release before it replaces anything. The Windows apps may show a SmartScreen warning the first time.

**macOS.** Run this line in Terminal. It installs `open-pact.app` and `open-pact-admin.app` to `~/Applications`, verifies their signatures, and opens `open-pact`.

```sh
curl -fsSL https://raw.githubusercontent.com/gaboe/open-pact-desktop/main/scripts/install-desktop.sh | sh
```

`OPEN_PACT_DESKTOP_VERSION=0.1.0` installs one version. `OPEN_PACT_INSTALL_DIR` changes the folder. `OPEN_PACT_NO_OPEN=1` skips opening the app. The installer quits a running copy first.

**Windows, with scoop (preferred).**

```powershell
scoop bucket add gaboe https://github.com/gaboe/scoop-bucket
scoop install open-pact-desktop
```

Scoop adds Start menu shortcuts for `open-pact` and `open-pact admin` and puts `open-pact-client` on PATH.

**Windows, without scoop.** Run this line in PowerShell. It installs to `%LOCALAPPDATA%\open-pact-desktop` and creates the Start menu shortcuts.

```powershell
irm https://raw.githubusercontent.com/gaboe/open-pact-desktop/main/scripts/install-desktop.ps1 | iex
```

Both releases bundle the `open-pact-client` version named in `cli-version`. The release workflow downloads it from the open-pact release and verifies the Sigstore signature of `SHA256SUMS` and every hash before it packs it.

## Update

Run the same install line again, or `scoop update open-pact-desktop`. Both apps also tell you: a strip at the top of the window says "open-pact desktop 0.1.1 is available" with an **Update** button. The button runs the installer above (or `scoop update open-pact-desktop` when the app lives in a scoop folder) and shows the command in the Terminal strip. A direct install goes to the folder that holds the running app. Close both apps before `scoop update` on Windows, because Windows keeps a running program locked.

**What the update check sends.** At start, then every 24 hours, each app runs `curl -fsSL -m 5 https://api.github.com/repos/gaboe/open-pact-desktop/releases/latest` (`curl.exe` on Windows). That is a plain GET to GitHub. GitHub sees your IP address and the curl user agent. The apps send nothing about you, your company, or your device. A failed check shows nothing and stays in the Terminal strip. Set `OPEN_PACT_NO_UPDATE_CHECK=1` to turn the check off.

When the command line tool reports a newer `open-pact-client` (`update` in `status --online --json`), the `open-pact` status screen shows "Command line tool 0.6.1 is available". The tool's `command` runs from the **Update** button. With no command, the app update brings the new tool.

## Release

Maintainers: set the workspace version in `Cargo.toml` and merge. Push an annotated tag `vX.Y.Z` on that commit. `.github/workflows/release.yml` builds universal macOS apps and Windows x64 apps, bundles the verified command line tool, and attaches these files to the GitHub release.

- `open-pact-desktop-X.Y.Z-macos.zip` and `.sha256`
- `open-pact-desktop-X.Y.Z-windows-x64.zip` and `.sha256`
- `open-pact-desktop.json`, the scoop manifest

The workflow holds no secret beyond `GITHUB_TOKEN`, so it cannot write to the scoop bucket. After a release (not a prerelease such as `v0.2.0-rc.1`), commit `open-pact-desktop.json` as `bucket/open-pact-desktop.json` in `gaboe/scoop-bucket`. A prerelease tag publishes assets only, and the update check ignores it. To bundle a newer command line tool, change `cli-version` in the same commit.

## Build the apps

Install Rust 1.99 or later. The macOS bundle script also needs `bun`. Windows also needs LLVM with `llvm-rc` on PATH.

```sh
cargo build --workspace
cargo run -p open-pact-app
cargo run -p open-pact-admin
```

For an unbundled client build, put `open-pact-client` next to the app executable. At start, each app reads the login shell PATH once (`$SHELL -lc`, 5 second limit; `/opt/homebrew/bin` and `/usr/local/bin` are always added after it when missing), because an app started from Finder has only the short system PATH. Every child process gets that PATH. The client then compares CLI versions. A CLI on that PATH, or in the install folder, that is as new as the bundled one skips installation. With none, or only an older one, the app installs the bundled CLI to `~/.local/bin` on macOS or `%LOCALAPPDATA%\open-pact` on Windows.

On macOS, make ad hoc signed bundles with the installed CLI.

```sh
scripts/build-macos.sh "$(command -v open-pact-client)"
```

The bundles appear in `dist`. Both bundles contain the CLI in `Contents/Helpers`. The admin app checks manifests with that copy first. Each bundle carries its icon from `assets` (`CFBundleIconFile`). On Windows, `build.rs` embeds the `.ico` in each executable. The icon sources and their prompts are in `design/brand`.

## Set up the admin app

Install `kubectl` and log in to your cluster. Pick the cluster from the dropdown that the app fills with `kubectl config get-contexts -o name`; it preselects the saved cluster, else `kubectl config current-context`. Pick the namespace from the dropdown that the app fills with `kubectl get namespaces -o name --context <cluster>` and reloads when the cluster changes; it preselects the saved namespace, else `open-pact`, else the first one. When kubectl cannot list namespaces (no right to, cluster unreachable, login needed), the app keeps a text field with `open-pact` and shows the kubectl error. With no contexts, both fields are text fields. Leave the kubectl path empty to search PATH, or enter the full path. These commands use the same PATH, timeout, and Terminal log as every other command.

The app chooses the local backup folder: `open-pact-admin/backups/<cluster>/<namespace>` in the OS app data directory. Settings shows it read-only with an **Open in Finder** button (`open <folder>` on macOS, `explorer <folder>` on Windows). An old `backup_dir` entry in `settings.json` is ignored. The app saves settings in the OS config directory under `open-pact-admin/settings.json`.

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
