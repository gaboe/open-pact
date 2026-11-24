//! The check for a newer desktop release and the command that installs it. Everything here is
//! pure or runs through the `Runner`, so the Terminal strip shows each command.

use crate::{Runner, args, client::version_key};
use serde_json::Value;
use std::time::Duration;

/// The repository that releases this app. The release workflow sets `OPEN_PACT_REPOSITORY` when it
/// builds, so a fork's build updates from the fork.
pub const REPOSITORY: &str = match option_env!("OPEN_PACT_REPOSITORY") {
    Some(repository) => repository,
    None => DEFAULT_REPOSITORY,
};
const DEFAULT_REPOSITORY: &str = "gaboe/open-pact";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
pub const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
const SCOOP_PACKAGE: &str = "open-pact-desktop";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Mac,
    Windows,
    Other,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Mac
        } else {
            Self::Other
        }
    }
}

/// A program, its arguments, and the environment variables it adds, as the Runner runs and the
/// Terminal strip shows them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

impl Invocation {
    fn new(program: &str, words: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args(words),
            env: Vec::new(),
        }
    }
}

/// `OPEN_PACT_NO_UPDATE_CHECK` set to anything but empty or `0` turns the check off.
pub fn checks_enabled(variable: Option<&str>) -> bool {
    matches!(variable, None | Some("" | "0"))
}

/// The call for the latest release. Both platforms ship curl.
pub fn check_invocation(platform: Platform) -> Invocation {
    Invocation::new(
        if platform == Platform::Windows {
            "curl.exe"
        } else {
            "curl"
        },
        &[
            "-fsSL",
            "-m",
            "5",
            &format!("https://api.github.com/repos/{REPOSITORY}/releases/latest"),
        ],
    )
}

/// The version in `tag_name` of a GitHub release document, without a leading `v`.
pub fn latest_version(release: &str) -> Option<String> {
    let value: Value = serde_json::from_str(release).ok()?;
    let tag = value.get("tag_name")?.as_str()?.trim();
    let version = tag.strip_prefix('v').unwrap_or(tag);
    version_key(version).map(|_| version.to_owned())
}

/// True when `latest` is a higher version than `current`. A prerelease sorts before its release.
pub fn newer(latest: &str, current: &str) -> bool {
    matches!((version_key(latest), version_key(current)), (Some(latest), Some(current)) if latest > current)
}

fn under_scoop(exe: &str) -> bool {
    let parts: Vec<String> = exe
        .split(['/', '\\'])
        .map(str::to_ascii_lowercase)
        .collect();
    parts
        .windows(2)
        .any(|pair| pair[0] == "apps" && pair[1] == SCOOP_PACKAGE)
}

/// The command that installs the newest release. `exe` is the path of the running app. There is
/// none on Linux, where the apps have no installer.
/// The folder a direct install goes to: the folder that holds the running `.app` bundle on macOS,
/// and the folder of the exe on Windows.
fn install_folder(platform: Platform, exe: &str) -> Option<&str> {
    match platform {
        Platform::Mac => {
            let mut path = exe;
            loop {
                let folder = parent(path)?;
                if last_segment(folder).ends_with(".app") {
                    return parent(folder);
                }
                path = folder;
            }
        }
        Platform::Windows => parent(exe),
        Platform::Other => None,
    }
}

fn parent(path: &str) -> Option<&str> {
    path.rfind(['/', '\\'])
        .map(|index| &path[..index])
        .filter(|folder| !folder.is_empty())
}

fn last_segment(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn install_dir_env(platform: Platform, exe: &str) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = install_folder(platform, exe)
        .map(|folder| vec![("OPEN_PACT_INSTALL_DIR".to_owned(), folder.to_owned())])
        .unwrap_or_default();
    // The install script reads this repository. Always pass the compiled one, so an inherited
    // value cannot switch the repository between the update check and the install.
    env.push(("OPEN_PACT_REPOSITORY".to_owned(), REPOSITORY.to_owned()));
    env
}

/// The folder of the install scripts in the source of the release `version`, not of `main`.
fn scripts_url(version: &str) -> String {
    format!("https://raw.githubusercontent.com/{REPOSITORY}/v{version}/desktop/scripts")
}

/// Downloads the installer to a temporary file and runs it. A failed download fails the command.
fn mac_installer_script(version: &str) -> String {
    let scripts = scripts_url(version);
    format!(
        "set -e; installer=$(mktemp) && trap 'rm -f \"$installer\"' EXIT && curl -fsSL -o \"$installer\" {scripts}/install-desktop.sh && sh \"$installer\""
    )
}

fn windows_installer_script(version: &str) -> String {
    let scripts = scripts_url(version);
    format!(
        "$ErrorActionPreference = 'Stop'; $installer = Join-Path $env:TEMP ('open-pact-install-' + [Guid]::NewGuid().ToString('N') + '.ps1'); try {{ Invoke-WebRequest -UseBasicParsing -Uri '{scripts}/install-desktop.ps1' -OutFile $installer; Invoke-Expression (Get-Content -Raw -Path $installer) }} finally {{ Remove-Item -Path $installer -Force -ErrorAction SilentlyContinue }}"
    )
}

/// The command that installs the newest release, `version`. The install script comes from the
/// tag of that release. `exe` is the path of the running app. There is none on Linux, where the
/// apps have no installer. Only a direct install gets the folder of the running app; scoop keeps
/// its own folder.
pub fn update_invocation(platform: Platform, exe: &str, version: &str) -> Option<Invocation> {
    match platform {
        Platform::Mac => Some(Invocation {
            program: "sh".into(),
            args: args(&["-c", &mac_installer_script(version)]),
            env: install_dir_env(platform, exe),
        }),
        Platform::Windows if under_scoop(exe) => Some(shell_invocation(
            platform,
            &format!("scoop update {SCOOP_PACKAGE}"),
        )),
        Platform::Windows => Some(Invocation {
            env: install_dir_env(platform, exe),
            ..shell_invocation(platform, &windows_installer_script(version))
        }),
        Platform::Other => None,
    }
}

/// Runs one command line in the platform shell. PowerShell finds `scoop`, which is a script.
pub fn shell_invocation(platform: Platform, line: &str) -> Invocation {
    if platform == Platform::Windows {
        Invocation::new("powershell", &["-NoProfile", "-Command", line])
    } else {
        Invocation::new("sh", &["-c", line])
    }
}

/// What the banner knows about an update.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum UpdateState {
    #[default]
    None,
    Available(String),
    Running(String),
    Failed(String, String),
    Done(String),
}

impl UpdateState {
    /// The state after a check. A running or finished update keeps its state.
    pub fn after_check(self, found: Option<String>) -> Self {
        match (self, found) {
            (state @ Self::Running(_), _) => state,
            (Self::Done(done), Some(found)) if done == found => Self::Done(done),
            (_, Some(found)) => Self::Available(found),
            (_, None) => Self::None,
        }
    }

    pub fn text(&self) -> Option<String> {
        match self {
            Self::None => None,
            Self::Available(version) => Some(format!("open-pact desktop {version} is available")),
            Self::Running(version) => Some(format!("Updating open-pact desktop to {version}")),
            Self::Failed(version, error) => Some(format!("Update to {version} failed: {error}")),
            Self::Done(version) => Some(format!(
                "open-pact desktop {version} is installed. Reopen the app to use it."
            )),
        }
    }

    pub fn button(&self) -> Option<&'static str> {
        match self {
            Self::Available(_) => Some("Update"),
            Self::Failed(..) => Some("Try again"),
            _ => None,
        }
    }

    pub fn running(&self) -> bool {
        matches!(self, Self::Running(_))
    }

    /// The version an update would install, when one may start now.
    pub fn startable(&self) -> Option<&str> {
        match self {
            Self::Available(version) | Self::Failed(version, _) => Some(version),
            _ => None,
        }
    }
}

/// The newer version GitHub lists, when there is one.
pub fn check(runner: &Runner) -> Result<Option<String>, String> {
    let call = check_invocation(Platform::current());
    let log = runner.run(std::path::Path::new(&call.program), &call.args)?;
    let latest = latest_version(&log.stdout).ok_or("The release has no usable version")?;
    Ok(newer(&latest, CURRENT).then_some(latest))
}

pub fn run(runner: &Runner, call: &Invocation) -> Result<(), String> {
    runner
        .with_timeout(Duration::from_secs(600))
        .with_env(&call.env)
        .run(std::path::Path::new(&call.program), &call.args)
        .map(|_| ())
}

/// The row for a newer command line tool. The second part is the command that updates it, or
/// `None` when the app update brings the tool.
pub fn cli_notice<'a>(latest: &str, command: Option<&'a str>) -> (String, Option<&'a str>) {
    let command = command.filter(|c| !c.trim().is_empty());
    let mut text = format!("Command line tool {latest} is available");
    if command.is_none() {
        text.push_str(". The app update brings it.");
    }
    (text, command)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOOP: &str = r"C:\Users\fictional\scoop\apps\open-pact-desktop\current\open-pact.exe";

    #[test]
    fn newer_compares_numbers_not_text() {
        assert!(newer("0.1.1", "0.1.0"));
        assert!(newer("v0.10.0", "0.9.0"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.1.0", "0.2.0"));
        assert!(newer("0.2.0", "0.2.0-rc.1"));
        assert!(!newer("0.2.0-rc.1", "0.2.0"));
        assert!(!newer("latest", "0.1.0"));
    }

    #[test]
    fn the_release_document_gives_its_version_or_nothing() {
        assert_eq!(
            latest_version(r#"{"tag_name":"v0.1.1"}"#).as_deref(),
            Some("0.1.1")
        );
        assert_eq!(
            latest_version(r#"{"tag_name":"0.2.0"}"#).as_deref(),
            Some("0.2.0")
        );
        assert_eq!(latest_version(r#"{"tag_name":"nightly"}"#), None);
        assert_eq!(latest_version(r#"{"message":"Not Found"}"#), None);
        assert_eq!(latest_version("not json"), None);
    }

    #[test]
    fn the_check_can_be_switched_off() {
        assert!(checks_enabled(None));
        assert!(checks_enabled(Some("")));
        assert!(checks_enabled(Some("0")));
        assert!(!checks_enabled(Some("1")));
    }

    /// Only a build without `OPEN_PACT_REPOSITORY` is the upstream build, so only it must name
    /// the upstream repository.
    #[test]
    fn the_default_build_updates_from_this_repository() {
        if option_env!("OPEN_PACT_REPOSITORY").is_none() {
            assert_eq!(REPOSITORY, "gaboe/open-pact");
        }
    }

    #[test]
    fn the_scripts_come_from_the_compiled_repository() {
        assert_eq!(
            scripts_url("0.8.1"),
            format!("https://raw.githubusercontent.com/{REPOSITORY}/v0.8.1/desktop/scripts")
        );
    }

    /// The installer reads the repository from its environment, so a direct update always names
    /// the repository that this build was compiled for, in a default build too.
    #[test]
    fn a_direct_update_always_names_the_compiled_repository() {
        let mac = update_invocation(
            Platform::Mac,
            "/Applications/Open Pact.app/Contents/MacOS/open-pact-desktop",
            "0.9.0",
        )
        .unwrap();
        let windows = update_invocation(
            Platform::Windows,
            r"C:\Users\Contoso\AppData\Local\open-pact-desktop\open-pact-desktop.exe",
            "0.9.0",
        )
        .unwrap();
        for invocation in [mac, windows] {
            assert!(
                invocation
                    .env
                    .contains(&("OPEN_PACT_REPOSITORY".to_owned(), REPOSITORY.to_owned()))
            );
        }
    }

    #[test]
    fn the_check_uses_curl_with_a_five_second_limit() {
        let mac = check_invocation(Platform::Mac);
        let url = format!("https://api.github.com/repos/{REPOSITORY}/releases/latest");
        assert_eq!(mac.program, "curl");
        assert_eq!(mac.args, ["-fsSL", "-m", "5", url.as_str()]);
        assert_eq!(check_invocation(Platform::Windows).program, "curl.exe");
    }

    #[test]
    fn each_platform_updates_in_its_own_way() {
        let mac = update_invocation(
            Platform::Mac,
            "/Users/fictional/Applications/open-pact.app/Contents/MacOS/open-pact",
            "0.8.1",
        )
        .unwrap();
        assert_eq!(mac.program, "sh");
        assert_eq!(mac.args[0], "-c");
        assert!(mac.args[1].contains("/open-pact/v0.8.1/desktop/scripts/install-desktop.sh"));
        assert!(!mac.args[1].contains("/main/"));
        let scoop = update_invocation(Platform::Windows, SCOOP, "0.8.1").unwrap();
        assert_eq!(scoop.program, "powershell");
        assert_eq!(
            scoop.args,
            ["-NoProfile", "-Command", "scoop update open-pact-desktop"]
        );
        let custom = update_invocation(
            Platform::Windows,
            r"D:\Tools\Scoop\APPS\open-pact-desktop\1.0\open-pact-admin.exe",
            "0.8.1",
        )
        .unwrap();
        assert!(custom.args[2].starts_with("scoop update"));
        let plain = update_invocation(
            Platform::Windows,
            r"C:\Users\fictional\AppData\Local\open-pact-desktop\open-pact.exe",
            "0.8.1",
        )
        .unwrap();
        assert!(plain.args[2].contains("/open-pact/v0.8.1/desktop/scripts/install-desktop.ps1"));
        let other_package = update_invocation(
            Platform::Windows,
            r"C:\scoop\apps\another\current\open-pact.exe",
            "0.8.1",
        )
        .unwrap();
        assert!(
            other_package.args[2].contains("/open-pact/v0.8.1/desktop/scripts/install-desktop.ps1")
        );
        assert_eq!(
            update_invocation(Platform::Other, "/usr/bin/open-pact", "0.8.1"),
            None
        );
    }

    #[test]
    fn a_command_line_runs_in_the_platform_shell() {
        assert_eq!(
            shell_invocation(Platform::Mac, "brew upgrade x").args,
            ["-c", "brew upgrade x"]
        );
        let windows = shell_invocation(Platform::Windows, "winget upgrade x");
        assert_eq!(windows.program, "powershell");
        assert_eq!(windows.args[2], "winget upgrade x");
    }

    #[test]
    fn the_banner_follows_the_update_through_its_states() {
        let available = UpdateState::None.after_check(Some("0.1.1".into()));
        assert_eq!(
            available.text().as_deref(),
            Some("open-pact desktop 0.1.1 is available")
        );
        assert_eq!(available.button(), Some("Update"));
        assert_eq!(available.startable(), Some("0.1.1"));
        assert_eq!(
            UpdateState::Available("0.1.1".into()).after_check(None),
            UpdateState::None
        );
        assert_eq!(UpdateState::None.text(), None);
        let running = UpdateState::Running("0.1.1".into());
        assert!(running.running());
        assert_eq!(running.button(), None);
        assert_eq!(running.clone().after_check(Some("0.1.2".into())), running);
        let failed = UpdateState::Failed("0.1.1".into(), "no network".into());
        assert_eq!(
            failed.text().as_deref(),
            Some("Update to 0.1.1 failed: no network")
        );
        assert_eq!(failed.button(), Some("Try again"));
        let done = UpdateState::Done("0.1.1".into());
        assert_eq!(done.clone().after_check(Some("0.1.1".into())), done);
        assert_eq!(
            done.after_check(Some("0.1.2".into())),
            UpdateState::Available("0.1.2".into())
        );
    }

    #[test]
    fn the_command_line_tool_row_names_its_command_or_the_app_update() {
        assert_eq!(
            cli_notice("0.6.1", Some("brew upgrade open-pact-client")),
            (
                "Command line tool 0.6.1 is available".to_owned(),
                Some("brew upgrade open-pact-client")
            )
        );
        assert_eq!(
            cli_notice("0.6.1", None),
            (
                "Command line tool 0.6.1 is available. The app update brings it.".to_owned(),
                None
            )
        );
        assert_eq!(cli_notice("0.6.1", Some("  ")).1, None);
    }

    #[test]
    fn the_update_installs_into_the_folder_the_app_runs_from() {
        let mac = update_invocation(
            Platform::Mac,
            "/Users/fictional/Tools/op/open-pact.app/Contents/MacOS/open-pact",
            "0.8.1",
        )
        .unwrap();
        assert_eq!(
            mac.env,
            [
                (
                    "OPEN_PACT_INSTALL_DIR".to_owned(),
                    "/Users/fictional/Tools/op".to_owned()
                ),
                ("OPEN_PACT_REPOSITORY".to_owned(), REPOSITORY.to_owned()),
            ]
        );
        let plain = update_invocation(
            Platform::Windows,
            r"C:\Users\fictional\AppData\Local\open-pact-desktop\open-pact.exe",
            "0.8.1",
        )
        .unwrap();
        assert_eq!(
            plain.env,
            [
                (
                    "OPEN_PACT_INSTALL_DIR".to_owned(),
                    r"C:\Users\fictional\AppData\Local\open-pact-desktop".to_owned()
                ),
                ("OPEN_PACT_REPOSITORY".to_owned(), REPOSITORY.to_owned()),
            ]
        );
        assert!(
            update_invocation(Platform::Windows, SCOOP, "0.8.1")
                .unwrap()
                .env
                .is_empty()
        );
        let bare =
            update_invocation(Platform::Mac, "/Users/fictional/dev/open-pact", "0.8.1").unwrap();
        assert_eq!(
            bare.env,
            [("OPEN_PACT_REPOSITORY".to_owned(), REPOSITORY.to_owned())]
        );
    }

    #[cfg(unix)]
    const FAKE_CURL_DOWNLOADS: &str = r#"out=; while [ $# -gt 0 ]; do if [ "$1" = -o ]; then out=$2; fi; shift; done; printf '%s\n' 'touch "$OPEN_PACT_TEST_MARKER"' > "$out""#;

    #[cfg(unix)]
    fn mac_update_with_fake_curl(name: &str, curl: &str) -> (bool, bool) {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("open-pact-update-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("curl");
        std::fs::write(&fake, format!("#!/bin/sh\n{curl}\n")).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let marker = dir.join("ran");
        let path = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let call = update_invocation(
            Platform::Mac,
            "/Users/fictional/Applications/open-pact.app/Contents/MacOS/open-pact",
            "0.8.1",
        )
        .unwrap();
        let status = std::process::Command::new(&call.program)
            .args(&call.args)
            .env("PATH", path)
            .env("OPEN_PACT_TEST_MARKER", &marker)
            .status()
            .unwrap();
        let ran = marker.exists();
        std::fs::remove_dir_all(&dir).unwrap();
        (status.success(), ran)
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_installer_download_fails_the_update() {
        let (succeeded, ran) = mac_update_with_fake_curl("failed-download", "exit 22");
        assert!(!succeeded);
        assert!(!ran);
    }

    #[cfg(unix)]
    #[test]
    fn the_update_runs_the_downloaded_installer() {
        let (succeeded, ran) = mac_update_with_fake_curl("downloaded", FAKE_CURL_DOWNLOADS);
        assert!(succeeded);
        assert!(ran);
    }
}
