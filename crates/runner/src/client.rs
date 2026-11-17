use crate::{Runner, args, command_error, find_on_path};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Company {
    pub name: String,
    pub key_fingerprint: String,
    pub matches_invitation: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Control {
    pub id: String,
    pub title: String,
    pub requirement: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Preview {
    pub company: Company,
    pub gateway: String,
    pub manifest_hash: String,
    pub controls: Vec<Control>,
    pub disclosed_metadata: Vec<Value>,
    pub schedule: Option<Value>,
    pub folders: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Issue {
    pub urgency: String,
    pub message: String,
    pub fix: Option<String>,
    pub command: Option<String>,
    pub deadline: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Approval {
    pub state: Option<String>,
    pub live: bool,
    pub source: String,
}

/// A newer command line tool, as `status --online --json` reports it. `command` is null when the
/// tool comes with the app update.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CliUpdate {
    pub current: String,
    pub latest: String,
    pub command: Option<String>,
}

/// An older command line tool has no `update` field, and a shape this app does not know is no
/// update. Neither may break the status screen.
fn lenient_update<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<CliUpdate>, D::Error> {
    let value = Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).ok())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Status {
    pub schema_version: u8,
    pub verdict: String,
    pub approval: Approval,
    pub last_claim: Option<Value>,
    pub manifest: Option<Value>,
    pub schedule: Value,
    pub issues: Vec<Issue>,
    pub limitations: Vec<String>,
    pub current_compliance: String,
    pub log: String,
    #[serde(default, deserialize_with = "lenient_update")]
    pub update: Option<CliUpdate>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Changes {
    pub signed_hash: String,
    pub published_hash: String,
    pub changes: Vec<Value>,
    pub schedule_widened: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Check {
    pub sent_at: String,
    pub accepted: bool,
    pub warnings: Vec<String>,
    pub reasons: Vec<String>,
    pub controls: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum JoinEvent {
    Step {
        step: u8,
        title: String,
        state: String,
        detail: Option<Value>,
    },
    Result {
        result: Value,
        device: String,
        manifest_hash: String,
    },
}

#[derive(Clone, Debug)]
pub enum Screen {
    Install,
    Invitation,
    Review(Preview),
    Joining(Vec<JoinEvent>),
    Status(Box<Status>),
    Changed(Changes),
}

#[derive(Clone)]
pub struct Client {
    pub runner: Runner,
    pub executable: PathBuf,
}

impl Client {
    /// A preview whose company key differs from the invitation comes with exit code 1.
    pub fn preview(&self, invitation: &str) -> Result<Preview, String> {
        self.runner.report(
            &self.executable,
            &args(&["join", "--preview", "--", invitation]),
        )
    }

    /// Status uses nonzero exits for actionable reports as well as errors.
    pub fn status(&self) -> Result<Status, String> {
        self.runner
            .report(&self.executable, &args(&["status", "--online", "--json"]))
    }

    pub fn join(
        &self,
        invitation: &str,
        folders: &[String],
        automatic: bool,
        mut event: impl FnMut(JoinEvent),
    ) -> Result<(), String> {
        let mut words = args(&[
            "join",
            "--yes",
            "--json",
            "--auto-send",
            if automatic { "on" } else { "off" },
        ]);
        for folder in folders {
            words.extend(args(&["--folder", folder]));
        }
        if !invitation.is_empty() {
            words.extend(args(&["--", invitation]));
        }
        let mut parse_error = None;
        let mut completed = false;
        let mut last_error = None;
        // A denied first claim ends with a result line and exit code 1. A join that stops early
        // ends with an {"error":…} line and exit code 1.
        let log = self.runner.stream_any(&self.executable, &words, |line| {
            if let Some(error) = serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|value| value.get("error")?.as_str().map(str::to_owned))
            {
                last_error = Some(error);
                return;
            }
            match serde_json::from_str::<JoinEvent>(line) {
                Ok(value) => {
                    completed |= matches!(value, JoinEvent::Result { .. });
                    event(value);
                }
                Err(error) => parse_error = Some(format!("Invalid join event: {error}")),
            }
        })?;
        if completed {
            return match parse_error {
                Some(error) => Err(error),
                None => Ok(()),
            };
        }
        if let Some(error) = last_error {
            return Err(error);
        }
        if let Some(error) = parse_error {
            return Err(error);
        }
        if log.exit != Some(0) {
            return Err(command_error(&log));
        }
        Err("Join ended without a final result. Reopen status to confirm what is stored.".into())
    }

    /// A denied claim comes with exit code 1 and a complete report.
    pub fn check(&self) -> Result<Check, String> {
        self.runner
            .report(&self.executable, &args(&["check", "--json"]))
    }

    pub fn changes(&self) -> Result<Changes, String> {
        self.runner
            .json(&self.executable, &args(&["accept", "--preview"]))
    }

    pub fn accept(&self) -> Result<(), String> {
        self.runner
            .run(&self.executable, &args(&["accept", "--yes"]))
            .map(|_| ())
    }

    pub fn schedule(&self, enabled: bool) -> Result<(), String> {
        self.runner
            .run(
                &self.executable,
                &args(&["schedule", if enabled { "on" } else { "off" }]),
            )
            .map(|_| ())
    }
}

/// The join resumes when IT approves a device while the app is closed. A saved "pending" or a
/// live "approved" with no claim yet means the wizard steps for the first claim are still open.
/// Returns the automatic-sending choice to resume with.
pub fn resume_join(status: &Status) -> Option<bool> {
    let open = match status.approval.state.as_deref() {
        Some("pending") => true,
        Some("approved") => status.last_claim.is_none(),
        _ => false,
    };
    open.then(|| status.schedule["owner_consented"] == true)
}

pub fn cli_name() -> &'static str {
    if cfg!(windows) {
        "open-pact-client.exe"
    } else {
        "open-pact-client"
    }
}

pub fn installed_path() -> Result<PathBuf, String> {
    let base = if cfg!(windows) {
        dirs::data_local_dir().map(|p| p.join("open-pact"))
    } else {
        dirs::home_dir().map(|p| p.join(".local/bin"))
    };
    Ok(base
        .ok_or("Cannot find the user home directory")?
        .join(cli_name()))
}

/// The CLIs a desktop app may run, best first: the one bundled with this app, the one the client
/// app installs, and the one on PATH. The bundled one matches this app's version, so an older CLI
/// elsewhere never wins. Only files that exist.
pub fn cli_candidates(app: Option<&Path>) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let listed = [
        app.and_then(|app| bundled_path(app).ok()),
        installed_path().ok(),
        find_on_path(cli_name()),
    ];
    for path in listed.into_iter().flatten() {
        if path.is_file() && !found.contains(&path) {
            found.push(path);
        }
    }
    found
}

pub fn bundled_path(app: &Path) -> Result<PathBuf, String> {
    let parent = app.parent().ok_or("Cannot find the app folder")?;
    let adjacent = parent.join(cli_name());
    if adjacent.is_file() {
        return Ok(adjacent);
    }
    Ok(parent
        .parent()
        .ok_or("Cannot find Contents folder")?
        .join("Helpers")
        .join(cli_name()))
}

pub fn version(runner: &Runner, path: &Path) -> Result<String, String> {
    Ok(runner
        .run(path, &args(&["--version"]))?
        .stdout
        .trim()
        .into())
}

/// Orders `open-pact-client 0.6.0` style version lines. A prerelease sorts before its release.
pub(crate) fn version_key(text: &str) -> Option<(Vec<u64>, bool)> {
    let token = text.split_whitespace().last()?;
    let token = token.strip_prefix('v').unwrap_or(token);
    let token = token.split('+').next()?;
    let (core, prerelease) = match token.split_once('-') {
        Some((core, _)) => (core, true),
        None => (token, false),
    };
    let mut numbers = core
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    if numbers.len() < 3 {
        numbers.resize(3, 0);
    }
    Some((numbers, !prerelease))
}

pub fn at_least(found: &str, wanted: &str) -> bool {
    match (version_key(found), version_key(wanted)) {
        (Some(found), Some(wanted)) => found >= wanted,
        _ => found == wanted,
    }
}

/// Uses a CLI on PATH or in the install folder when it is as new as the bundled one. Returns
/// `None` when there is none or only an older one, so the caller installs the bundled copy.
pub fn resolve_cli(runner: &Runner, bundled: &Path) -> Result<Option<PathBuf>, String> {
    let wanted = version(runner, bundled)?;
    let usable = |path: &Path| version(runner, path).is_ok_and(|found| at_least(&found, &wanted));
    if let Some(path) = find_on_path(cli_name())
        && usable(&path)
    {
        return Ok(Some(path));
    }
    let installed = installed_path()?;
    if installed.is_file() && usable(&installed) {
        return Ok(Some(installed));
    }
    Ok(None)
}

pub fn install(runner: &Runner, bundled: &Path, destination: &Path) -> Result<(), String> {
    let wanted = version(runner, bundled)?;
    let parent = destination.parent().ok_or("Invalid install destination")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let temporary = destination.with_extension("installing");
    std::fs::copy(bundled, &temporary).map_err(|e| e.to_string())?;
    if version(runner, &temporary)? != wanted {
        let _ = std::fs::remove_file(&temporary);
        return Err("Installed CLI version does not match the bundled CLI".into());
    }
    if cfg!(windows) && destination.exists() {
        std::fs::remove_file(destination).map_err(|e| e.to_string())?;
    }
    std::fs::rename(temporary, destination).map_err(|e| e.to_string())
}

#[cfg(unix)]
pub fn terminal_path(profile: &Path, directory: &Path) -> Result<(), String> {
    use std::io::Write;
    let existing = match std::fs::read_to_string(profile) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.to_string()),
    };
    let quoted = directory.to_string_lossy().replace('\'', "'\\''");
    let line = format!("export PATH='{quoted}':\"$PATH\"");
    if existing.lines().any(|row| row == line) {
        return Ok(());
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(profile)
        .map_err(|e| e.to_string())?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(file).map_err(|e| e.to_string())?;
    }
    writeln!(file, "{line}").map_err(|e| e.to_string())
}

/// zsh reads ~/.zprofile. A login bash reads ~/.bash_profile when it exists and skips ~/.profile.
pub fn profile_name(shell: &str, home: &Path) -> &'static str {
    if shell.ends_with("zsh") {
        ".zprofile"
    } else if home.join(".bash_profile").exists() {
        ".bash_profile"
    } else {
        ".profile"
    }
}

pub fn enable_terminal(destination: &Path) -> Result<(), String> {
    let directory = destination.parent().ok_or("Invalid CLI location")?;
    #[cfg(unix)]
    {
        let home = dirs::home_dir().ok_or("Cannot locate the home directory")?;
        let shell = std::env::var("SHELL").unwrap_or_default();
        terminal_path(&home.join(profile_name(&shell, &home)), directory)
    }
    #[cfg(windows)]
    {
        use winreg::{HKCU, RegValue, enums::REG_EXPAND_SZ, types::ToRegValue};
        let (environment, _) = HKCU
            .create_subkey("Environment")
            .map_err(|e| e.to_string())?;
        let original: String = match environment.get_value("Path") {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.to_string()),
        };
        let directory = directory.to_string_lossy();
        if original
            .split(';')
            .any(|part| part.eq_ignore_ascii_case(&directory))
        {
            return Ok(());
        }
        let kind = environment
            .get_raw_value("Path")
            .map(|value| value.vtype)
            .unwrap_or(REG_EXPAND_SZ);
        let path_value = format!("{directory};{original}");
        let value = path_value.to_reg_value();
        environment
            .set_raw_value(
                "Path",
                &RegValue {
                    bytes: value.bytes,
                    vtype: kind,
                },
            )
            .map_err(|e| e.to_string())?;
        broadcast_environment_change();
        Ok(())
    }
}

/// Tells Explorer and new terminals to reread the user environment.
#[cfg(windows)]
fn broadcast_environment_change() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn SendMessageTimeoutW(
            window: isize,
            message: u32,
            wparam: usize,
            lparam: isize,
            flags: u32,
            timeout: u32,
            result: *mut usize,
        ) -> isize;
    }
    const HWND_BROADCAST: isize = 0xffff;
    const WM_SETTINGCHANGE: u32 = 0x001a;
    const SMTO_ABORTIFHUNG: u32 = 0x0002;
    let name: Vec<u16> = "Environment\0".encode_utf16().collect();
    let mut result = 0usize;
    // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call, and `result` is a
    // valid pointer for the duration of the call.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            name.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            5000,
            &mut result,
        );
    }
}
