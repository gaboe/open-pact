use crate::{Runner, args, client, command_error};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Settings {
    pub context: String,
    pub namespace: String,
    /// Empty means search PATH for kubectl.
    #[serde(default)]
    pub kubectl: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            context: String::new(),
            namespace: "open-pact".into(),
            kubectl: String::new(),
        }
    }
}

fn folder_name(text: &str) -> String {
    let name: String = text
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.is_empty() || name.chars().all(|c| c == '.') {
        "_".into()
    } else {
        name
    }
}

impl Settings {
    /// The folder that holds the backups of every cluster. The user never chooses it.
    pub fn backup_root() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_default()
            .join("open-pact-admin/backups")
    }

    /// One folder per context and namespace under `root`, so that backups of another cluster
    /// are never offered for restore.
    pub fn backup_folder_in(&self, root: &Path) -> PathBuf {
        root.join(folder_name(&self.context))
            .join(folder_name(&self.namespace))
    }

    pub fn backup_folder(&self) -> PathBuf {
        self.backup_folder_in(&Self::backup_root())
    }

    pub fn kubectl_program(&self) -> PathBuf {
        let chosen = self.kubectl.trim();
        if chosen.is_empty() {
            "kubectl".into()
        } else {
            chosen.into()
        }
    }

    pub fn path() -> Result<PathBuf, String> {
        Ok(dirs::config_dir()
            .ok_or("Cannot locate the OS config directory")?
            .join("open-pact-admin/settings.json"))
    }

    pub fn load() -> Result<Self, String> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::path()?;
        std::fs::create_dir_all(path.parent().ok_or("Invalid settings path")?)
            .map_err(|e| e.to_string())?;
        let temporary = path.with_extension("tmp");
        std::fs::write(
            &temporary,
            serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if cfg!(windows) && path.exists() {
            std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
        std::fs::rename(temporary, path).map_err(|e| e.to_string())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Device {
    pub pseudonym: String,
    pub code: String,
    pub state: String,
    pub note: String,
    pub enrolled_at: String,
    pub manifest_hash: String,
    pub last_claim_at: Option<String>,
    pub last_result: Option<Value>,
    pub last_reasons: Option<Value>,
}

/// The devices the Overview lists: revoked ones left out, the newest result first, and devices
/// without a result last.
pub fn latest_results(devices: &[Device]) -> Vec<&Device> {
    let claimed = |device: &Device| {
        device
            .last_claim_at
            .as_deref()
            .and_then(|at| DateTime::parse_from_rfc3339(at).ok())
            .map(|at| at.with_timezone(&Utc))
    };
    let mut shown: Vec<&Device> = devices
        .iter()
        .filter(|device| device.state != "revoked")
        .collect();
    shown.sort_by_key(|device| {
        (
            device.last_result.is_none(),
            std::cmp::Reverse(claimed(device)),
        )
    });
    shown
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Gateway {
    pub version: String,
    pub manifest_hash: String,
    pub auto_approve: bool,
    pub devices: Value,
    pub company_key_fingerprint: String,
    #[serde(default)]
    pub manifest_source: Option<String>,
    #[serde(default)]
    pub manifest_version: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Invitation {
    pub invitation: String,
    pub expires_at: String,
    pub company_key_fingerprint: String,
    pub note: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Version {
    pub version: u64,
    pub manifest_hash: String,
    pub created_at: String,
    pub note: String,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Applied {
    pub version: u64,
    pub manifest_hash: String,
    pub previous_hash: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Backup {
    pub path: PathBuf,
    pub manifest_hash: String,
}

#[derive(Clone, Debug)]
pub struct History {
    pub versions: Vec<Version>,
    pub backups: Vec<Backup>,
    pub synced_at: String,
    /// Backup files that were skipped, each with the reason.
    pub warnings: Vec<String>,
}

/// A manifest write that the gateway confirmed.
#[derive(Clone, Debug)]
pub struct Written {
    pub hash: String,
    /// The hash of a manifest that another admin made active after this review. It was replaced,
    /// and it stays in the server history.
    pub overwritten: Option<String>,
}

#[derive(Clone, Debug)]
pub enum WriteError {
    /// Stopped before anything was sent to the gateway.
    Refused(String),
    /// The gateway may or may not have stored the manifest.
    Unknown(String),
    /// The gateway confirmed the write. A later step failed or found another manifest.
    AfterWrite(String),
}

fn sentence(text: &str) -> String {
    let text = text.trim();
    if text.ends_with(['.', '!', '?']) {
        text.into()
    } else {
        format!("{text}.")
    }
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(message) => write!(f, "{} Nothing was written.", sentence(message)),
            Self::AfterWrite(message) => f.write_str(message),
            Self::Unknown(message) if message.contains("unconfirmed") => f.write_str(message),
            Self::Unknown(message) => {
                write!(f, "{} The write outcome is unconfirmed.", sentence(message))
            }
        }
    }
}

impl std::error::Error for WriteError {}

#[derive(Clone, Debug)]
pub enum Restore {
    Server(Version),
    Local(Backup),
}

#[derive(Clone)]
pub struct Admin {
    pub runner: Runner,
    pub settings: Settings,
    pub kubectl: PathBuf,
    /// Tests point this at a temporary folder. The app always uses `Settings::backup_root()`.
    pub backup_root: PathBuf,
    /// The open-pact-client that checks manifests. `None` looks for the one bundled with this
    /// app first, then the one the client app installs, then the one on PATH.
    pub client: Option<PathBuf>,
    /// How long one manifest check may run.
    pub check_limit: Duration,
}

/// What an open-pact-client older than the manifest check answers with.
pub const CLI_TOO_OLD: &str =
    "This open-pact-client is too old to check manifests; update it to 0.7.1 or later.";

/// One reason the open-pact CLI refuses a manifest draft.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CheckError {
    pub message: String,
    /// The 1-based line in the draft, when the CLI knows it.
    #[serde(default)]
    pub line: Option<usize>,
    /// The dotted TOML path the message names, when it names one.
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Deserialize)]
struct CheckReport {
    ok: bool,
    errors: Vec<CheckError>,
}

enum Answer {
    Errors(Vec<CheckError>),
    TooOld,
}

/// Reads what `manifest check --json` printed. The draft is valid only when the exit code, `ok`
/// and the error list all say so.
fn read_answer(log: &crate::CommandLog) -> Result<Answer, String> {
    if log.exit == Some(2)
        || log
            .stderr
            .to_lowercase()
            .contains("unrecognized subcommand")
    {
        return Ok(Answer::TooOld);
    }
    let report: CheckReport = match (log.exit, serde_json::from_str(&log.stdout)) {
        (Some(0 | 1), Ok(report)) => report,
        (Some(0), Err(error)) => {
            return Err(format!("Invalid JSON from open-pact-client: {error}"));
        }
        _ => return Err(command_error(log)),
    };
    if log.exit == Some(0) && report.ok && report.errors.is_empty() {
        return Ok(Answer::Errors(Vec::new()));
    }
    if report.errors.is_empty() {
        return Err(format!(
            "open-pact-client gave no reason with exit code {:?}.",
            log.exit
        ));
    }
    Ok(Answer::Errors(report.errors))
}

/// Cluster names from `kubectl config get-contexts -o name`.
pub fn list_contexts(runner: &Runner, kubectl: &Path) -> Result<Vec<String>, String> {
    let output = runner.run(kubectl, &args(&["config", "get-contexts", "-o", "name"]))?;
    Ok(output
        .stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

/// The context kubectl uses now, or `None` when none is set.
pub fn current_context(runner: &Runner, kubectl: &Path) -> Option<String> {
    let output = runner
        .run(kubectl, &args(&["config", "current-context"]))
        .ok()?;
    let name = output.stdout.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

/// Namespace names from `kubectl get namespaces -o name --context <context>`. A user without the
/// right to list namespaces, or a cluster that does not answer, gets the kubectl error.
pub fn list_namespaces(
    runner: &Runner,
    kubectl: &Path,
    context: &str,
) -> Result<Vec<String>, String> {
    let output = runner.run(
        kubectl,
        &args(&["get", "namespaces", "-o", "name", "--context", context]),
    )?;
    let names: Vec<String> = output
        .stdout
        .lines()
        .map(str::trim)
        .map(|line| line.strip_prefix("namespace/").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    if names.is_empty() {
        Err("kubectl returned no namespaces.".into())
    } else {
        Ok(names)
    }
}

/// The saved cluster when kubectl still has it, else the current context when it is listed.
pub fn pick_context(saved: &str, contexts: &[String], current: Option<&str>) -> Option<String> {
    let listed = |name: &str| contexts.iter().any(|context| context == name);
    if listed(saved) {
        return Some(saved.into());
    }
    current.filter(|name| listed(name)).map(str::to_owned)
}

/// The saved namespace, else "open-pact", else the first one.
pub fn pick_namespace(saved: &str, namespaces: &[String]) -> Option<String> {
    let listed = |name: &str| namespaces.iter().any(|namespace| namespace == name);
    [saved, "open-pact"]
        .into_iter()
        .find(|name| listed(name))
        .map(str::to_owned)
        .or_else(|| namespaces.first().cloned())
}

/// The first line of a kubectl error, short enough for one muted line.
pub fn short_error(error: &str) -> String {
    let line = error
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("kubectl failed.");
    let line = line.strip_prefix("error: ").unwrap_or(line);
    if line.chars().count() > 140 {
        let cut: String = line.chars().take(137).collect();
        format!("{cut}...")
    } else {
        line.into()
    }
}

pub fn hash(text: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(text.as_bytes()))
}

fn hash12(hash: &str) -> Result<&str, String> {
    let bytes = hash
        .strip_prefix("sha256:")
        .ok_or("Invalid manifest hash")?;
    if bytes.len() != 64 || !bytes.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Invalid manifest hash".into());
    }
    Ok(&bytes[..12])
}

/// A backup name ends with the first 12 hex characters of its manifest hash. A file with such a
/// name must contain the manifest that the name says.
fn check_name(name: &str, text: &str) -> Result<(), String> {
    let stem = name.strip_suffix(".toml").unwrap_or(name);
    let tail = stem.rsplit('-').next().unwrap_or_default();
    if tail.len() == 12 && tail.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let actual = hash(text);
        if !actual["sha256:".len()..].starts_with(&tail.to_ascii_lowercase()) {
            return Err(format!(
                "Skipped backup {name}: its content does not match the hash in its name. Move it out of the folder and sync again."
            ));
        }
    }
    Ok(())
}

/// Writes through a temporary file and a rename, so a crash never leaves a partial file under
/// a backup name.
fn save_backup(directory: &Path, filename: &str, text: &str) -> Result<PathBuf, String> {
    use std::io::Write;
    std::fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    let path = directory.join(filename);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err("Backup path is a symbolic link".into());
            }
            if std::fs::read_to_string(&path).map_err(|e| e.to_string())? != text {
                return Err(format!(
                    "Backup {} differs from the server. Move it out of the folder and sync again.",
                    path.display()
                ));
            }
            return Ok(path);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let temporary = directory.join(format!(".{filename}.part"));
    let mut file = std::fs::File::create(&temporary).map_err(|e| e.to_string())?;
    file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    std::fs::rename(&temporary, &path).map_err(|e| {
        let _ = std::fs::remove_file(&temporary);
        e.to_string()
    })?;
    Ok(path)
}

pub fn restore_note(restore: &Restore) -> String {
    match restore {
        Restore::Local(backup) => format!(
            "restore {}",
            backup
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ),
        Restore::Server(version) => format!("restore version {}", version.version),
    }
}

impl Admin {
    pub fn new(runner: Runner, settings: Settings) -> Self {
        Self {
            runner: runner.with_timeout(Duration::from_secs(60)),
            kubectl: settings.kubectl_program(),
            settings,
            backup_root: Settings::backup_root(),
            client: None,
            check_limit: Duration::from_secs(5),
        }
    }

    fn client_candidates(&self) -> Vec<PathBuf> {
        match &self.client {
            Some(client) => vec![client.clone()],
            None => client::cli_candidates(std::env::current_exe().ok().as_deref()),
        }
    }

    /// Runs the rules of a client and the gateway on a manifest draft, by asking the CLI. No
    /// error list means the draft is valid. A CLI too old to know the command is one error. A CLI
    /// that cannot be run, or that answers in a way this app cannot read, is an `Err`.
    pub fn check_manifest(&self, toml: &str) -> Result<Vec<CheckError>, String> {
        self.check_manifest_with(&self.client_candidates(), toml)
    }

    /// Like `check_manifest`, with the CLIs to try in order. The next one is tried when one is
    /// too old.
    pub fn check_manifest_with(
        &self,
        programs: &[PathBuf],
        toml: &str,
    ) -> Result<Vec<CheckError>, String> {
        if programs.is_empty() {
            return Err(
                "open-pact-client was not found. Install the open-pact app, or put open-pact-client on your PATH."
                    .into(),
            );
        }
        // A separate runner keeps the draft out of the command log and gives the check its own limit.
        let runner = Runner::default().with_timeout(self.check_limit);
        let words = args(&["manifest", "check", "--json"]);
        for program in programs {
            let log = runner.input_any(program, &words, toml)?;
            match read_answer(&log)? {
                Answer::Errors(errors) => return Ok(errors),
                Answer::TooOld => (),
            }
        }
        Ok(vec![CheckError {
            message: CLI_TOO_OLD.into(),
            line: None,
            key: None,
        }])
    }

    pub fn use_settings(&mut self, settings: Settings) {
        self.kubectl = settings.kubectl_program();
        self.settings = settings;
    }

    pub fn backup_dir(&self) -> PathBuf {
        self.settings.backup_folder_in(&self.backup_root)
    }

    pub fn kube_args(&self, words: &[&str]) -> Vec<String> {
        let mut result = args(&[
            "--context",
            &self.settings.context,
            "-n",
            &self.settings.namespace,
        ]);
        result.extend(args(words));
        result
    }

    pub fn gateway_args(&self, words: &[&str]) -> Vec<String> {
        let mut result = self.kube_args(&[
            "exec",
            "deploy/open-pact-gateway",
            "--",
            "open-pact-gateway",
        ]);
        result.extend(args(words));
        result
    }

    pub fn gateway(&self) -> Result<Gateway, String> {
        self.runner
            .json(&self.kubectl, &self.gateway_args(&["status", "--json"]))
    }

    pub fn deployment(&self) -> Result<Value, String> {
        self.runner.json(
            &self.kubectl,
            &self.kube_args(&["get", "deploy/open-pact-gateway", "-o", "json"]),
        )
    }

    pub fn devices(&self) -> Result<Vec<Device>, String> {
        self.runner.json(
            &self.kubectl,
            &self.gateway_args(&["devices", "list", "--json"]),
        )
    }

    pub fn invite(&self, ttl: &str, note: &str) -> Result<Invitation, String> {
        self.runner.json(
            &self.kubectl,
            &self.gateway_args(&["invite", "--ttl", ttl, &format!("--note={note}"), "--json"]),
        )
    }

    pub fn device_action(&self, action: &str, device: &str) -> Result<(), String> {
        if !matches!(action, "approve" | "revoke") {
            return Err("Unknown device action".into());
        }
        self.runner
            .run(
                &self.kubectl,
                &self.gateway_args(&["devices", action, device]),
            )
            .map(|_| ())
    }

    pub fn manifest(&self, version: Option<u64>) -> Result<String, String> {
        let mut words = self.gateway_args(&["manifest", "get"]);
        if let Some(version) = version {
            words.extend(args(&["--version", &version.to_string()]));
        }
        Ok(self.runner.run(&self.kubectl, &words)?.stdout)
    }

    pub fn history(&self) -> Result<Vec<Version>, String> {
        self.runner.json(
            &self.kubectl,
            &self.gateway_args(&["manifest", "history", "--json"]),
        )
    }

    pub fn backups(&self) -> Result<Vec<Backup>, String> {
        Ok(self.scan_backups()?.0)
    }

    fn scan_backups(&self) -> Result<(Vec<Backup>, Vec<String>), String> {
        let directory = self.backup_dir();
        if !directory.exists() {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut backups = Vec::new();
        let mut warnings = Vec::new();
        for entry in std::fs::read_dir(&directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if !entry.file_type().map_err(|e| e.to_string())?.is_file()
                || entry.path().extension().is_none_or(|ext| ext != "toml")
            {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            match std::fs::read_to_string(entry.path()) {
                Err(error) => warnings.push(format!("Skipped backup {name}: {error}.")),
                Ok(text) => match check_name(&name, &text) {
                    Err(warning) => warnings.push(warning),
                    Ok(()) => backups.push(Backup {
                        path: entry.path(),
                        manifest_hash: hash(&text),
                    }),
                },
            }
        }
        backups.sort_by(|left, right| right.path.cmp(&left.path));
        warnings.sort();
        Ok((backups, warnings))
    }

    pub fn sync(&self) -> Result<History, String> {
        let directory = self.backup_dir();
        std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        let versions = self.history()?;
        let mut warnings = Vec::new();
        for version in &versions {
            let time = DateTime::parse_from_rfc3339(&version.created_at)
                .map_err(|e| format!("Invalid server version time: {e}"))?
                .with_timezone(&Utc)
                .format("%Y%m%dT%H%M%S%.3fZ")
                .to_string();
            let filename = format!(
                "{time}-v{}-{}.toml",
                version.version,
                hash12(&version.manifest_hash)?
            );
            let path = directory.join(&filename);
            if let Ok(metadata) = std::fs::symlink_metadata(&path) {
                // A file with the wrong content is reported by the folder scan below.
                if metadata.file_type().is_symlink() {
                    warnings.push(format!(
                        "Skipped backup {filename}: it is a symbolic link. Move it out of the folder and sync again."
                    ));
                }
                continue;
            }
            let text = self.manifest(Some(version.version))?;
            if hash(&text) != version.manifest_hash {
                return Err(format!(
                    "Downloaded version {} has the wrong hash",
                    version.version
                ));
            }
            save_backup(&directory, &filename, &text)?;
        }
        let (backups, scanned) = self.scan_backups()?;
        warnings.extend(scanned);
        Ok(History {
            versions,
            backups,
            synced_at: Utc::now().to_rfc3339(),
            warnings,
        })
    }

    pub fn restore_text(&self, restore: &Restore) -> Result<String, String> {
        let (text, expected) = match restore {
            Restore::Server(version) => (
                self.manifest(Some(version.version))?,
                &version.manifest_hash,
            ),
            Restore::Local(backup) => {
                let path = backup.path.canonicalize().map_err(|e| e.to_string())?;
                let directory = self
                    .backup_dir()
                    .canonicalize()
                    .map_err(|e| e.to_string())?;
                if path.parent() != Some(directory.as_path()) {
                    return Err("Backup is outside the configured folder".into());
                }
                let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
                check_name(
                    &path.file_name().unwrap_or_default().to_string_lossy(),
                    &text,
                )?;
                (text, &backup.manifest_hash)
            }
        };
        if hash(&text) != *expected {
            return Err("The selected manifest changed. Sync and review it again.".into());
        }
        text.parse::<toml_edit::DocumentMut>()
            .map_err(|e| e.to_string())?;
        Ok(text)
    }

    fn backup_active(&self, reviewed_hash: &str) -> Result<(), String> {
        let current = self.manifest(None)?;
        let current_hash = hash(&current);
        if current_hash != reviewed_hash {
            return Err("The active manifest changed. Reload it and review the diff again.".into());
        }
        let filename = format!(
            "{}-{}.toml",
            Utc::now().format("%Y%m%dT%H%M%S%.3fZ"),
            hash12(&current_hash)?
        );
        save_backup(&self.backup_dir(), &filename, &current)?;
        Ok(())
    }

    fn set(&self, text: &str, note: &str) -> Result<Applied, String> {
        let words = self.kube_args(&[
            "exec",
            "-i",
            "deploy/open-pact-gateway",
            "--",
            "open-pact-gateway",
            "manifest",
            "set",
            &format!("--note={note}"),
            "--json",
        ]);
        let output = self.runner.input(&self.kubectl, &words, text)?;
        serde_json::from_str(&output.stdout).map_err(|e| {
            format!("Manifest write response is unknown: {e}. Refresh status before retrying.")
        })
    }

    fn confirm(
        &self,
        result: Applied,
        expected: &str,
        reviewed_hash: &str,
        timeout: Duration,
        what: &str,
    ) -> Result<Written, WriteError> {
        if result.manifest_hash != expected {
            return Err(WriteError::Unknown(format!(
                "The {what} returned an unexpected hash. Refresh status before retrying."
            )));
        }
        // The gateway has no expected-previous argument, so another admin's write between the
        // backup check and this write is found only here.
        let overwritten = result
            .previous_hash
            .filter(|previous| previous != reviewed_hash);
        self.wait_for(expected, timeout)
            .map(|hash| Written {
                hash,
                overwritten: overwritten.clone(),
            })
            .map_err(|error| {
                WriteError::Unknown(match overwritten {
                    Some(previous) => format!(
                        "{error} Another admin's manifest {previous} was active before this write and may be replaced. It stays in the server history."
                    ),
                    None => error,
                })
            })
    }

    pub fn apply(
        &self,
        text: &str,
        note: &str,
        reviewed_hash: &str,
        timeout: Duration,
    ) -> Result<Written, WriteError> {
        text.parse::<toml_edit::DocumentMut>()
            .map_err(|e| WriteError::Refused(e.to_string()))?;
        if note.trim().is_empty() {
            return Err(WriteError::Refused("Enter a change note.".into()));
        }
        self.backup_active(reviewed_hash)
            .map_err(WriteError::Refused)?;
        let result = self.set(text, note).map_err(WriteError::Unknown)?;
        self.confirm(result, &hash(text), reviewed_hash, timeout, "gateway write")
    }

    pub fn restore(
        &self,
        restore: &Restore,
        reviewed_hash: &str,
        timeout: Duration,
    ) -> Result<Written, WriteError> {
        let text = self.restore_text(restore).map_err(WriteError::Refused)?;
        self.backup_active(reviewed_hash)
            .map_err(WriteError::Refused)?;
        let versions = self.history().map_err(WriteError::Refused)?;
        let expected = hash(&text);
        let server = versions.iter().find(|version| match restore {
            Restore::Server(selected) => {
                version.version == selected.version && version.manifest_hash == expected
            }
            Restore::Local(_) => version.manifest_hash == expected,
        });
        let result: Applied = if let Some(version) = server {
            self.runner
                .json(
                    &self.kubectl,
                    &self.gateway_args(&[
                        "manifest",
                        "activate",
                        &version.version.to_string(),
                        "--json",
                    ]),
                )
                .map_err(WriteError::Unknown)?
        } else {
            self.set(&text, &restore_note(restore))
                .map_err(WriteError::Unknown)?
        };
        self.confirm(result, &expected, reviewed_hash, timeout, "restore")
    }

    pub fn wait_for(&self, expected: &str, timeout: Duration) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        let mut last_error = String::new();
        while Instant::now() < deadline {
            match self.gateway() {
                Ok(status) if status.manifest_hash == expected => return Ok(expected.into()),
                Ok(status) => last_error = format!("Gateway reports {}", status.manifest_hash),
                Err(error) => last_error = error,
            }
            std::thread::sleep(
                Duration::from_secs(1).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        Err(format!(
            "Manifest update timed out. Expected {expected}. {last_error}. The write outcome is unconfirmed. Refresh status before retrying."
        ))
    }
}

pub fn ready(deployment: &Value) -> bool {
    deployment
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .is_some_and(|conditions| {
            conditions
                .iter()
                .any(|value| value["type"] == "Available" && value["status"] == "True")
        })
}
