use crate::{Runner, args};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Settings {
    pub context: String,
    pub namespace: String,
    pub backup_dir: PathBuf,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            context: String::new(),
            namespace: "open-pact".into(),
            backup_dir: dirs::data_local_dir()
                .unwrap_or_default()
                .join("open-pact-admin/backups"),
        }
    }
}

impl Settings {
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
}

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

fn save_backup(directory: &Path, filename: &str, text: &str) -> Result<PathBuf, String> {
    use std::io::Write;
    std::fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    let path = directory.join(filename);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::symlink_metadata(&path)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("Backup path is a symbolic link".into());
            }
            if std::fs::read_to_string(&path).map_err(|e| e.to_string())? != text {
                return Err(format!(
                    "Backup {} differs from the server. Choose a new backup folder.",
                    path.display()
                ));
            }
        }
        Err(error) => return Err(error.to_string()),
    }
    Ok(path)
}

impl Admin {
    pub fn new(runner: Runner, settings: Settings) -> Self {
        Self {
            runner,
            settings,
            kubectl: "kubectl".into(),
        }
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
            &self.gateway_args(&["invite", "--ttl", ttl, "--note", note, "--json"]),
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
        Ok(self.runner.raw(&self.kubectl, &words)?.stdout)
    }

    pub fn history(&self) -> Result<Vec<Version>, String> {
        self.runner.json(
            &self.kubectl,
            &self.gateway_args(&["manifest", "history", "--json"]),
        )
    }

    pub fn backups(&self) -> Result<Vec<Backup>, String> {
        if !self.settings.backup_dir.exists() {
            return Ok(Vec::new());
        }
        let mut backups = Vec::new();
        for entry in std::fs::read_dir(&self.settings.backup_dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.file_type().map_err(|e| e.to_string())?.is_file()
                && entry.path().extension().is_some_and(|ext| ext == "toml")
            {
                let text = std::fs::read_to_string(entry.path()).map_err(|e| e.to_string())?;
                backups.push(Backup {
                    path: entry.path(),
                    manifest_hash: hash(&text),
                });
            }
        }
        backups.sort_by(|left, right| right.path.cmp(&left.path));
        Ok(backups)
    }

    pub fn sync(&self) -> Result<History, String> {
        std::fs::create_dir_all(&self.settings.backup_dir).map_err(|e| e.to_string())?;
        let versions = self.history()?;
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
            let path = self.settings.backup_dir.join(&filename);
            if path.exists() {
                if std::fs::symlink_metadata(&path)
                    .map_err(|e| e.to_string())?
                    .file_type()
                    .is_symlink()
                    || hash(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
                        != version.manifest_hash
                {
                    return Err(format!(
                        "Local backup for version {} does not match the server.",
                        version.version
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
            save_backup(&self.settings.backup_dir, &filename, &text)?;
        }
        Ok(History {
            versions,
            backups: self.backups()?,
            synced_at: Utc::now().to_rfc3339(),
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
                    .settings
                    .backup_dir
                    .canonicalize()
                    .map_err(|e| e.to_string())?;
                if path.parent() != Some(directory.as_path()) {
                    return Err("Backup is outside the configured folder".into());
                }
                (
                    std::fs::read_to_string(path).map_err(|e| e.to_string())?,
                    &backup.manifest_hash,
                )
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
        save_backup(&self.settings.backup_dir, &filename, &current)?;
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
            "--note",
            note,
            "--json",
        ]);
        let output = self.runner.input(&self.kubectl, &words, text)?;
        serde_json::from_str(&output.stdout).map_err(|e| {
            format!("Manifest write response is unknown: {e}. Refresh status before retrying.")
        })
    }

    pub fn apply(
        &self,
        text: &str,
        note: &str,
        reviewed_hash: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        text.parse::<toml_edit::DocumentMut>()
            .map_err(|e| e.to_string())?;
        if note.trim().is_empty() {
            return Err("Enter a change note".into());
        }
        self.backup_active(reviewed_hash)?;
        let result = self.set(text, note)?;
        let expected = hash(text);
        if result.manifest_hash != expected {
            return Err(
                "The gateway write returned an unexpected hash. Refresh status before retrying."
                    .into(),
            );
        }
        self.wait_for(&expected, timeout)
    }

    pub fn restore(
        &self,
        restore: &Restore,
        reviewed_hash: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let text = self.restore_text(restore)?;
        self.backup_active(reviewed_hash)?;
        let versions = self.history()?;
        let expected = hash(&text);
        let server = versions.iter().find(|version| match restore {
            Restore::Server(selected) => {
                version.version == selected.version && version.manifest_hash == expected
            }
            Restore::Local(_) => version.manifest_hash == expected,
        });
        let result: Applied = if let Some(version) = server {
            self.runner.json(
                &self.kubectl,
                &self.gateway_args(&[
                    "manifest",
                    "activate",
                    &version.version.to_string(),
                    "--json",
                ]),
            )?
        } else {
            let name = match restore {
                Restore::Local(backup) => backup
                    .path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                Restore::Server(version) => format!("version {}", version.version),
            };
            self.set(&text, &format!("restore {name}"))?
        };
        if result.manifest_hash != expected {
            return Err(
                "The restore returned an unexpected hash. Refresh status before retrying.".into(),
            );
        }
        self.wait_for(&expected, timeout)
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
