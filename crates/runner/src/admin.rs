use crate::{Runner, args, manifest::Block};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Settings {
    pub repo: PathBuf,
    pub manifest: PathBuf,
    pub context: String,
    pub namespace: String,
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
            return Ok(Self {
                namespace: "open-pact".into(),
                ..Self::default()
            });
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

    pub fn manifest_path(&self) -> Result<PathBuf, String> {
        if self.manifest.is_absolute()
            || self
                .manifest
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("Manifest path must be inside the deployment repository".into());
        }
        let repo = self.repo.canonicalize().map_err(|e| e.to_string())?;
        let path = repo
            .join(&self.manifest)
            .canonicalize()
            .map_err(|e| e.to_string())?;
        if !path.starts_with(&repo) {
            return Err("Manifest resolves outside the deployment repository".into());
        }
        Ok(path)
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Invitation {
    pub invitation: String,
    pub expires_at: String,
    pub company_key_fingerprint: String,
    pub note: String,
}

#[derive(Clone)]
pub struct Admin {
    pub runner: Runner,
    pub settings: Settings,
    pub kubectl: PathBuf,
    pub git: PathBuf,
}

impl Admin {
    pub fn new(runner: Runner, settings: Settings) -> Self {
        Self {
            runner,
            settings,
            kubectl: "kubectl".into(),
            git: "git".into(),
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

    fn git(&self, words: &[&str]) -> Result<crate::CommandLog, String> {
        let mut command = args(&["-C", &self.settings.repo.to_string_lossy()]);
        command.extend(args(words));
        self.runner.run(&self.git, &command)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.settings.manifest_path()?;
        self.git(&["status", "--porcelain"])?;
        self.deployment()?;
        Ok(())
    }

    pub fn apply(
        &self,
        block: &Block,
        text: &str,
        message: &str,
        timeout: Duration,
        mut progress: impl FnMut(&str),
    ) -> Result<String, String> {
        if message.trim().is_empty() {
            return Err("Enter a commit message".into());
        }
        let path = self.settings.manifest_path()?;
        block.unchanged(&path)?;
        let replacement = block.replace(text)?;
        if !self
            .git(&["status", "--porcelain"])?
            .stdout
            .trim()
            .is_empty()
        {
            return Err(
                "The deployment repository has local changes. Commit or remove them first.".into(),
            );
        }
        let previous = self.deployment()?;
        let previous_generation = previous.pointer("/metadata/generation").cloned();
        progress("Pulling the deployment repository");
        self.git(&["pull", "--ff-only"])?;
        block.unchanged(&path)?;
        progress("Writing and committing the manifest");
        std::fs::write(&path, replacement).map_err(|e| e.to_string())?;
        self.git(&["commit", "-am", message])?;
        progress("Pushing the commit");
        self.git(&["push"])?;
        let committed = Block::parse(std::fs::read_to_string(path).map_err(|e| e.to_string())?)?;
        let expected = format!("sha256:{:x}", Sha256::digest(committed.text.as_bytes()));
        let deadline = Instant::now() + timeout;
        progress("Waiting for the gateway to restart and enforce the new manifest");
        while Instant::now() < deadline {
            let deployment = self.deployment()?;
            let restarted =
                deployment.pointer("/metadata/generation") != previous_generation.as_ref();
            let available = deployment
                .pointer("/status/availableReplicas")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                > 0;
            if restarted && available {
                let status = self.gateway()?;
                if status.manifest_hash == expected {
                    return Ok(status.manifest_hash);
                }
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        Err(format!(
            "Rollout timed out. Expected {expected}. Reload gateway status before retrying. The commit was pushed."
        ))
    }
}

pub fn load_block(settings: &Settings) -> Result<Block, String> {
    Block::parse(std::fs::read_to_string(settings.manifest_path()?).map_err(|e| e.to_string())?)
}

pub fn ready(deployment: &Value) -> bool {
    deployment
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .is_some_and(|conditions| {
            conditions
                .iter()
                .any(|v| v["type"] == "Available" && v["status"] == "True")
        })
}

pub fn relative(repo: &Path, file: &Path) -> Result<PathBuf, String> {
    file.strip_prefix(repo)
        .map(Path::to_path_buf)
        .map_err(|e| e.to_string())
}
