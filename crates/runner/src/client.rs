use crate::{Runner, args, find_on_path};
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
    pub fn preview(&self, invitation: &str) -> Result<Preview, String> {
        self.runner
            .json(&self.executable, &args(&["join", "--preview", invitation]))
    }

    pub fn status(&self) -> Result<Status, String> {
        // Status uses nonzero exits for actionable reports as well as errors.
        let output = self
            .runner
            .run(&self.executable, &args(&["status", "--json"]));
        let stdout = match output {
            Ok(log) => log.stdout,
            Err(error) => {
                let log = self.runner.logs().pop().ok_or_else(|| error.clone())?;
                if log.stdout.trim().is_empty() {
                    return Err(error);
                }
                log.stdout
            }
        };
        serde_json::from_str(&stdout).map_err(|e| {
            serde_json::from_str::<Value>(&stdout)
                .ok()
                .and_then(|v| v.get("error")?.as_str().map(str::to_owned))
                .unwrap_or_else(|| format!("Invalid status JSON: {e}"))
        })
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
        words.push(invitation.into());
        let mut parse_error = None;
        let mut completed = false;
        self.runner.stream(
            &self.executable,
            &words,
            |line| match serde_json::from_str::<JoinEvent>(line) {
                Ok(value) => {
                    completed |= matches!(value, JoinEvent::Result { .. });
                    event(value);
                }
                Err(error) => parse_error = Some(format!("Invalid join event: {error}")),
            },
        )?;
        if let Some(error) = parse_error {
            return Err(error);
        }
        if !completed {
            return Err(
                "Join ended without a final result. Reopen status to confirm what is stored."
                    .into(),
            );
        }
        Ok(())
    }

    pub fn check(&self) -> Result<Check, String> {
        self.runner
            .json(&self.executable, &args(&["check", "--json"]))
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

pub fn resolve_cli(runner: &Runner, bundled: &Path) -> Result<Option<PathBuf>, String> {
    let wanted = version(runner, bundled)?;
    if let Some(path) = find_on_path(cli_name())
        && version(runner, &path).is_ok_and(|v| v == wanted)
    {
        return Ok(Some(path));
    }
    let installed = installed_path()?;
    if installed.is_file() && version(runner, &installed).is_ok_and(|v| v == wanted) {
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
