pub mod admin;
pub mod client;
#[cfg(feature = "desktop")]
pub mod desktop;
pub mod manifest;

use serde::de::DeserializeOwned;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Default)]
pub struct CommandLog {
    pub program: String,
    pub args: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub exit: Option<i32>,
}

impl CommandLog {
    pub fn display(&self) -> String {
        let words = std::iter::once(&self.program).chain(self.args.iter());
        words
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Clone, Default)]
pub struct Runner {
    log: Arc<Mutex<Vec<CommandLog>>>,
}

impl Runner {
    pub fn logs(&self) -> Vec<CommandLog> {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn run(&self, program: &Path, args: &[String]) -> Result<CommandLog, String> {
        self.stream(program, args, |_| {})
    }

    pub fn stream(
        &self,
        program: &Path,
        args: &[String],
        mut line: impl FnMut(&str),
    ) -> Result<CommandLog, String> {
        let mut entry = CommandLog {
            program: program.display().to_string(),
            args: args.to_vec(),
            ..Default::default()
        };
        let index = {
            let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
            let index = log.len();
            log.push(entry.clone());
            index
        };
        let result = (|| {
            let mut child = Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| {
                    format!("{}: {e}. Install the command and retry.", program.display())
                })?;
            let mut stderr = child.stderr.take().ok_or("Missing command stderr")?;
            let reader = std::thread::spawn(move || {
                let mut text = String::new();
                stderr.read_to_string(&mut text).map(|_| text)
            });
            let stdout = child.stdout.take().ok_or("Missing command stdout")?;
            let read_result = (|| {
                for row in BufReader::new(stdout).lines() {
                    let row = row.map_err(|e| e.to_string())?;
                    entry.stdout.push_str(&row);
                    entry.stdout.push('\n');
                    line(&row);
                    self.log.lock().unwrap_or_else(|e| e.into_inner())[index] = entry.clone();
                }
                Ok::<_, String>(())
            })();
            if read_result.is_err() {
                let _ = child.kill();
            }
            let status = child.wait().map_err(|e| e.to_string())?;
            entry.exit = status.code();
            entry.stderr = reader
                .join()
                .map_err(|_| "stderr reader stopped")?
                .map_err(|e| e.to_string())?;
            read_result?;
            if status.success() {
                Ok(())
            } else {
                Err(command_error(&entry))
            }
        })();
        if let Err(error) = &result
            && entry.stderr.is_empty()
            && entry.stdout.is_empty()
        {
            entry.stderr = error.clone();
        }
        self.log.lock().unwrap_or_else(|e| e.into_inner())[index] = entry.clone();
        result.map(|()| entry)
    }

    pub fn json<T: DeserializeOwned>(&self, program: &Path, args: &[String]) -> Result<T, String> {
        let output = self.run(program, args)?;
        serde_json::from_str(&output.stdout)
            .map_err(|e| format!("Invalid JSON from {}: {e}", program.display()))
    }
}

pub fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).into()).collect()
}

fn command_error(log: &CommandLog) -> String {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&log.stdout)
        && let Some(error) = value.get("error").and_then(|v| v.as_str())
    {
        return error.into();
    }
    if !log.stderr.trim().is_empty() {
        log.stderr.trim().into()
    } else {
        format!("Command exited {:?}: {}", log.exit, log.stdout.trim())
    }
}

pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
}
