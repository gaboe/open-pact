pub mod admin;
pub mod client;
#[cfg(feature = "desktop")]
pub mod desktop;
pub mod manifest;
pub mod results;
pub mod text;
pub mod update;

use serde::de::DeserializeOwned;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

static TOOL_PATH: OnceLock<OsString> = OnceLock::new();

/// The PATH every child process gets. A macOS app started from Finder has only the launchd PATH,
/// so on macOS and Linux this reads the login shell PATH once.
pub fn tool_path() -> &'static OsString {
    TOOL_PATH.get_or_init(|| {
        let current = std::env::var_os("PATH");
        if cfg!(windows) {
            return current.unwrap_or_default();
        }
        let login = std::env::var_os("SHELL")
            .filter(|shell| !shell.is_empty())
            .and_then(|shell| login_path(Path::new(&shell), Duration::from_secs(5)));
        compose_path(login, current)
    })
}

/// Runs `$SHELL -lc 'printf %s "$PATH"'` and returns its last output line.
pub fn login_path(shell: &Path, timeout: Duration) -> Option<OsString> {
    let mut child = Command::new(shell)
        .args(["-lc", "printf %s \"$PATH\""])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let (sender, receiver) = channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = sender.send(stdout.read_to_end(&mut bytes).map(|_| bytes));
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    // A background process started by a shell profile can keep the pipe open, so do not wait
    // for the end of the stream for long.
    if !status?.success() {
        return None;
    }
    let bytes = receiver.recv_timeout(Duration::from_secs(1)).ok()?.ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    Some(line.into())
}

/// Login shell directories first, then the app's own PATH, then the two usual Homebrew and
/// Docker Desktop directories when they are missing. A login shell that skips `.zshrc` does not
/// see tools that a user added there.
pub fn compose_path(login: Option<OsString>, current: Option<OsString>) -> OsString {
    let mut directories: Vec<PathBuf> = Vec::new();
    for source in [login, current].into_iter().flatten() {
        directories.extend(std::env::split_paths(&source));
    }
    directories.extend(["/opt/homebrew/bin", "/usr/local/bin"].map(PathBuf::from));
    let mut unique: Vec<PathBuf> = Vec::new();
    for directory in directories {
        if !directory.as_os_str().is_empty() && !unique.contains(&directory) {
            unique.push(directory);
        }
    }
    std::env::join_paths(unique).unwrap_or_default()
}

fn find_in(path: &OsStr, name: &str) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
}

pub fn find_on_path(name: &str) -> Option<PathBuf> {
    find_in(tool_path(), name)
}

/// A child process with the tool PATH and, on Windows, no console window.
pub fn command(program: &Path) -> Command {
    let path = tool_path();
    let resolved = match program.to_str() {
        Some(name) if program.components().count() == 1 => {
            find_in(path, name).unwrap_or_else(|| program.to_path_buf())
        }
        _ => program.to_path_buf(),
    };
    let mut command = Command::new(resolved);
    command.env("PATH", path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command
}

/// Opens a folder in the file manager (`open`, `explorer` or `xdg-open`) and does not wait for
/// it. The folder is created first, because the file manager cannot open a missing one.
pub fn open_folder(folder: &Path) -> Result<(), String> {
    std::fs::create_dir_all(folder).map_err(|e| e.to_string())?;
    let program = if cfg!(windows) {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let mut child = command(Path::new(program))
        .arg(folder)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    // Reap the child; explorer exits with code 1 even when it opened the folder.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// Quotes one word for a POSIX shell, so a shown command can be pasted back safely.
pub fn shell_quote(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte));
    if plain {
        word.into()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

pub fn shell_line<S: AsRef<str>>(words: &[S]) -> String {
    words
        .iter()
        .map(|word| shell_quote(word.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Debug, Default)]
pub struct CommandLog {
    pub program: String,
    pub args: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub exit: Option<i32>,
    pub stdin: Option<String>,
}

impl CommandLog {
    pub fn display(&self) -> String {
        let words: Vec<&str> = std::iter::once(&self.program)
            .chain(self.args.iter())
            .map(String::as_str)
            .collect();
        shell_line(&words)
    }
}

#[derive(Clone, Default)]
pub struct Runner {
    log: Arc<Mutex<Vec<CommandLog>>>,
    timeout: Option<Duration>,
    env: Vec<(String, String)>,
}

fn stop_after(
    child: Arc<Mutex<Child>>,
    timeout: Duration,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<bool>) {
    let (done, wait) = channel::<()>();
    let handle = std::thread::spawn(move || {
        if matches!(wait.recv_timeout(timeout), Err(RecvTimeoutError::Timeout)) {
            let _ = child.lock().unwrap_or_else(|e| e.into_inner()).kill();
            true
        } else {
            false
        }
    });
    (done, handle)
}

impl Runner {
    /// A runner that shares this one's log and stops each command after `timeout`.
    pub fn with_timeout(&self, timeout: Duration) -> Self {
        Self {
            log: self.log.clone(),
            timeout: Some(timeout),
            env: self.env.clone(),
        }
    }

    /// A runner that shares this one's log and adds `env` to each command.
    pub fn with_env(&self, env: &[(String, String)]) -> Self {
        Self {
            log: self.log.clone(),
            timeout: self.timeout,
            env: self.env.iter().chain(env.iter()).cloned().collect(),
        }
    }

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
        line: impl FnMut(&str),
    ) -> Result<CommandLog, String> {
        strict(self.execute(program, args, None, line)?)
    }

    /// Like `stream`, but a command that ran and exited with a nonzero code is not an error.
    pub fn stream_any(
        &self,
        program: &Path,
        args: &[String],
        line: impl FnMut(&str),
    ) -> Result<CommandLog, String> {
        self.execute(program, args, None, line)
    }

    pub fn input(
        &self,
        program: &Path,
        args: &[String],
        input: &str,
    ) -> Result<CommandLog, String> {
        strict(self.execute(program, args, Some(input.to_owned()), |_| {})?)
    }

    /// Like `input`, but a command that ran and exited with a nonzero code is not an error.
    pub fn input_any(
        &self,
        program: &Path,
        args: &[String],
        input: &str,
    ) -> Result<CommandLog, String> {
        self.execute(program, args, Some(input.to_owned()), |_| {})
    }

    fn execute(
        &self,
        program: &Path,
        args: &[String],
        input: Option<String>,
        mut line: impl FnMut(&str),
    ) -> Result<CommandLog, String> {
        let mut entry = CommandLog {
            program: program.display().to_string(),
            args: args.to_vec(),
            stdin: input.clone(),
            ..Default::default()
        };
        let index = {
            let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
            let index = log.len();
            log.push(entry.clone());
            index
        };
        let result = (|| {
            let mut child = command(program)
                .args(args)
                .envs(self.env.iter().map(|(key, value)| (key, value)))
                .stdin(if input.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| {
                    format!("{}: {e}. Install the command and retry.", program.display())
                })?;
            let mut stderr = child.stderr.take().ok_or("Missing command stderr")?;
            let stdout = child.stdout.take().ok_or("Missing command stdout")?;
            let stdin = child.stdin.take();
            let child = Arc::new(Mutex::new(child));
            let watchdog = self
                .timeout
                .map(|timeout| stop_after(child.clone(), timeout));
            let writer = input.map(|input| {
                std::thread::spawn(move || {
                    stdin
                        .ok_or_else(|| std::io::Error::other("Missing command stdin"))?
                        .write_all(input.as_bytes())
                })
            });
            let reader = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                stderr
                    .read_to_end(&mut bytes)
                    .map(|_| String::from_utf8_lossy(&bytes).into_owned())
            });
            let read_result = (|| {
                let mut stdout = BufReader::new(stdout);
                let mut row = Vec::new();
                loop {
                    row.clear();
                    if stdout
                        .read_until(b'\n', &mut row)
                        .map_err(|e| e.to_string())?
                        == 0
                    {
                        return Ok::<_, String>(());
                    }
                    let text = String::from_utf8_lossy(&row);
                    entry.stdout.push_str(&text);
                    line(text.trim_end_matches(['\n', '\r']));
                    self.log.lock().unwrap_or_else(|e| e.into_inner())[index] = entry.clone();
                }
            })();
            if read_result.is_err() {
                let _ = child.lock().unwrap_or_else(|e| e.into_inner()).kill();
            }
            let status = loop {
                let polled = child.lock().unwrap_or_else(|e| e.into_inner()).try_wait();
                match polled.map_err(|e| e.to_string())? {
                    Some(status) => break status,
                    None => std::thread::sleep(Duration::from_millis(5)),
                }
            };
            let timed_out = watchdog.is_some_and(|(done, handle)| {
                drop(done);
                handle.join().unwrap_or(false)
            });
            entry.exit = status.code();
            entry.stderr = reader
                .join()
                .map_err(|_| "stderr reader stopped")?
                .map_err(|e| e.to_string())?;
            let write_result = writer
                .map(|writer| {
                    writer
                        .join()
                        .map_err(|_| "stdin writer stopped".to_owned())
                        .and_then(|result| result.map_err(|e| e.to_string()))
                })
                .transpose();
            if timed_out {
                return Err(format!(
                    "{} did not finish within {} seconds and was stopped.",
                    program.display(),
                    self.timeout.unwrap_or_default().as_secs()
                ));
            }
            read_result?;
            if status.success() {
                write_result?;
            }
            Ok(())
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

    /// For commands whose complete report can come with a nonzero exit code. A document that
    /// parses is the answer at any exit code; otherwise the command's own error is shown.
    pub fn report<T: DeserializeOwned>(
        &self,
        program: &Path,
        args: &[String],
    ) -> Result<T, String> {
        let log = self.execute(program, args, None, |_| {})?;
        match serde_json::from_str(&log.stdout) {
            Ok(report) => Ok(report),
            Err(error) if log.exit == Some(0) => {
                Err(format!("Invalid JSON from {}: {error}", program.display()))
            }
            Err(_) => Err(command_error(&log)),
        }
    }
}

fn strict(log: CommandLog) -> Result<CommandLog, String> {
    if log.exit == Some(0) {
        Ok(log)
    } else {
        Err(command_error(&log))
    }
}

pub fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).into()).collect()
}

fn error_text(text: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    value.get("error")?.as_str().map(str::to_owned)
}

/// The message of a failed command: its JSON `error` (the whole output, or its last line, as
/// NDJSON commands end with it), then stderr, then the raw output.
pub fn command_error(log: &CommandLog) -> String {
    if let Some(error) = error_text(&log.stdout).or_else(|| {
        log.stdout
            .lines()
            .rev()
            .find(|row| !row.trim().is_empty())
            .and_then(error_text)
    }) {
        return error;
    }
    if !log.stderr.trim().is_empty() {
        log.stderr.trim().into()
    } else {
        format!("Command exited {:?}: {}", log.exit, log.stdout.trim())
    }
}
