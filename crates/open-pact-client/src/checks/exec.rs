use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const TIMEOUT: Duration = Duration::from_secs(3);

type Captured = Arc<Mutex<Vec<u8>>>;

/// Output of a command that exited before the timeout, with stdout and stderr together.
pub struct Ran {
    pub success: bool,
    pub text: String,
}

/// The output of `program`, whatever its exit status. `None` when it cannot start or times out.
pub fn run(program: &str, args: &[&str]) -> Option<String> {
    run_status(program, args).map(|ran| ran.text)
}

pub fn run_status(program: &str, args: &[&str]) -> Option<Ran> {
    run_status_with_timeout(program, args, TIMEOUT)
}

#[cfg(test)]
pub fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    run_status_with_timeout(program, args, timeout).map(|ran| ran.text)
}

fn run_status_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<Ran> {
    let output = capture(program, args, timeout).ok()?;
    if output.timed_out {
        return None;
    }
    Some(Ran {
        success: output.status?.success(),
        text: output.stdout + &output.stderr,
    })
}

#[derive(Debug)]
pub struct CapturedOutput {
    pub status: Option<ExitStatus>,
    pub timed_out: bool,
    pub elapsed: Duration,
    pub stdout: String,
    pub stderr: String,
}

#[cfg(unix)]
fn executable(candidate: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(candidate.as_os_str().as_bytes()) else {
        return false;
    };
    std::fs::metadata(candidate).is_ok_and(|m| m.is_file())
        && unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), libc::X_OK, libc::AT_EACCESS) }
            == 0
}

#[cfg(unix)]
fn script_interpreter_exists(candidate: &std::path::Path) -> bool {
    use std::io::BufRead;
    use std::os::unix::ffi::OsStrExt;
    let Ok(file) = std::fs::File::open(candidate) else {
        return true;
    };
    let mut line = Vec::new();
    if std::io::BufReader::new(file.take(512))
        .read_until(b'\n', &mut line)
        .is_err()
    {
        return true;
    }
    let Some(interpreter) = line.strip_prefix(b"#!") else {
        return true;
    };
    let interpreter = interpreter.strip_suffix(b"\n").unwrap_or(interpreter);
    let interpreter = interpreter
        .split(|b| matches!(b, b' ' | b'\t'))
        .find(|s| !s.is_empty())
        .unwrap_or_default();
    // Some emulators report a successful spawn even when the interpreter is absent.
    executable(std::path::Path::new(std::ffi::OsStr::from_bytes(
        interpreter,
    )))
}

#[cfg(unix)]
fn resolve_program(
    program: &str,
    path: Option<&std::ffi::OsStr>,
) -> std::io::Result<std::path::PathBuf> {
    use std::path::{Path, PathBuf};

    let resolved = if program.contains('/') {
        let candidate = PathBuf::from(program);
        (executable(&candidate) && script_interpreter_exists(&candidate)).then_some(candidate)
    } else {
        let default = default_search_path();
        Some(path.unwrap_or(&default)).and_then(|path| {
            std::env::split_paths(path)
                .map(|entry| {
                    if entry.as_os_str().is_empty() {
                        Path::new(".").join(program)
                    } else {
                        entry.join(program)
                    }
                })
                .find(|candidate| executable(candidate))
        })
    };
    resolved.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
}

#[cfg(unix)]
fn default_search_path() -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    // confstr supplies the platform's exec search path without consulting PATH.
    unsafe {
        let size = libc::confstr(libc::_CS_PATH, std::ptr::null_mut(), 0);
        let mut bytes = vec![0; size];
        if size == 0 || libc::confstr(libc::_CS_PATH, bytes.as_mut_ptr().cast(), size) == 0 {
            return "/bin:/usr/bin".into();
        }
        bytes.pop();
        std::ffi::OsString::from_vec(bytes)
    }
}

fn spawn(
    program: impl AsRef<std::ffi::OsStr>,
    args: &[&str],
) -> std::io::Result<std::process::Child> {
    Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

#[cfg(unix)]
fn spawn_program(
    program: &str,
    args: &[&str],
    path: Option<&std::ffi::OsStr>,
) -> std::io::Result<std::process::Child> {
    if program.contains('/') {
        return spawn(resolve_program(program, path)?, args);
    }
    let default = default_search_path();
    let path = path.unwrap_or(&default);
    let mut denied = None;
    for entry in std::env::split_paths(path) {
        let entry = if entry.as_os_str().is_empty() {
            std::path::PathBuf::from(".")
        } else {
            entry
        };
        let candidate = entry.join(program);
        if !executable(&candidate) || !script_interpreter_exists(&candidate) {
            continue;
        }
        match spawn(&candidate, args) {
            Ok(child) => return Ok(child),
            Err(error) => match error.raw_os_error() {
                Some(libc::EACCES) => denied = Some(error),
                Some(libc::ENOENT | libc::ENOTDIR) => (),
                _ => return Err(error),
            },
        }
    }
    Err(denied.unwrap_or_else(|| std::io::ErrorKind::NotFound.into()))
}

pub fn capture(program: &str, args: &[&str], timeout: Duration) -> std::io::Result<CapturedOutput> {
    let start = Instant::now();
    #[cfg(unix)]
    let mut child = spawn_program(program, args, std::env::var_os("PATH").as_deref())?;
    #[cfg(not(unix))]
    let mut child = spawn(program, args)?;
    let readers = [
        child.stdout.take().map(drain),
        child.stderr.take().map(drain),
    ];
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            result => {
                timed_out = matches!(result, Ok(None));
                let _ = child.kill();
                let status = child.wait();
                result?;
                break status.ok();
            }
        }
    };
    let grace = Instant::now() + Duration::from_millis(250);
    let mut streams = [String::new(), String::new()];
    for (stream, reader) in streams.iter_mut().zip(readers) {
        let Some((buf, reader)) = reader else {
            continue;
        };
        while !reader.is_finished() && Instant::now() < grace {
            thread::sleep(Duration::from_millis(5));
        }
        let bytes = buf
            .lock()
            .map_err(|_| std::io::Error::other("output reader panicked"))?;
        *stream = String::from_utf8_lossy(&bytes).into_owned();
    }
    let [stdout, stderr] = streams;
    Ok(CapturedOutput {
        status,
        timed_out,
        elapsed: start.elapsed(),
        stdout,
        stderr,
    })
}

/// A background grandchild can keep the pipe open after the child exits, so
/// the reader fills a shared buffer and the caller stops waiting shortly after the child exits.
fn drain<R: Read + Send + 'static>(mut pipe: R) -> (Captured, thread::JoinHandle<()>) {
    let buf: Captured = Arc::default();
    let sink = Arc::clone(&buf);
    let handle = thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n) = pipe.read(&mut chunk) {
            if n == 0 {
                break;
            }
            if let Ok(mut bytes) = sink.lock() {
                bytes.extend_from_slice(&chunk[..n]);
            }
        }
    });
    (buf, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_stdout_and_stderr() {
        let out = run("sh", &["-c", "echo out; echo err >&2"]).unwrap();
        assert!(out.contains("out") && out.contains("err"));
    }

    #[test]
    fn reports_the_exit_status() {
        assert!(run_status("sh", &["-c", "echo ok"]).unwrap().success);
        let failed = run_status("sh", &["-c", "echo no >&2; exit 1"]).unwrap();
        assert!(!failed.success && failed.text.contains("no"));
    }

    #[test]
    #[cfg(unix)]
    fn timeout_preserves_partial_stdout_and_stderr() {
        let output = capture(
            "sh",
            &[
                "-c",
                "printf 'bitlocker\t1\nsecure_boot\t1'; printf 'diagnostic' >&2; exec sleep 30",
            ],
            Duration::from_millis(200),
        )
        .unwrap();
        assert!(output.timed_out, "{output:?}");
        assert!(!output.status.unwrap().success());
        assert_eq!(output.stdout, "bitlocker\t1\nsecure_boot\t1");
        assert_eq!(output.stderr, "diagnostic");
    }

    #[test]
    fn missing_program_is_none() {
        assert_eq!(run("open-pact-no-such-binary", &[]), None);
    }

    #[test]
    fn background_child_holding_the_pipe_does_not_stall() {
        let start = Instant::now();
        let out = run("sh", &["-c", "sleep 20 & echo started"]).unwrap();
        assert!(out.contains("started"));
        assert!(start.elapsed() < Duration::from_secs(6));
    }

    #[test]
    fn hanging_program_is_killed() {
        let start = Instant::now();
        assert_eq!(run("sleep", &["30"]), None);
        assert!(start.elapsed() < Duration::from_secs(6));
    }

    #[test]
    #[cfg(unix)]
    fn explicit_timeout_kills_a_hanging_program() {
        let start = Instant::now();
        assert_eq!(
            run_with_timeout("sleep", &["30"], Duration::from_millis(200)),
            None
        );
        assert!(start.elapsed() < Duration::from_secs(6));
    }

    #[cfg(windows)]
    #[test]
    fn explicit_timeout_kills_a_hanging_program_on_windows() {
        let timeout = Duration::from_millis(200);
        let start = Instant::now();
        assert_eq!(
            run_with_timeout(
                "powershell.exe",
                &["-NoProfile", "-Command", "Start-Sleep -Seconds 30"],
                timeout
            ),
            None
        );
        assert!(start.elapsed() >= timeout);
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}

#[cfg(all(test, unix))]
mod unix_resolution_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn write_program(path: &Path, executable: bool, output: &str) {
        std::fs::write(path, format!("#!/bin/sh\nprintf '{output}'\n")).unwrap();
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(if executable { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }

    #[test]
    fn absent_path_uses_platform_default_but_empty_path_does_not() {
        let output = spawn_program("sh", &["-c", "printf default-path"], None)
            .unwrap()
            .wait_with_output()
            .unwrap();
        assert_eq!(output.stdout, b"default-path");
        assert_eq!(
            spawn_program("sh", &[], Some(std::ffi::OsStr::new("")))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn search_continues_after_denied_or_missing_interpreter() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let file = first.join("fictional-program");
        write_program(&second.join("fictional-program"), true, "usable");
        let path = std::env::join_paths([&first, &second]).unwrap();
        for stale_interpreter in [false, true] {
            write_program(&file, true, "denied");
            if stale_interpreter {
                std::fs::write(&file, "#!/fictional/missing-interpreter\n").unwrap();
            } else {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o601)).unwrap();
                if unsafe { libc::geteuid() } == 0 {
                    continue;
                }
            }
            let output = spawn_program("fictional-program", &[], Some(&path))
                .unwrap()
                .wait_with_output()
                .unwrap();
            assert_eq!(output.stdout, b"usable");
        }
    }

    #[test]
    fn missing_bare_program_returns_not_found() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_program("fictional-missing", Some(root.path().as_os_str()))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(
            resolve_program("fictional-missing", None)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn missing_absolute_program_returns_not_found_without_spawning() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("fictional-missing");
        assert_eq!(
            capture(missing.to_str().unwrap(), &[], TIMEOUT)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn non_executable_file_and_directory_are_not_programs() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("fictional-program");
        write_program(&file, false, "fictional");
        for path in [file.as_path(), root.path()] {
            assert_eq!(
                capture(path.to_str().unwrap(), &[], TIMEOUT)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::NotFound
            );
        }
    }

    #[test]
    fn fictional_path_skips_non_executable_files_and_uses_the_first_executable() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        write_program(&first.join("fictional-program"), false, "first");
        write_program(&second.join("fictional-program"), true, "second");
        let path = std::env::join_paths([&first, &second]).unwrap();
        let resolved = resolve_program("fictional-program", Some(&path)).unwrap();
        assert_eq!(resolved, second.join("fictional-program"));
        assert_eq!(
            capture(resolved.to_str().unwrap(), &[], TIMEOUT)
                .unwrap()
                .stdout,
            "second"
        );
        write_program(&first.join("fictional-program"), true, "first");
        assert_eq!(
            resolve_program("fictional-program", Some(&path)).unwrap(),
            first.join("fictional-program")
        );
    }

    #[test]
    fn empty_path_entry_searches_the_current_directory() {
        let file = tempfile::Builder::new()
            .prefix(".fictional-exec-")
            .tempfile_in(".")
            .unwrap()
            .into_temp_path();
        write_program(&file, true, "fictional-current");
        let name = file.file_name().unwrap().to_str().unwrap();
        let resolved = resolve_program(name, Some(std::ffi::OsStr::new(""))).unwrap();
        assert_eq!(resolved, Path::new(".").join(name));
        assert_eq!(
            capture(resolved.to_str().unwrap(), &[], TIMEOUT)
                .unwrap()
                .stdout,
            "fictional-current"
        );
    }
}
