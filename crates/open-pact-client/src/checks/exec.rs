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
fn program_exists(program: &str, path: Option<&std::ffi::OsStr>) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let executable = |candidate: &std::path::Path| {
        std::fs::metadata(candidate)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if program.contains('/') {
        return executable(std::path::Path::new(program));
    }
    let default = default_search_path();
    std::env::split_paths(path.unwrap_or(&default)).any(|entry| executable(&entry.join(program)))
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

pub fn capture(program: &str, args: &[&str], timeout: Duration) -> std::io::Result<CapturedOutput> {
    let start = Instant::now();
    #[cfg(unix)]
    if !program_exists(program, std::env::var_os("PATH").as_deref()) {
        return Err(std::io::ErrorKind::NotFound.into());
    }
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
        assert!(program_exists("sh", None));
        assert!(!program_exists("sh", Some(std::ffi::OsStr::new(""))));
    }

    #[test]
    fn missing_bare_program_returns_not_found() {
        let root = tempfile::tempdir().unwrap();
        assert!(!program_exists(
            "fictional-missing",
            Some(root.path().as_os_str())
        ));
        assert!(!program_exists("fictional-missing", None));
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
    fn execute_bit_precheck_does_not_test_effective_access_or_interpreters() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("fictional-program");
        std::fs::write(&file, "#!/fictional/missing-interpreter\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o601)).unwrap();
        assert!(program_exists(file.to_str().unwrap(), None));
        assert!(program_exists(
            "fictional-program",
            Some(root.path().as_os_str())
        ));
    }

    #[test]
    fn lookup_child() {
        let Ok(program) = std::env::var("FICTIONAL_LOOKUP_PROGRAM") else {
            return;
        };
        let expected = spawn(&program, &["-c", "printf default-path"])
            .and_then(|child| child.wait_with_output());
        let actual = capture(&program, &["-c", "printf default-path"], TIMEOUT);
        match (expected, actual) {
            (Ok(expected), Ok(actual)) => {
                assert_eq!(actual.status, Some(expected.status));
                assert_eq!(actual.stdout.as_bytes(), expected.stdout);
                assert_eq!(actual.stderr.as_bytes(), expected.stderr);
            }
            (Err(expected), Err(actual)) => assert_eq!(actual.kind(), expected.kind()),
            (expected, actual) => panic!("direct spawn {expected:?}, capture {actual:?}"),
        }
    }

    fn compare_lookup(program: &str, path: Option<&std::ffi::OsStr>, cwd: &Path) {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "checks::exec::unix_resolution_tests::lookup_child",
                "--nocapture",
            ])
            .current_dir(cwd)
            .env("FICTIONAL_LOOKUP_PROGRAM", program);
        if let Some(path) = path {
            child.env("PATH", path);
        } else {
            child.env_remove("PATH");
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn original_name_preserves_platform_lookup_for_all_script_formats() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let file = first.join("fictional-program");
        write_program(&second.join("fictional-program"), true, "second");
        let path = std::env::join_paths([&first, &second]).unwrap();
        for script in [
            "#!\nprintf first",
            "#!   \nprintf first",
            "printf first",
            "#!/fictional/missing-interpreter\n",
            "#!/bin/sh\nprintf first",
        ] {
            std::fs::write(&file, script).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
            compare_lookup("fictional-program", Some(&path), root.path());
            compare_lookup(file.to_str().unwrap(), Some(&path), root.path());
        }
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o601)).unwrap();
        compare_lookup("fictional-program", Some(&path), root.path());
        compare_lookup("sh", None, root.path());
        compare_lookup(
            "fictional-program",
            Some(std::ffi::OsStr::new(":")),
            &second,
        );
    }
}
