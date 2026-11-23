use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub const TIMEOUT: Duration = Duration::from_secs(3);

type Captured = Arc<Mutex<Vec<u8>>>;

/// How often the wait loop looks at the child.
const POLL: Duration = Duration::from_millis(10);

/// Output of a command that exited before the timeout, with stdout and stderr together.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub struct Ran {
    pub success: bool,
    pub text: String,
}

/// The output of `program`, whatever its exit status. `None` when it cannot start or times out.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub fn run(program: &str, args: &[&str]) -> Option<String> {
    run_status(program, args).map(|ran| ran.text)
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub fn run_status(program: &str, args: &[&str]) -> Option<Ran> {
    run_status_with_timeout(program, args, TIMEOUT)
}

#[cfg(test)]
pub fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    run_status_with_timeout(program, args, timeout).map(|ran| ran.text)
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub(super) fn run_status_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Option<Ran> {
    let output = capture(program, args, timeout).ok()?;
    if output.timed_out {
        return None;
    }
    Some(Ran {
        success: output.status?.success(),
        text: output.stdout + &output.stderr,
    })
}

/// The stdout of a command that exited before the timeout, and printed at most `max_stdout` bytes.
/// Stderr is not part of `text`. `None` when it cannot start, times out, or prints more.
#[cfg(any(target_os = "macos", test))]
pub(super) fn run_stdout_with_limit(
    program: &str,
    args: &[&str],
    timeout: Duration,
    max_stdout: usize,
) -> Option<Ran> {
    let output = capture_limited(program, args, timeout, Some(max_stdout), POLL).ok()?;
    if output.timed_out || output.stdout_overflowed || output.stdout_invalid_utf8 {
        return None;
    }
    Some(Ran {
        success: output.status?.success(),
        text: output.stdout,
    })
}

#[derive(Debug)]
pub struct CapturedOutput {
    pub status: Option<ExitStatus>,
    /// The child did not exit before the deadline. With a stdout limit, a child that exits after it counts too.
    pub timed_out: bool,
    /// The child printed more than the stdout limit. `stdout` holds only the bytes before it.
    #[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
    pub stdout_overflowed: bool,
    /// The child's stdout was not valid UTF-8. `stdout` then has U+FFFD in place of those bytes.
    #[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
    pub stdout_invalid_utf8: bool,
    #[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
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
    piped_stdin: bool,
) -> std::io::Result<std::process::Child> {
    Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(if piped_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub fn capture(program: &str, args: &[&str], timeout: Duration) -> std::io::Result<CapturedOutput> {
    capture_input(program, args, None, timeout)
}

/// Like [`capture`], and writes `input` to the child's stdin, then closes it. A script sent this
/// way does not count against the command line limit of the platform.
#[cfg(any(windows, test))]
pub fn capture_with_stdin(
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
) -> std::io::Result<CapturedOutput> {
    capture_input(program, args, Some(input), timeout)
}

fn capture_input(
    program: &str,
    args: &[&str],
    input: Option<&[u8]>,
    timeout: Duration,
) -> std::io::Result<CapturedOutput> {
    capture_with(program, args, input, timeout, None, POLL)
}

#[cfg(any(target_os = "macos", test))]
fn capture_limited(
    program: &str,
    args: &[&str],
    timeout: Duration,
    max_stdout: Option<usize>,
    poll: Duration,
) -> std::io::Result<CapturedOutput> {
    capture_with(program, args, None, timeout, max_stdout, poll)
}

fn capture_with(
    program: &str,
    args: &[&str],
    input: Option<&[u8]>,
    timeout: Duration,
    max_stdout: Option<usize>,
    poll: Duration,
) -> std::io::Result<CapturedOutput> {
    let start = Instant::now();
    #[cfg(unix)]
    if !program_exists(program, std::env::var_os("PATH").as_deref()) {
        return Err(std::io::ErrorKind::NotFound.into());
    }
    let mut child = spawn(program, args, input.is_some())?;
    // A thread writes, so that a child that does not read cannot block the timeout below. The
    // write fails once the child exits or is killed, and the thread ends with it.
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        let input = input.to_vec();
        thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    let overflow = Arc::new(AtomicBool::new(false));
    let readers = [
        child
            .stdout
            .take()
            .map(|pipe| drain(pipe, max_stdout, Arc::clone(&overflow))),
        child
            .stderr
            .take()
            .map(|pipe| drain(pipe, None, Arc::default())),
    ];
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        if overflow.load(Ordering::Relaxed) {
            let _ = child.kill();
            break child.wait().ok();
        }
        match child.try_wait() {
            // With a stdout limit, an exit that this loop sees after the deadline is a timeout, as if
            // it had been killed.
            Ok(Some(status)) => {
                timed_out = max_stdout.is_some() && Instant::now() >= deadline;
                break Some(status);
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(poll),
            result => {
                timed_out = matches!(result, Ok(None));
                let _ = child.kill();
                let status = child.wait();
                result?;
                break status.ok();
            }
        }
    };
    #[cfg(windows)]
    crate::timings::note_child(&child);
    let grace = Instant::now() + Duration::from_millis(250);
    let mut streams = [String::new(), String::new()];
    let mut stdout_invalid_utf8 = false;
    for (index, (stream, reader)) in streams.iter_mut().zip(readers).enumerate() {
        let Some((buf, reader)) = reader else {
            continue;
        };
        while !reader.is_finished() && Instant::now() < grace {
            thread::sleep(Duration::from_millis(5));
        }
        let bytes = buf
            .lock()
            .map_err(|_| std::io::Error::other("output reader panicked"))?;
        if index == 0 {
            stdout_invalid_utf8 = std::str::from_utf8(&bytes).is_err();
        }
        *stream = String::from_utf8_lossy(&bytes).into_owned();
    }
    let [stdout, stderr] = streams;
    Ok(CapturedOutput {
        status,
        timed_out,
        stdout_overflowed: overflow.load(Ordering::Relaxed),
        stdout_invalid_utf8,
        elapsed: start.elapsed(),
        stdout,
        stderr,
    })
}

/// A background grandchild can keep the pipe open after the child exits, so
/// the reader fills a shared buffer and the caller stops waiting shortly after the child exits.
///
/// With a `limit`, the reader stops at the first byte past it, keeps the bytes before it, and sets
/// `overflow`, so a child that prints without end cannot fill memory.
fn drain<R: Read + Send + 'static>(
    mut pipe: R,
    limit: Option<usize>,
    overflow: Arc<AtomicBool>,
) -> (Captured, thread::JoinHandle<()>) {
    let buf: Captured = Arc::default();
    let sink = Arc::clone(&buf);
    let handle = thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n) = pipe.read(&mut chunk) {
            if n == 0 {
                break;
            }
            let Ok(mut bytes) = sink.lock() else {
                break;
            };
            let room = limit.map_or(n, |limit| limit.saturating_sub(bytes.len()).min(n));
            bytes.extend_from_slice(&chunk[..room]);
            if room < n {
                overflow.store(true, Ordering::Relaxed);
                break;
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
    #[cfg(unix)]
    fn stdin_input_reaches_the_child_and_is_closed() {
        let input = "x".repeat(1 << 20);
        let output =
            capture_with_stdin("cat", &[], input.as_bytes(), Duration::from_secs(20)).unwrap();
        assert!(!output.timed_out, "{output:?}");
        assert!(output.status.unwrap().success());
        assert_eq!(output.stdout, input);
    }

    #[test]
    #[cfg(unix)]
    fn a_child_that_ignores_stdin_still_times_out() {
        let input = vec![b'x'; 1 << 20];
        let output = capture_with_stdin(
            "sh",
            &["-c", "exec sleep 30"],
            &input,
            Duration::from_millis(200),
        )
        .unwrap();
        assert!(output.timed_out, "{output:?}");
    }

    #[test]
    #[cfg(unix)]
    fn stdout_only_read_leaves_stderr_out_of_the_text() {
        let ran = run_stdout_with_limit(
            "sh",
            &["-c", "printf out; printf '{\"finished\":1}' >&2"],
            Duration::from_secs(5),
            1024,
        )
        .unwrap();
        assert!(ran.success);
        assert_eq!(ran.text, "out");
    }

    #[test]
    #[cfg(unix)]
    fn stdout_over_the_limit_is_none() {
        let read = |bytes: usize| {
            run_stdout_with_limit(
                "sh",
                &["-c", &format!("head -c {bytes} /dev/zero")],
                Duration::from_secs(5),
                1024,
            )
        };
        assert_eq!(read(1024).unwrap().text.len(), 1024);
        assert!(read(1025).is_none());
        // A producer that never stops is cut off long before its own timeout.
        let start = Instant::now();
        let endless = run_stdout_with_limit("yes", &[], Duration::from_secs(5), 1 << 20);
        assert!(endless.is_none());
        assert!(start.elapsed() < Duration::from_secs(4));
    }

    #[test]
    #[cfg(unix)]
    fn an_exit_seen_after_the_deadline_is_a_timeout() {
        // The child exits at about 500 ms. The loop looks again only at 2 s, well past the 100 ms deadline
        // and the exit, so a slow runner still sees an exited child on that second look.
        let output = capture_limited(
            "sh",
            &["-c", "printf late; sleep 0.5"],
            Duration::from_millis(100),
            Some(1024),
            Duration::from_secs(2),
        )
        .unwrap();
        // The status is a success, so the late exit set the timeout, not a kill.
        assert!(output.timed_out, "{output:?}");
        assert!(output.status.unwrap().success(), "{output:?}");
    }

    #[test]
    #[cfg(unix)]
    fn an_exit_seen_after_the_deadline_is_kept_without_a_stdout_limit() {
        let output = capture_limited(
            "sh",
            &["-c", "printf late; sleep 0.5"],
            Duration::from_millis(100),
            None,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(!output.timed_out, "{output:?}");
        assert!(output.status.unwrap().success(), "{output:?}");
        assert_eq!(output.stdout, "late");
    }

    #[test]
    #[cfg(unix)]
    fn stdout_that_is_not_utf8_is_none_with_a_limit() {
        let script = "printf '\\377'";
        let limited = run_stdout_with_limit("sh", &["-c", script], Duration::from_secs(5), 1024);
        assert!(limited.is_none(), "invalid UTF-8 was accepted");
        // Without a limit, the same byte comes back as U+FFFD.
        let output = capture("sh", &["-c", script], Duration::from_secs(5)).unwrap();
        assert_eq!(output.stdout, "\u{FFFD}");
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
                &crate::machine::system_powershell().to_string_lossy(),
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
        let expected = spawn(&program, &["-c", "printf default-path"], false)
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
