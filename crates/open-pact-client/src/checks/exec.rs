use std::io::Read;
use std::process::{Command, Stdio};
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

pub fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    run_status_with_timeout(program, args, timeout).map(|ran| ran.text)
}

fn run_status_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<Ran> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let readers = [
        child.stdout.take().map(drain),
        child.stderr.take().map(drain),
    ];
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let grace = (Instant::now() + Duration::from_millis(250)).min(deadline);
    let mut text = String::new();
    for (buf, reader) in readers.into_iter().flatten() {
        while !reader.is_finished() && Instant::now() < grace {
            thread::sleep(Duration::from_millis(5));
        }
        let bytes = buf.lock().ok()?;
        text.push_str(&String::from_utf8_lossy(&bytes));
    }
    Some(Ran {
        success: status.success(),
        text,
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
