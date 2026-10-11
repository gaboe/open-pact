use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const TIMEOUT: Duration = Duration::from_secs(3);

pub fn run(program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let readers = [
        child.stdout.take().map(drain),
        child.stderr.take().map(drain),
    ];
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut text = String::new();
    for reader in readers.into_iter().flatten() {
        let bytes = reader.join().ok()?;
        text.push_str(&String::from_utf8_lossy(&bytes));
    }
    Some(text)
}

fn drain<R: Read + Send + 'static>(mut pipe: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
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
    fn missing_program_is_none() {
        assert_eq!(run("open-pact-no-such-binary", &[]), None);
    }

    #[test]
    fn hanging_program_is_killed() {
        let start = Instant::now();
        assert_eq!(run("sleep", &["30"]), None);
        assert!(start.elapsed() < Duration::from_secs(6));
    }
}
