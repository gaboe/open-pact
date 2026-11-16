//! The real binary on a command line that does not parse: with a JSON flag, stdout holds one
//! error document and nothing else.

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_open-pact-client"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn an_argument_failure_with_a_json_flag_prints_one_error_document() {
    for args in [
        &["join", "--json", "--yes", "--auto-send", "maybe"][..],
        &["join", "--preview"],
        &["check", "--json", "--bogus"],
        &["status", "--json", "--bogus"],
    ] {
        let output = run(args);

        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let document: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("{args:?} printed {stdout:?}: {error}"));
        assert_eq!(document.as_object().unwrap().len(), 1, "{stdout}");
        assert!(!document["error"].as_str().unwrap().is_empty(), "{stdout}");
        assert_eq!(stdout.lines().count(), 1, "{stdout}");
        assert!(output.stderr.is_empty(), "{args:?}");
    }
}

#[test]
fn an_argument_failure_without_a_json_flag_stays_a_readable_error_on_stderr() {
    let output = run(&["join", "--bogus"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--bogus"));
}

#[test]
fn help_still_prints_on_stdout() {
    let output = run(&["join", "--help", "--json"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
}

#[cfg(unix)]
#[tokio::test]
async fn a_json_join_survives_a_closed_stderr_pipe() {
    use open_pact_core::{
        Checkpoint, Endorsement, Invitation, InvitationCode, LogHash, LogKey, Manifest, PublicKey,
        dev_key,
    };
    use serde_json::json;
    use std::os::fd::FromRawFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let company = dev_key::generate();
    let signer = dev_key::generate();
    let log = LogKey::new("pact.example.com/log", &PublicKey::from(&signer));
    let demo = include_str!("../../../examples/manifest.toml");
    let (before, after) = demo.split_once("[log]").unwrap();
    let (_, schedule) = after.split_once("[schedule]").unwrap();
    let toml = format!(
        "{before}[log]\nallow_split_views = true\nwitness_quorum = 0\ncheckpoint_max_age = \"1h\"\n[schedule]{schedule}"
    );
    let manifest = Manifest::parse(toml.as_bytes()).unwrap();
    let published = json!({
        "toml": toml,
        "company": Endorsement::sign(&company, manifest.hash()),
    })
    .to_string();
    let checkpoint = log
        .sign(
            &signer,
            &Checkpoint {
                origin: log.origin().into(),
                size: 1,
                root: LogHash([3; 32]),
            },
        )
        .to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let invitation = Invitation::new(
        &url,
        &PublicKey::from(&company),
        &log,
        InvitationCode::from_bytes([7; 32]),
    )
    .encode();
    let pid = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let client_pid = pid.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let mut chunk = [0; 4096];
                let n = stream.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            let request = String::from_utf8_lossy(&request);
            let body = if request.starts_with("GET /v1/manifest ") {
                published.clone()
            } else if request.starts_with("GET /v1/log/key ") {
                log.vkey().to_string()
            } else if request.starts_with("GET /v1/log/checkpoint ") {
                // Some hosts suppress SIGPIPE from pipe writes. Deliver the same signal at
                // the warning boundary so this also checks real main's signal disposition.
                let pid = client_pid.load(std::sync::atomic::Ordering::Relaxed);
                assert_ne!(pid, 0);
                assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGPIPE) }, 0);
                checkpoint.clone()
            } else {
                json!({"salt": "11".repeat(32), "state": "pending"}).to_string()
            };
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    let home = tempfile::tempdir().unwrap();
    // Use an ordinary OS pipe, as a shell would for diagnostic output.
    let mut pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    let writer = unsafe {
        drop(std::fs::File::from_raw_fd(pipe[0]));
        std::fs::File::from_raw_fd(pipe[1])
    };
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_open-pact-client"));
    command
        .kill_on_drop(true)
        .arg("--home")
        .arg(home.path())
        .args(["join", "--yes", "--json", "--software-key", "--no-wait"])
        .arg(invitation)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(writer));
    unsafe {
        command.pre_exec(|| {
            #[cfg(target_os = "macos")]
            if libc::fcntl(libc::STDERR_FILENO, libc::F_SETNOSIGPIPE, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let mut signals = std::mem::zeroed();
            libc::sigemptyset(&mut signals);
            libc::sigaddset(&mut signals, libc::SIGPIPE);
            if libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.stdout(std::process::Stdio::piped());
    let child = command.spawn().unwrap();
    pid.store(child.id().unwrap(), std::sync::atomic::Ordering::Relaxed);
    let output =
        tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output()).await;
    server.abort();
    let _ = server.await;
    let output = output
        .expect("join finishes within thirty seconds")
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{}: {stdout}", output.status);
    let documents: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("only NDJSON on stdout"))
        .collect();
    assert_eq!(documents.last().unwrap()["result"], "enrolled", "{stdout}");
}
