//! The real binary, interrupted while a repository scan reads a FIFO. Ctrl-C ends the process
//! with exit 130 at once: the blocked scan thread does not keep it alive.
#![cfg(unix)]

use std::ffi::CString;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use open_pact_core::{
    Checkpoint, Endorsement, Invitation, InvitationCode, LogHash, LogKey, Manifest, PublicKey,
    dev_key,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The request head and body of one request. Reads the whole body, so that a reply does not
/// reset a client that still sends it.
async fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            return String::from_utf8_lossy(&buf).into_owned();
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    while buf.len() < head_end + length {
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    head
}

#[tokio::test]
async fn ctrl_c_during_a_blocked_repository_scan_exits_130_at_once() {
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
    let enrolled = Arc::new(tokio::sync::Notify::new());
    let enrolment_seen = enrolled.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            let is_enrolment = request.starts_with("POST /v1/enroll ");
            let body = if request.starts_with("GET /v1/manifest ") {
                published.clone()
            } else if request.starts_with("GET /v1/log/key ") {
                log.vkey().to_string()
            } else if request.starts_with("GET /v1/log/checkpoint") {
                checkpoint.clone()
            } else if request.starts_with("POST /v1/nonce ") {
                json!({"nonce": "wait-1"}).to_string()
            } else if request.starts_with("POST /v1/device/status ") {
                json!({"state": "pending"}).to_string()
            } else {
                json!({"salt": "11".repeat(32), "state": "pending"}).to_string()
            };
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
            if is_enrolment {
                enrolment_seen.notify_one();
            }
        }
    });

    // The device home holds the device state. The child's HOME holds a FIFO where the SSH config
    // should be: the repository scan opens it first. The test is the writer, and it writes nothing,
    // so the scan blocks reading the FIFO.
    let device_home = tempfile::tempdir().unwrap();
    let user_home = tempfile::tempdir().unwrap();
    let ssh = user_home.path().join(".ssh");
    std::fs::create_dir(&ssh).unwrap();
    let fifo = CString::new(ssh.join("config").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_open-pact-client"))
        .kill_on_drop(true)
        .arg("--home")
        .arg(device_home.path())
        .args(["join", "--yes", "--json", "--software-key"])
        .arg(invitation)
        .env("HOME", user_home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id().unwrap();

    tokio::time::timeout(Duration::from_secs(30), enrolled.notified())
        .await
        .expect("the join enrols the device and starts the repository scan");
    // The enrolment reply is sent. The wizard then waits for IT, and the scan opens the FIFO. A
    // non-blocking writer open fails with ENXIO until a reader exists. When it succeeds, the scan
    // thread is inside its open of the FIFO. The writer stays open until the child has exited, so
    // the scan then blocks on its read.
    let deadline = Instant::now() + Duration::from_secs(30);
    let _writer = loop {
        let fd = unsafe {
            libc::open(
                fifo.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            break unsafe { std::fs::File::from_raw_fd(fd) };
        }
        let error = std::io::Error::last_os_error();
        assert_eq!(error.raw_os_error(), Some(libc::ENXIO), "{error}");
        assert!(
            Instant::now() < deadline,
            "the repository scan never opened the FIFO"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) }, 0);

    // On timeout the child is dropped, and kill_on_drop ends it along with its blocked scan.
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await;
    server.abort();
    let output = output
        .expect("the interrupted CLI exits within five seconds, not after its blocked scan")
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(130), "{stdout}");
    let last: serde_json::Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
    assert_eq!(last["error"], "interrupted", "{stdout}");
}
