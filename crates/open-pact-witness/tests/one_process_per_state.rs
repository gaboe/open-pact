use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn witness(dir: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_open-pact-witness"))
        .env("WITNESS_NAME", "witness.example.org/test")
        .env("WITNESS_KEY_FILE", dir.join("witness.key"))
        .env("WITNESS_STATE", dir.join("state.json"))
        .env("WITNESS_LOG_KEYS", "")
        .env("LISTEN_ADDR", "127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn a_second_process_refuses_a_state_file_another_process_holds() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("witness.key"),
        format!("{}\n", "05".repeat(32)),
    )
    .unwrap();

    let mut first = witness(dir.path());
    let mut lines = BufReader::new(first.stderr.take().unwrap()).lines();
    let started = lines.next().unwrap().unwrap();
    assert!(started.starts_with("witness key "), "{started}");

    let mut second = witness(dir.path());
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = second.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    second.kill().ok();
    first.kill().unwrap();
    first.wait().unwrap();
    let status = status.expect("the second witness kept running on the same state file");
    assert!(!status.success());
    let mut err = String::new();
    std::io::Read::read_to_string(&mut second.stderr.take().unwrap(), &mut err).unwrap();
    assert!(err.contains("another witness process"), "{err}");

    let mut restarted = witness(dir.path());
    let mut lines = BufReader::new(restarted.stderr.take().unwrap()).lines();
    let started = lines.next().unwrap().unwrap();
    restarted.kill().unwrap();
    restarted.wait().unwrap();
    assert!(
        started.starts_with("witness key "),
        "after the first exits: {started}"
    );
}
