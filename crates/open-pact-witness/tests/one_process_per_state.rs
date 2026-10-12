use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use open_pact_core::{
    AddCheckpoint, Checkpoint, LogHash, LogKey, PublicKey, SigningKey, consistency_proof, dev_key,
    leaf_hash, root,
};

const ORIGIN: &str = "pact.example.com/log";

fn command(key: &Path, state: &Path, log_keys: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_open-pact-witness"));
    command
        .env("WITNESS_NAME", "witness.example.org/test")
        .env("WITNESS_KEY_FILE", key)
        .env("WITNESS_STATE", state)
        .env("WITNESS_LOG_KEYS", log_keys)
        .env("LISTEN_ADDR", "127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

fn witness(dir: &Path) -> Child {
    command(&dir.join("witness.key"), &dir.join("state.json"), "")
        .spawn()
        .unwrap()
}

fn write_key(path: &Path, byte: u8) {
    std::fs::write(path, format!("{}\n", format!("{byte:02x}").repeat(32))).unwrap();
}

/// Waits until `child` exits and returns its stderr. Panics if it is still running after 10s.
fn refused(mut child: Child) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().ok();
            child.wait().ok();
            panic!("the witness kept running");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(!status.success());
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    err
}

fn lock_of(state: &Path) -> PathBuf {
    let mut name = state.as_os_str().to_owned();
    name.push(".lockdir");
    PathBuf::from(name)
}

#[test]
fn a_second_process_refuses_a_state_file_another_process_holds() {
    let dir = tempfile::tempdir().unwrap();
    write_key(&dir.path().join("witness.key"), 5);

    let mut first = witness(dir.path());
    let mut lines = BufReader::new(first.stderr.take().unwrap()).lines();
    let started = lines.next().unwrap().unwrap();
    assert!(started.starts_with("witness key "), "{started}");

    let err = refused(witness(dir.path()));
    first.kill().unwrap();
    first.wait().unwrap();
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

struct Log {
    signer: SigningKey,
    key: LogKey,
    leaves: Vec<LogHash>,
}

impl Log {
    fn new() -> Log {
        let signer = dev_key::generate();
        Log {
            key: LogKey::new(ORIGIN, &PublicKey::from(&signer)),
            signer,
            leaves: (0u8..16).map(|i| leaf_hash(&[i])).collect(),
        }
    }

    /// An add-checkpoint request body from `old` to `size`.
    fn add(&self, old: u64, size: u64) -> String {
        let leaves = &self.leaves[..size as usize];
        let cp = Checkpoint {
            origin: ORIGIN.into(),
            size,
            root: root(leaves),
        };
        AddCheckpoint {
            old_size: old,
            proof: if old == 0 || old == size {
                vec![]
            } else {
                consistency_proof(leaves, old).unwrap()
            },
            note: self.key.sign(&self.signer, &cp),
        }
        .to_string()
    }
}

/// A running witness process and the address it listens on.
struct Running {
    child: Child,
    addr: String,
}

impl Running {
    fn start(key: &Path, state: &Path, log: &Log) -> Running {
        let mut child = command(key, state, &log.key.vkey()).spawn().unwrap();
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        let addr = loop {
            let line = lines
                .next()
                .expect("the witness exited before it listened")
                .unwrap();
            if let Some(addr) = line.strip_prefix("listening on ") {
                break addr.to_string();
            }
        };
        std::thread::spawn(move || lines.for_each(drop));
        Running { child, addr }
    }

    /// Posts to /add-checkpoint and returns the status code and body.
    fn add(&self, body: &str) -> (u16, String) {
        let mut stream = std::net::TcpStream::connect(&self.addr).unwrap();
        write!(
            stream,
            "POST /add-checkpoint HTTP/1.1\r\nhost: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            self.addr,
            body.len()
        )
        .unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        let status = reply[9..12].parse().unwrap();
        let body = reply.split_once("\r\n\r\n").unwrap().1.to_string();
        (status, body)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Witness B's state file has the name witness A once used for its lock file. B's saves must not
/// let a second process with A's exact key and state start while A runs.
#[test]
fn another_witness_saving_next_to_the_state_cannot_free_its_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (key_a, key_b) = (dir.path().join("a.key"), dir.path().join("b.key"));
    write_key(&key_a, 0xa);
    write_key(&key_b, 0xb);
    let state_a = dir.path().join("state.json");
    let state_b = dir.path().join("state.json.lock");
    let log = Log::new();

    let b = Running::start(&key_b, &state_b, &log);
    assert_eq!(b.add(&log.add(0, 1)).0, 200);
    let a = Running::start(&key_a, &state_a, &log);
    assert_eq!(a.add(&log.add(0, 1)).0, 200);

    for size in 2..6 {
        let (status, body) = b.add(&log.add(size - 1, size));
        assert_eq!(status, 200, "B saves size {size}: {body}");
        let err = refused(command(&key_a, &state_a, &log.key.vkey()).spawn().unwrap());
        assert!(
            err.contains("another witness process"),
            "after B saved size {size}: {err}"
        );
        let (status, body) = a.add(&log.add(size - 1, size));
        assert_eq!(status, 200, "A saves size {size}: {body}");
    }
}

/// A state file can never take the name of another state file's lock, in either start order.
#[test]
fn a_state_path_cannot_be_another_states_lock() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("witness.key");
    write_key(&key, 5);
    let log = Log::new();
    let state = dir.path().join("state.json");
    let lock = lock_of(&state);

    let err = refused(command(&key, &lock, &log.key.vkey()).spawn().unwrap());
    assert!(err.contains("reserved"), "alone: {err}");
    let running = Running::start(&key, &state, &log);
    assert_eq!(running.add(&log.add(0, 1)).0, 200);
    let err = refused(command(&key, &lock, &log.key.vkey()).spawn().unwrap());
    assert!(err.contains("reserved"), "next to a running witness: {err}");
}

/// A regular file where the lock directory belongs is a conflicting configuration, not a lock.
#[test]
fn a_file_in_place_of_the_lock_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("witness.key");
    write_key(&key, 5);
    let state = dir.path().join("state.json");
    std::fs::write(lock_of(&state), "someone else's file").unwrap();
    let err = refused(command(&key, &state, "").spawn().unwrap());
    assert!(err.contains("not a directory"), "{err}");
}

/// If the lock is replaced under a running witness, it no longer knows it is alone: it must stop
/// cosigning rather than sign next to a second process.
#[test]
fn a_witness_whose_lock_was_replaced_cosigns_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("witness.key");
    write_key(&key, 5);
    let log = Log::new();
    let state = dir.path().join("state.json");
    let running = Running::start(&key, &state, &log);
    assert_eq!(running.add(&log.add(0, 1)).0, 200);
    let stored = std::fs::read(&state).unwrap();

    let other = dir.path().join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::rename(&other, lock_of(&state)).unwrap();

    let (status, body) = running.add(&log.add(1, 2));
    assert_eq!(status, 500, "{body}");
    assert!(!body.contains("witness.example.org/test"), "{body}");
    assert_eq!(std::fs::read(&state).unwrap(), stored, "state unchanged");
}

/// R4-H1: a second name for the state file must not get a second lock. Both processes would load
/// one history and then sign two.
#[test]
fn a_symlink_or_hard_link_to_a_held_state_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("witness.key");
    write_key(&key, 5);
    let log = Log::new();
    let state = dir.path().join("state.json");
    let running = Running::start(&key, &state, &log);
    assert_eq!(running.add(&log.add(0, 1)).0, 200);

    let symlink = dir.path().join("symlink.json");
    std::os::unix::fs::symlink(&state, &symlink).unwrap();
    let err = refused(command(&key, &symlink, &log.key.vkey()).spawn().unwrap());
    assert!(err.contains("symlink"), "symlink: {err}");

    let hard_link = dir.path().join("hard-link.json");
    std::fs::hard_link(&state, &hard_link).unwrap();
    let err = refused(command(&key, &hard_link, &log.key.vkey()).spawn().unwrap());
    assert!(err.contains("links"), "hard link: {err}");
}

/// R4-H1: a hard link made while the witness runs would become a stale copy at the next save, and
/// a second process could start on it. The witness stops saving instead.
#[test]
fn a_witness_whose_state_gained_a_hard_link_cosigns_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("witness.key");
    write_key(&key, 5);
    let log = Log::new();
    let state = dir.path().join("state.json");
    let running = Running::start(&key, &state, &log);
    assert_eq!(running.add(&log.add(0, 1)).0, 200);
    let stored = std::fs::read(&state).unwrap();

    std::fs::hard_link(&state, dir.path().join("hard-link.json")).unwrap();
    let (status, body) = running.add(&log.add(1, 2));
    assert_eq!(status, 500, "{body}");
    assert_eq!(std::fs::read(&state).unwrap(), stored, "state unchanged");
}

/// R4-H1: a witness that finds a different file under its state name, for example one another
/// process saved, must not overwrite it.
#[test]
fn a_witness_whose_state_was_replaced_cosigns_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("witness.key");
    write_key(&key, 5);
    let log = Log::new();
    let state = dir.path().join("state.json");
    let running = Running::start(&key, &state, &log);
    assert_eq!(running.add(&log.add(0, 1)).0, 200);

    let other = dir.path().join("other.json");
    std::fs::copy(&state, &other).unwrap();
    std::fs::rename(&other, &state).unwrap();
    let stored = std::fs::read(&state).unwrap();
    let (status, body) = running.add(&log.add(1, 2));
    assert_eq!(status, 500, "{body}");
    assert_eq!(std::fs::read(&state).unwrap(), stored, "state unchanged");
}
