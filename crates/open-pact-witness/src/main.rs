//! A c2sp.org/tlog-witness witness. It keeps the latest checkpoint it cosigned for each log and
//! cosigns a new one only if a consistency proof shows that it extends that one, so the gateway
//! cannot show one history to some clients and another to the rest.
//!
//! Run it under a different operator than the gateway: a witness the gateway operator controls
//! detects nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use open_pact_core::{AddCheckpoint, Checkpoint, LogKey, Refusal, WitnessKey, add_checkpoint};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

const USAGE: &str = "usage: open-pact-witness [serve | keygen | vkey]

Environment:
  WITNESS_NAME         key name, for example witness.example.org/w1 (required)
  WITNESS_KEY_FILE     Ed25519 seed as 64 hex digits; keygen creates it (required)
  WITNESS_STATE        state file (default witness-state.json)
  WITNESS_LOG_KEYS     comma-separated verifier keys of the logs to witness
  WITNESS_LOG_KEY_URL  demo only: pin the key this URL serves on first start
  LISTEN_ADDR          default 0.0.0.0:8080";

/// What the witness must never forget. Losing it lets the gateway roll a log back.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    /// Log keys pinned from WITNESS_LOG_KEY_URL.
    #[serde(default)]
    pinned_log_keys: Vec<String>,
    /// The latest cosigned checkpoint body per origin.
    #[serde(default)]
    checkpoints: BTreeMap<String, String>,
}

struct Memory {
    pinned: Vec<LogKey>,
    latest: BTreeMap<String, Checkpoint>,
}

impl Memory {
    fn load(state: &StateFile) -> anyhow::Result<Memory> {
        let path = &state.path;
        let stored: Stored = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Stored::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Memory {
            pinned: stored
                .pinned_log_keys
                .iter()
                .map(|k| LogKey::parse(k))
                .collect::<Result<_, _>>()?,
            latest: stored
                .checkpoints
                .into_iter()
                .map(|(origin, body)| Ok((origin, Checkpoint::parse(&body)?)))
                .collect::<Result<_, open_pact_core::Error>>()?,
        })
    }

    /// Writes a new temporary file, syncs it and renames it over the state file. Checks before
    /// and after that this process still holds the lock: a lock replaced after the rename can
    /// never come back, so a match afterwards proves no other process loaded the state meanwhile.
    fn save(&self, state: &StateFile) -> anyhow::Result<()> {
        state.check_lock()?;
        let path = &state.path;
        let stored = Stored {
            pinned_log_keys: self.pinned.iter().map(LogKey::vkey).collect(),
            checkpoints: self
                .latest
                .iter()
                .map(|(o, c)| (o.clone(), c.body()))
                .collect(),
        };
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            hex::encode(rand::random::<[u8; 8]>())
        ));
        let tmp = PathBuf::from(tmp);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        let written = serde_json::to_writer_pretty(&file, &stored)
            .map_err(anyhow::Error::from)
            .and_then(|()| Ok(file.sync_all()?))
            .and_then(|()| Ok(std::fs::rename(&tmp, path)?));
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written?;
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
        std::fs::File::open(dir.unwrap_or(Path::new(".")))?.sync_all()?;
        state.check_lock()
    }
}

/// Names `<state>.lockdir`. It is a directory: saves rename files, and a file cannot be renamed
/// over a directory, so no witness's save can replace another's lock.
const LOCK_SUFFIX: &str = ".lockdir";

/// The state file and the lock that keeps other processes off it for as long as the witness
/// runs. Two processes with one state could each cosign a different history.
struct StateFile {
    path: PathBuf,
    lock_path: PathBuf,
    lock: std::fs::File,
}

impl StateFile {
    fn open(path: PathBuf) -> anyhow::Result<StateFile> {
        if path.as_os_str().to_string_lossy().ends_with(LOCK_SUFFIX) {
            bail!(
                "{}: names ending in {LOCK_SUFFIX} are reserved for the lock of another state file",
                path.display()
            );
        }
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(LOCK_SUFFIX);
        let lock_path = PathBuf::from(lock_path);
        match std::fs::create_dir(&lock_path) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
                return Err(e).context(lock_path.display().to_string());
            }
            _ => {}
        }
        let lock = std::fs::File::open(&lock_path).context(lock_path.display().to_string())?;
        if !lock.metadata()?.is_dir() {
            bail!(
                "{} is not a directory; another program uses the lock name of {}",
                lock_path.display(),
                path.display()
            );
        }
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => bail!(
                "another witness process holds {}; run one process per state file",
                lock_path.display()
            ),
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(e).context(lock_path.display().to_string());
            }
        }
        let state = StateFile {
            path,
            lock_path,
            lock,
        };
        state.check_lock()?;
        Ok(state)
    }

    /// Fails unless the lock path still names the directory this process locked.
    fn check_lock(&self) -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let held = self.lock.metadata()?;
        let named = std::fs::symlink_metadata(&self.lock_path)
            .with_context(|| self.lock_path.display().to_string())?;
        if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
            bail!(
                "{} was replaced: another witness process may hold this state",
                self.lock_path.display()
            );
        }
        Ok(())
    }
}

struct Witness {
    signer: ed25519_dalek::SigningKey,
    key: WitnessKey,
    logs: Vec<LogKey>,
    /// WITNESS_LOG_KEY_URL is set: not ready until that key is pinned.
    pins_log_key: bool,
    state: StateFile,
    /// Held from the old-size check until the new checkpoint is on disk.
    memory: Mutex<Memory>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

fn text(status: StatusCode, body: String) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn add(State(w): State<Arc<Witness>>, body: String) -> Response {
    let req = match AddCheckpoint::parse(&body) {
        Ok(req) => req,
        Err(e) => return text(StatusCode::BAD_REQUEST, format!("{e}\n")),
    };
    let mut memory = w.memory.lock().await;
    let logs: Vec<LogKey> = w.logs.iter().chain(&memory.pinned).cloned().collect();
    match add_checkpoint(&logs, &memory.latest, &req) {
        Ok(cp) => {
            let previous = memory.latest.insert(cp.origin.clone(), cp.clone());
            if let Err(e) = memory.save(&w.state) {
                match previous {
                    Some(p) => memory.latest.insert(cp.origin.clone(), p),
                    None => memory.latest.remove(&cp.origin),
                };
                eprintln!("cannot store {}: {e:#}", w.state.path.display());
                return text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "state not stored\n".into(),
                );
            }
            text(
                StatusCode::OK,
                w.key.cosign(&w.signer, &cp, now()).to_string(),
            )
        }
        Err(Refusal::Conflict(size)) => (
            StatusCode::CONFLICT,
            [(header::CONTENT_TYPE, "text/x.tlog.size")],
            format!("{size}\n"),
        )
            .into_response(),
        Err(refusal) => {
            eprintln!("refused: {refusal}");
            let status = StatusCode::from_u16(refusal.status()).expect("tlog-witness status");
            text(status, format!("{refusal}\n"))
        }
    }
}

async fn healthz(State(w): State<Arc<Witness>>) -> Response {
    let pinned = !w.memory.lock().await.pinned.is_empty();
    if !pinned && (w.pins_log_key || w.logs.is_empty()) {
        return text(StatusCode::SERVICE_UNAVAILABLE, "no log key yet\n".into());
    }
    text(StatusCode::OK, "ok\n".into())
}

fn router(w: Arc<Witness>) -> Router {
    Router::new()
        .route("/add-checkpoint", post(add))
        .route("/healthz", get(healthz))
        .with_state(w)
}

/// Demo only: trusts whatever key the URL serves first, then keeps it.
async fn pin_log_key(w: Arc<Witness>, url: String) {
    let http = reqwest::Client::new();
    loop {
        let fetched = async {
            let vkey = http
                .get(&url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            anyhow::Ok(LogKey::parse(vkey.trim())?)
        };
        match fetched.await {
            Ok(key) => {
                let mut memory = w.memory.lock().await;
                memory.pinned.push(key.clone());
                match memory.save(&w.state) {
                    Ok(()) => {
                        eprintln!(
                            "pinned log key {} from {url} (demo trust on first use)",
                            key.vkey()
                        );
                        return;
                    }
                    Err(e) => {
                        memory.pinned.pop();
                        eprintln!("cannot store the pinned log key: {e:#}");
                    }
                }
            }
            Err(e) => eprintln!("log key from {url} not available yet: {e:#}"),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn key_name() -> anyhow::Result<String> {
    let name = env("WITNESS_NAME").context("WITNESS_NAME is required")?;
    if name.contains(|c: char| c.is_whitespace() || c == '+') {
        bail!("WITNESS_NAME must not contain spaces or '+': {name:?}");
    }
    Ok(name)
}

fn load_key(path: &Path) -> anyhow::Result<ed25519_dalek::SigningKey> {
    let hex = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    let mut seed = [0; 32];
    hex::decode_to_slice(hex.trim(), &mut seed)
        .with_context(|| format!("{}: expected 64 hex digits", path.display()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn key_file() -> anyhow::Result<PathBuf> {
    env("WITNESS_KEY_FILE")
        .map(PathBuf::from)
        .context("WITNESS_KEY_FILE is required")
}

fn log_keys() -> anyhow::Result<Vec<LogKey>> {
    env("WITNESS_LOG_KEYS")
        .unwrap_or_default()
        .split([',', ' ', '\n'])
        .filter(|k| !k.is_empty())
        .map(|k| LogKey::parse(k).with_context(|| format!("WITNESS_LOG_KEYS: {k}")))
        .collect()
}

async fn serve() -> anyhow::Result<()> {
    let name = key_name()?;
    let signer = load_key(&key_file()?)?;
    let state = StateFile::open(PathBuf::from(
        env("WITNESS_STATE").unwrap_or_else(|| "witness-state.json".into()),
    ))?;
    let memory = Memory::load(&state).with_context(|| state.path.display().to_string())?;
    let pin_url = env("WITNESS_LOG_KEY_URL").filter(|_| memory.pinned.is_empty());
    let witness = Arc::new(Witness {
        pins_log_key: pin_url.is_some(),
        key: WitnessKey::new(&name, signer.verifying_key()),
        signer,
        logs: log_keys()?,
        state,
        memory: Mutex::new(memory),
    });
    eprintln!("witness key {}", witness.key.vkey());
    for log in &witness.logs {
        eprintln!("witnessing {}", log.vkey());
    }
    {
        let memory = witness.memory.lock().await;
        for log in &memory.pinned {
            eprintln!("witnessing {} (pinned)", log.vkey());
        }
        for cp in memory.latest.values() {
            eprintln!("latest cosigned {} size {}", cp.origin, cp.size);
        }
        if let Some(url) = pin_url {
            eprintln!("WITNESS_LOG_KEY_URL is for demos: the first key {url} serves is trusted");
            tokio::spawn(pin_log_key(witness.clone(), url));
        }
    }
    let addr = env("LISTEN_ADDR").unwrap_or_else(|| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router(witness))
        .with_graceful_shutdown(async {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            tokio::select! {
                _ = term.recv() => {},
                _ = tokio::signal::ctrl_c() => {},
            }
        })
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        None | Some("serve") => serve().await,
        Some("keygen") => {
            let path = key_file()?;
            let seed: [u8; 32] = rand::random();
            open_pact_core::dev_key::write_new(
                &path,
                format!("{}\n", hex::encode(seed)).as_bytes(),
            )?;
            let key = WitnessKey::new(&key_name()?, load_key(&path)?.verifying_key());
            println!("{}", key.vkey());
            Ok(())
        }
        Some("vkey") => {
            let key = WitnessKey::new(&key_name()?, load_key(&key_file()?)?.verifying_key());
            println!("{}", key.vkey());
            Ok(())
        }
        Some(_) => bail!("{USAGE}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use open_pact_core::{
        LogHash, NoteSignature, PublicKey, consistency_proof, dev_key, leaf_hash, root,
    };

    const ORIGIN: &str = "pact.example.com/log";

    struct Log {
        signer: open_pact_core::SigningKey,
        key: LogKey,
        leaves: Vec<LogHash>,
    }

    impl Log {
        fn new() -> Log {
            let signer = dev_key::generate();
            Log {
                key: LogKey::new(ORIGIN, &PublicKey::from(&signer)),
                signer,
                leaves: (0u8..8).map(|i| leaf_hash(&[i])).collect(),
            }
        }

        fn body(&self, old: u64, size: u64, fork: bool) -> String {
            let leaves = &self.leaves[..size as usize];
            let cp = Checkpoint {
                origin: ORIGIN.into(),
                size,
                root: if fork { LogHash([1; 32]) } else { root(leaves) },
            };
            let proof = if old == 0 || old >= size {
                vec![]
            } else {
                consistency_proof(leaves, old).unwrap()
            };
            AddCheckpoint {
                old_size: old,
                proof,
                note: self.key.sign(&self.signer, &cp),
            }
            .to_string()
        }
    }

    struct Running {
        url: String,
        stop: tokio::sync::oneshot::Sender<()>,
        served: tokio::task::JoinHandle<()>,
    }

    impl Running {
        async fn stop(self) {
            self.stop.send(()).unwrap();
            self.served.await.unwrap();
        }
    }

    async fn start(log: &Log, path: &Path) -> anyhow::Result<Running> {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let state = StateFile::open(path.to_path_buf())?;
        let memory = Memory::load(&state)?;
        let witness = Arc::new(Witness {
            key: WitnessKey::new("witness.example.org/test", signer.verifying_key()),
            signer,
            logs: vec![log.key.clone()],
            pins_log_key: false,
            state,
            memory: Mutex::new(memory),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let served = tokio::spawn(async move {
            axum::serve(listener, router(witness))
                .with_graceful_shutdown(async {
                    stopped.await.ok();
                })
                .await
                .unwrap();
        });
        Ok(Running { url, stop, served })
    }

    async fn post(url: &str, body: String) -> (u16, String) {
        let resp = reqwest::Client::new()
            .post(format!("{url}/add-checkpoint"))
            .body(body)
            .send()
            .await
            .unwrap();
        (resp.status().as_u16(), resp.text().await.unwrap())
    }

    #[test]
    fn saving_leaves_other_files_in_the_directory_alone() {
        let dir = tempfile::tempdir().unwrap();
        let neighbour = dir.path().join("state.tmp");
        std::fs::write(&neighbour, "another witness's state").unwrap();
        let state = StateFile::open(dir.path().join("state.json")).unwrap();
        let memory = Memory::load(&state).unwrap();
        memory.save(&state).unwrap();
        memory.save(&state).unwrap();
        assert_eq!(
            std::fs::read_to_string(&neighbour).unwrap(),
            "another witness's state"
        );
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| !n.ends_with(LOCK_SUFFIX))
            .collect();
        names.sort();
        assert_eq!(names, ["state.json", "state.tmp"]);
    }

    #[tokio::test]
    async fn an_empty_checkpoint_does_not_block_later_ones_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let log = Log::new();
        let first = start(&log, &path).await.unwrap();
        assert_eq!(post(&first.url, log.body(0, 0, false)).await.0, 200);
        assert_eq!(
            post(&first.url, log.body(0, 0, false)).await.0,
            200,
            "renewal"
        );
        first.stop().await;

        let restarted = start(&log, &path).await.unwrap();
        assert_eq!(post(&restarted.url, log.body(0, 0, false)).await.0, 200);
        let (status, body) = post(&restarted.url, log.body(0, 1, false)).await;
        assert_eq!(status, 200, "growth: {body}");
        assert_eq!(post(&restarted.url, log.body(1, 3, false)).await.0, 200);
        restarted.stop().await;
    }

    #[tokio::test]
    async fn cosigns_extensions_refuses_forks_and_remembers_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let log = Log::new();
        let first = start(&log, &path).await.unwrap();
        let url = first.url.clone();

        let (status, body) = post(&url, log.body(0, 3, false)).await;
        assert_eq!(status, 200, "{body}");
        let sig = NoteSignature::parse(body.trim_end()).unwrap();
        let witness = WitnessKey::new(
            "witness.example.org/test",
            ed25519_dalek::SigningKey::from_bytes(&[5; 32]).verifying_key(),
        );
        let cp = Checkpoint {
            origin: ORIGIN.into(),
            size: 3,
            root: root(&log.leaves[..3]),
        };
        let at = witness.verify(&cp, &sig).unwrap().unwrap();
        assert!(at.abs_diff(now()) < 60);

        assert_eq!(post(&url, log.body(3, 6, false)).await.0, 200);
        assert_eq!(
            post(&url, log.body(6, 6, true)).await.0,
            422,
            "fork at the same size"
        );
        assert_eq!(
            post(&url, log.body(6, 7, true)).await.0,
            422,
            "fork that grows"
        );
        assert_eq!(post(&url, log.body(6, 5, false)).await.0, 400, "rollback");
        assert_eq!(post(&url, log.body(3, 7, false)).await, (409, "6\n".into()));
        assert_eq!(post(&url, "old 0\n\nnot a note".into()).await.0, 400);

        let err = start(&log, &path)
            .await
            .err()
            .expect("a second witness on one state");
        assert!(err.to_string().contains("another witness process"), "{err}");
        first.stop().await;
        let second = start(&log, &path).await.unwrap();
        let restarted = second.url.clone();
        assert_eq!(
            post(&restarted, log.body(0, 3, false)).await,
            (409, "6\n".into())
        );
        let (status, body) = post(&restarted, log.body(6, 8, false)).await;
        assert_eq!(status, 200, "{body}");
        let stored: Stored = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            Checkpoint::parse(&stored.checkpoints[ORIGIN]).unwrap().size,
            8
        );
        second.stop().await;
    }
}
