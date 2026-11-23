//! A fake witness for the gateway tests. It runs the core add-checkpoint rules with an in-memory
//! "latest" map and a real witness key, so its 200, 409 and 422 answers are the real witness's.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{Router, extract::State, http::StatusCode, routing::post};
use open_pact_core::{AddCheckpoint, Checkpoint, LogKey, Refusal, WitnessKey, add_checkpoint};
use tokio::sync::Notify;

pub const DEMO_NAME: &str = "witness.example.org/demo";

/// What the fake does with a push.
#[derive(Clone, Debug)]
pub enum Behaviour {
    Healthy,
    /// Answers this status at once and stores nothing.
    Answer(u16),
    /// Sleeps this long before it answers, then decides as a healthy witness.
    Delay(Duration),
    /// Decides and stores, then drops the answer (a 500).
    StoreThenFail,
    /// Sleeps, then answers this status and stores nothing.
    DelayAnswer(Duration, u16),
}

#[derive(Clone, Debug)]
pub struct Received {
    pub size: u64,
    pub old_size: u64,
    pub status: u16,
    /// When the push arrived, and when the witness answered.
    pub arrived: Instant,
    pub at: Instant,
}

pub struct Inner {
    signer: ed25519_dalek::SigningKey,
    pub key: WitnessKey,
    logs: Mutex<Vec<LogKey>>,
    latest: Mutex<BTreeMap<String, Checkpoint>>,
    behaviour: Mutex<Behaviour>,
    received: Mutex<Vec<Received>>,
    arrivals: std::sync::atomic::AtomicUsize,
    /// A decision gate: while set, a push waits for a permit before it decides.
    gate: Mutex<Option<Arc<Notify>>>,
}

pub struct FakeWitness {
    pub url: String,
    pub inner: Arc<Inner>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for FakeWitness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl FakeWitness {
    /// A witness with the key of the demo manifest (a public seed, fictional).
    pub async fn demo(log: &LogKey) -> FakeWitness {
        let hex = include_str!("../../../deploy/compose/demo-witness.key");
        let mut seed = [0; 32];
        hex::decode_to_slice(hex.trim(), &mut seed).expect("demo witness seed");
        FakeWitness::with_seed(DEMO_NAME, seed, log).await
    }

    pub async fn with_seed(name: &str, seed: [u8; 32], log: &LogKey) -> FakeWitness {
        let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
        let key = WitnessKey::new(name, signer.verifying_key());
        let inner = Arc::new(Inner {
            signer,
            key,
            logs: Mutex::new(vec![log.clone()]),
            latest: Mutex::default(),
            behaviour: Mutex::new(Behaviour::Healthy),
            received: Mutex::default(),
            arrivals: std::sync::atomic::AtomicUsize::new(0),
            gate: Mutex::default(),
        });
        let router = Router::new()
            .route("/add-checkpoint", post(add))
            .with_state(inner.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        FakeWitness { url, inner, server }
    }

    pub fn set(&self, behaviour: Behaviour) {
        *self.inner.behaviour.lock().unwrap() = behaviour;
    }

    /// The next pushes wait at the returned gate until the test adds permits.
    pub fn gate(&self) -> Arc<Notify> {
        let gate = Arc::new(Notify::new());
        *self.inner.gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    /// Removes the gate and lets every push that waits at it decide.
    pub fn open_gate(&self) {
        let gate = self.inner.gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.notify_waiters();
        }
    }

    /// How many pushes arrived, decided or not.
    pub fn arrivals(&self) -> usize {
        self.inner.arrivals.load(Ordering::SeqCst)
    }

    /// A line of this witness for `cp` made at `at`, as if it had cosigned then.
    pub fn cosign(&self, cp: &Checkpoint, at: u64) -> open_pact_core::NoteSignature {
        self.inner.key.cosign(&self.inner.signer, cp, at)
    }

    pub fn received(&self) -> Vec<Received> {
        self.inner.received.lock().unwrap().clone()
    }

    pub fn sizes(&self) -> Vec<u64> {
        self.received().iter().map(|r| r.size).collect()
    }

    pub fn latest(&self, origin: &str) -> u64 {
        self.inner
            .latest
            .lock()
            .unwrap()
            .get(origin)
            .map_or(0, |c| c.size)
    }

    /// Sets the size the witness holds, as if another gateway had advanced it.
    pub fn hold(&self, cp: Checkpoint) {
        self.inner
            .latest
            .lock()
            .unwrap()
            .insert(cp.origin.clone(), cp);
    }
}

async fn add(State(w): State<Arc<Inner>>, body: String) -> (StatusCode, String) {
    let Ok(req) = AddCheckpoint::parse(&body) else {
        return (StatusCode::BAD_REQUEST, "bad body".into());
    };
    let size = Checkpoint::parse(&req.note.text).map_or(0, |c| c.size);
    let arrived = Instant::now();
    w.arrivals.fetch_add(1, Ordering::SeqCst);
    let record = |status: u16| {
        w.received.lock().unwrap().push(Received {
            size,
            old_size: req.old_size,
            status,
            arrived,
            at: Instant::now(),
        });
    };
    let behaviour = w.behaviour.lock().unwrap().clone();
    if let Behaviour::Answer(code) = behaviour {
        record(code);
        return (StatusCode::from_u16(code).unwrap(), "fake".into());
    }
    if let Behaviour::DelayAnswer(delay, code) = behaviour {
        tokio::time::sleep(delay).await;
        record(code);
        return (StatusCode::from_u16(code).unwrap(), "fake".into());
    }
    if let Behaviour::Delay(delay) = behaviour {
        tokio::time::sleep(delay).await;
    }
    let gate = w.gate.lock().unwrap().clone();
    if let Some(gate) = gate {
        gate.notified().await;
    }
    let logs = w.logs.lock().unwrap().clone();
    let mut latest = w.latest.lock().unwrap();
    match add_checkpoint(&logs, &latest, &req) {
        Ok(cp) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let line = w.key.cosign(&w.signer, &cp, now);
            latest.insert(cp.origin.clone(), cp);
            if matches!(behaviour, Behaviour::StoreThenFail) {
                record(500);
                return (StatusCode::INTERNAL_SERVER_ERROR, "dropped".into());
            }
            record(200);
            (StatusCode::OK, line.to_string())
        }
        Err(refusal) => {
            record(refusal.status());
            let body = match &refusal {
                Refusal::Conflict(size) => size.to_string(),
                other => other.to_string(),
            };
            (StatusCode::from_u16(refusal.status()).unwrap(), body)
        }
    }
}
