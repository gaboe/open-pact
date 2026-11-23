//! Pushes each checkpoint to the witnesses in WITNESS_URLS with the c2sp.org/tlog-witness
//! add-checkpoint call. One owner task per witness does every push to it: enrolment, claim, reader
//! demand and renewal. So the sizes this process sends to one witness never go down, and a slow
//! witness holds up only its own owner.

use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use open_pact_core::{
    AddCheckpoint, Checkpoint, LogPolicy, Note, NoteSignature, WitnessKey, consistency_proof,
};
use reqwest::StatusCode;
use sqlx::{PgConnection, PgPool};
use tokio::sync::{Notify, mpsc, oneshot, watch};

use crate::hooks::Hooks;
use crate::metrics::{Observation, Push};
use crate::{Enforced, Tree};

/// What the manifest asks of the witnesses, per manifest snapshot.
pub struct Witnesses {
    keys: Vec<WitnessKey>,
    pub quorum: usize,
    last_retry: Mutex<Option<Instant>>,
}

/// How often a request may retry a push that left the checkpoint short of its quorum. A slow
/// witness then delays one request in this interval, not every request.
const RETRY_EVERY: Duration = Duration::from_secs(30);

/// The time one database step of an owner or a reader may take.
pub const STEP_DB: Duration = Duration::from_secs(2);

const PUSH_TIMEOUT: Duration = Duration::from_secs(5);

impl Witnesses {
    pub fn new(policy: Option<&LogPolicy>) -> Witnesses {
        Witnesses {
            keys: policy.map_or(vec![], |p| {
                p.witnesses.iter().map(|w| w.key.clone()).collect()
            }),
            quorum: policy.map_or(0, |p| p.witness_quorum),
            last_retry: Mutex::default(),
        }
    }

    pub fn keys(&self) -> &[WitnessKey] {
        &self.keys
    }

    /// The next `retry_due` is true, as if the interval had passed.
    #[cfg(test)]
    pub fn force_retry(&self) {
        *self.last_retry.lock().expect("witness retry time") = None;
    }

    /// Whether a request may retry pushing now; at most once per RETRY_EVERY.
    pub fn retry_due(&self) -> bool {
        let mut last = self.last_retry.lock().expect("witness retry time");
        let due = last.is_none_or(|t| t.elapsed() >= RETRY_EVERY);
        if due {
            *last = Some(Instant::now());
        }
        due
    }
}

/// The witness URLs without a trailing slash and without repeats, in their first order. A repeated
/// entry would give one witness two owners, two pushes in flight and two floors.
pub fn normalize_urls(urls: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = vec![];
    for url in urls {
        let url = url.trim_end_matches('/').to_string();
        if seen.insert(url.clone()) {
            out.push(url);
        } else {
            eprintln!("WITNESS_URLS lists {url} more than once; one owner serves it");
        }
    }
    out
}

type StepFuture<'c, T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'c>>;

/// Runs `f` as one database step in its own task, which owns the connection: PostgreSQL ends a
/// blocked statement after 2 s, the whole step ends after 2 s, and a connection that did not finish
/// is closed, never returned with a reply pending. Dropping the handle drops no connection.
pub fn db_step<T, F>(pool: PgPool, f: F) -> tokio::task::JoinHandle<anyhow::Result<T>>
where
    T: Send + 'static,
    F: for<'c> FnOnce(&'c mut PgConnection) -> StepFuture<'c, T> + Send + 'static,
{
    tokio::spawn(async move {
        let mut held: Option<sqlx::pool::PoolConnection<sqlx::Postgres>> = None;
        let held_ref = &mut held;
        let done = tokio::time::timeout(STEP_DB, async move {
            let conn = held_ref.insert(pool.acquire().await?);
            sqlx::query("SET statement_timeout = '2s'")
                .execute(&mut **conn)
                .await?;
            let result = f(conn).await;
            sqlx::query("RESET statement_timeout")
                .execute(&mut **conn)
                .await?;
            result
        })
        .await;
        match done {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                if let Some(mut conn) = held {
                    conn.close_on_drop();
                }
                Err(error)
            }
            Err(_) => {
                if let Some(mut conn) = held {
                    conn.close_on_drop();
                }
                Err(anyhow::anyhow!("database step timed out"))
            }
        }
    })
}

/// What an owner knows of its witness; readers look at it and never at the owner's state.
#[derive(Clone, Debug)]
pub struct View {
    pub idle: bool,
    pub cooling: bool,
    pub tried: u64,
    pub failures: u32,
}

/// The answer to one Push job.
#[derive(Debug)]
pub enum Outcome {
    /// The lines of the witness that a key of the job's policy (or a key this process enforced)
    /// verifies.
    Cosigned(Vec<(WitnessKey, NoteSignature)>),
    /// The witness holds, or may hold, a size above the job's.
    Behind {
        floor: u64,
    },
    Failed,
}

pub struct PushJob {
    pub size: u64,
    pub note: Note,
    pub cp: Checkpoint,
    pub tree: Tree,
    pub keys: Arc<[WitnessKey]>,
    pub reply: oneshot::Sender<Outcome>,
}

enum Job {
    Push(PushJob),
    Join(oneshot::Sender<()>),
    Refresh,
    Reload,
}

#[derive(Clone, Debug)]
pub enum WitnessEvent {
    /// Informational: the witness holds a larger size than the push had.
    Ahead {
        url: String,
        witness: u64,
        pushed: u64,
    },
    /// The only fork diagnostic: the witness refused the consistency proof.
    Refused {
        url: String,
        reason: String,
    },
    Failed {
        url: String,
        error: String,
    },
}

struct OwnerHandle {
    jobs: mpsc::UnboundedSender<Job>,
    wake: Arc<Notify>,
    view: watch::Receiver<View>,
}

struct Shared {
    /// Every witness key this process enforced. Filters what an owner stores.
    keys: Mutex<Vec<WitnessKey>>,
    /// Every fan-out of Push or Join to the owners, and every dispatch commit, runs under it.
    ingress: Mutex<()>,
    /// The newest size a reader asked for.
    wanted: AtomicU64,
    current: Arc<RwLock<Arc<Enforced>>>,
    changed: watch::Sender<u64>,
    http: reqwest::Client,
    db: PgPool,
    observe: Option<Arc<Observation>>,
    events: Mutex<Option<mpsc::UnboundedSender<WitnessEvent>>>,
    hooks: Arc<Hooks>,
}

impl Shared {
    fn event(&self, event: WitnessEvent) {
        match &event {
            WitnessEvent::Ahead {
                url,
                witness,
                pushed,
            } => eprintln!(
                "witness {url} holds size {witness}, this push had {pushed}; the next push starts from {witness}"
            ),
            WitnessEvent::Refused { url, reason } => {
                eprintln!("witness {url} refused the consistency proof: {reason}");
            }
            WitnessEvent::Failed { url, error } => {
                eprintln!("witness {url} did not cosign: {error}");
            }
        }
        if let Some(events) = self.events.lock().expect("witness events").as_ref() {
            let _ = events.send(event);
        }
    }

    fn revision(&self) -> u64 {
        self.current.read().expect("manifest snapshot").revision
    }
}

pub struct Owners {
    shared: Arc<Shared>,
    owners: Vec<OwnerHandle>,
    /// Test only: how many Push fan-outs ran.
    #[cfg(test)]
    pub fanouts: std::sync::atomic::AtomicUsize,
}

impl Owners {
    /// Spawns one owner task per URL. `urls` must already be normalized.
    pub fn start(
        urls: Vec<String>,
        keys: Vec<WitnessKey>,
        current: Arc<RwLock<Arc<Enforced>>>,
        db: PgPool,
        observe: Option<Arc<Observation>>,
    ) -> anyhow::Result<Owners> {
        let shared = Arc::new(Shared {
            keys: Mutex::new(keys),
            ingress: Mutex::new(()),
            wanted: AtomicU64::new(0),
            current,
            changed: watch::channel(0).0,
            http: reqwest::Client::builder().timeout(PUSH_TIMEOUT).build()?,
            db,
            observe,
            events: Mutex::default(),
            hooks: Arc::default(),
        });
        let owners = urls
            .into_iter()
            .map(|url| {
                let (jobs, rx) = mpsc::unbounded_channel();
                let wake = Arc::new(Notify::new());
                let (view_tx, view) = watch::channel(View {
                    idle: true,
                    cooling: false,
                    tried: 0,
                    failures: 0,
                });
                let owner = Owner::new(url.clone(), shared.clone(), rx, wake.clone(), view_tx);
                tokio::spawn(owner.run());
                OwnerHandle { jobs, wake, view }
            })
            .collect();
        Ok(Owners {
            shared,
            owners,
            #[cfg(test)]
            fanouts: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    pub fn hooks(&self) -> Arc<Hooks> {
        self.shared.hooks.clone()
    }

    /// Adds the witness keys of a manifest this process starts to enforce.
    pub fn add_keys(&self, keys: &[WitnessKey]) {
        let mut known = self.shared.keys.lock().expect("owner keys");
        for key in keys {
            if !known.contains(key) {
                known.push(key.clone());
            }
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.shared.changed.subscribe()
    }

    pub fn views(&self) -> Vec<View> {
        self.owners
            .iter()
            .map(|o| o.view.borrow().clone())
            .collect()
    }

    #[cfg(test)]
    pub fn events(&self) -> mpsc::UnboundedReceiver<WitnessEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.shared.events.lock().expect("witness events") = Some(tx);
        rx
    }

    /// A reader wants a witnessed note of `size`. Every owner wakes; none is owned by the reader.
    pub fn kick(&self, size: u64) {
        self.shared.wanted.fetch_max(size, Ordering::SeqCst);
        for owner in &self.owners {
            owner.wake.notify_one();
        }
    }

    /// Queues a Push of `cp` at every owner, in one order, and returns the replies.
    pub fn push_all(
        &self,
        cp: &Checkpoint,
        note: &Note,
        tree: &Tree,
        keys: &Arc<[WitnessKey]>,
    ) -> Vec<oneshot::Receiver<Outcome>> {
        let _order = self.shared.ingress.lock().expect("owner ingress");
        #[cfg(test)]
        self.fanouts.fetch_add(1, Ordering::SeqCst);
        self.owners
            .iter()
            .map(|owner| {
                let (reply, rx) = oneshot::channel();
                let _ = owner.jobs.send(Job::Push(PushJob {
                    size: cp.size,
                    note: note.clone(),
                    cp: cp.clone(),
                    tree: tree.clone(),
                    keys: keys.clone(),
                    reply,
                }));
                rx
            })
            .collect()
    }

    /// Waits behind every Push already queued (the base `settled`).
    pub fn join_all(&self) -> Vec<oneshot::Receiver<()>> {
        let _order = self.shared.ingress.lock().expect("owner ingress");
        self.owners
            .iter()
            .map(|owner| {
                let (reply, rx) = oneshot::channel();
                let _ = owner.jobs.send(Job::Join(reply));
                rx
            })
            .collect()
    }

    pub fn refresh_all(&self) {
        for owner in &self.owners {
            let _ = owner.jobs.send(Job::Refresh);
            owner.wake.notify_one();
        }
    }

    /// A manifest reload changed the keys: forget what the owners reuse.
    pub fn reload_all(&self) {
        for owner in &self.owners {
            let _ = owner.jobs.send(Job::Reload);
            owner.wake.notify_one();
        }
    }
}

struct Last {
    size: u64,
    revision: u64,
    lines: Vec<NoteSignature>,
}

/// The one rule that names a witness line: the key that verifies it, and its cosign time.
fn verified<'k>(
    keys: impl IntoIterator<Item = &'k WitnessKey>,
    cp: &Checkpoint,
    line: &NoteSignature,
) -> Option<&'k WitnessKey> {
    keys.into_iter()
        .find(|k| matches!(k.verify(cp, line), Some(Ok(_))))
}

enum Target {
    Push(u64),
    Reader(Tree, Checkpoint, Note),
}

enum Staged {
    Cosigned(Vec<NoteSignature>),
    Behind,
    Failed,
}

struct Attempt {
    /// A 409 named a size above the push: (the witness's size, the pushed size).
    ahead: Option<(u64, u64)>,
    staged: Staged,
    observed: Option<u64>,
    new_held: Option<u64>,
}

struct Owner {
    url: String,
    shared: Arc<Shared>,
    jobs: mpsc::UnboundedReceiver<Job>,
    wake: Arc<Notify>,
    view: watch::Sender<View>,
    /// The size the witness is known to hold.
    held: u64,
    /// The largest size this owner has sent, whatever the outcome.
    sent: u64,
    last: Option<Last>,
    tried: u64,
    failures: u32,
    not_before: Option<Instant>,
    ingress: u64,
    pushes: BTreeMap<(u64, u64), PushJob>,
    joins: Vec<(u64, oneshot::Sender<()>)>,
    refresh: bool,
    recheck: Option<Instant>,
    announced: HashSet<u64>,
}

impl Owner {
    fn new(
        url: String,
        shared: Arc<Shared>,
        jobs: mpsc::UnboundedReceiver<Job>,
        wake: Arc<Notify>,
        view: watch::Sender<View>,
    ) -> Owner {
        Owner {
            url,
            shared,
            jobs,
            wake,
            view,
            held: 0,
            sent: 0,
            last: None,
            tried: 0,
            failures: 0,
            not_before: None,
            ingress: 0,
            pushes: BTreeMap::new(),
            joins: vec![],
            refresh: false,
            recheck: None,
            announced: HashSet::new(),
        }
    }

    fn floor(&self) -> u64 {
        self.held.max(self.sent)
    }

    fn accept(&mut self, job: Job) {
        let n = self.ingress;
        self.ingress += 1;
        match job {
            Job::Push(push) => {
                self.pushes.insert((push.size, n), push);
            }
            Job::Join(reply) => self.joins.push((n, reply)),
            Job::Refresh => {
                self.refresh = true;
                self.recheck = None;
            }
            // held and sent are facts about the witness and the wire; they stay.
            Job::Reload => {
                self.shared.hooks.bump("reload_drained");
                self.last = None;
                self.tried = 0;
                self.failures = 0;
                self.not_before = None;
                self.recheck = None;
            }
        }
    }

    fn drain(&mut self) {
        while let Ok(job) = self.jobs.try_recv() {
            self.accept(job);
        }
    }

    fn publish(&self, idle: bool) {
        let cooling = self.not_before.is_some_and(|t| t > Instant::now());
        self.view.send_replace(View {
            idle,
            cooling,
            tried: self.tried,
            failures: self.failures,
        });
    }

    fn due(&self) -> bool {
        self.refresh
            || self.shared.wanted.load(Ordering::SeqCst) > self.tried
            || (self.failures > 0 && self.shared.wanted.load(Ordering::SeqCst) >= self.tried)
    }

    fn answer_joins(&mut self) {
        let first = self.pushes.keys().map(|&(_, n)| n).min();
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.joins)
            .into_iter()
            .partition(|(n, _)| first.is_none_or(|f| *n < f));
        self.joins = waiting;
        for (_, reply) in ready {
            let _ = reply.send(());
        }
    }

    async fn run(mut self) {
        loop {
            let now = Instant::now();
            if self.not_before.is_some_and(|t| t <= now) {
                self.not_before = None;
            }
            if self.recheck.is_some_and(|t| t <= now) {
                self.recheck = None;
            }
            self.drain();
            self.answer_joins();
            if self.rule_one().await {
                continue;
            }
            if self.not_before.is_none()
                && self.recheck.is_none()
                && self.due()
                && self.rule_two(now).await
            {
                continue;
            }
            self.answer_joins();
            self.publish(self.pushes.is_empty());
            let timer = if self.due() {
                [self.not_before, self.recheck].into_iter().flatten().min()
            } else {
                None
            };
            let wake = self.wake.clone();
            let job = tokio::select! {
                job = self.jobs.recv() => Some(job),
                () = wake.notified() => None,
                () = async {
                    match timer {
                        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                        None => std::future::pending().await,
                    }
                } => None,
            };
            match job {
                Some(Some(job)) => self.accept(job),
                Some(None) => return,
                None => {}
            }
        }
    }

    /// Rule 1: a queued Push. Returns whether it did something.
    async fn rule_one(&mut self) -> bool {
        let Some(&(s, _)) = self.pushes.keys().next() else {
            return false;
        };
        if s < self.floor() {
            let floor = self.floor();
            for key in self.keys_at(s) {
                if let Some(push) = self.pushes.remove(&key) {
                    let _ = push.reply.send(Outcome::Behind { floor });
                }
            }
            return true;
        }
        let revision = self.shared.revision();
        let reusable = self.last.as_ref().is_some_and(|last| {
            last.size == s
                && last.revision == revision
                && self.keys_at(s).iter().all(|key| {
                    let push = &self.pushes[key];
                    last.lines
                        .iter()
                        .any(|l| verified(push.keys.iter(), &push.cp, l).is_some())
                })
        });
        if reusable {
            let lines = self
                .last
                .as_ref()
                .map(|l| l.lines.clone())
                .unwrap_or_default();
            let known = self.shared.keys.lock().expect("owner keys").clone();
            for key in self.keys_at(s) {
                if let Some(push) = self.pushes.remove(&key) {
                    let accepted = accepted_lines(&known, &push.keys, &push.cp, &lines);
                    let _ = push.reply.send(Outcome::Cosigned(accepted));
                }
            }
            return true;
        }
        self.attempt(Target::Push(s)).await;
        true
    }

    fn keys_at(&self, s: u64) -> Vec<(u64, u64)> {
        self.pushes
            .range((s, 0)..=(s, u64::MAX))
            .map(|(k, _)| *k)
            .collect()
    }

    /// Rule 2: reader demand, renewal or a retry. Returns whether it did something.
    async fn rule_two(&mut self, now: Instant) -> bool {
        let snap = self
            .shared
            .current
            .read()
            .expect("manifest snapshot")
            .clone();
        self.publish(false);
        let tree = crate::tree_step(
            self.shared.db.clone(),
            snap.clone(),
            crate::TreeSql::Step,
            self.shared.hooks.clone(),
        )
        .await;
        let tree = match tree {
            Ok(Ok(tree)) => tree,
            failed => {
                let error = match failed {
                    Ok(Err(error)) => error,
                    Err(error) => anyhow::Error::from(error),
                    Ok(Ok(_)) => unreachable!("handled above"),
                };
                eprintln!("witness {}: the tree read failed: {error:#}", self.url);
                let done = Instant::now();
                if self.shared.revision() == snap.revision {
                    self.failures += 1;
                    self.not_before = Some(done + backoff(self.failures));
                }
                self.publish(self.pushes.is_empty());
                self.shared.changed.send_modify(|n| *n += 1);
                return true;
            }
        };
        self.shared.hooks.hit("owner_tree_captured").await;
        self.drain();
        if !self.pushes.is_empty() {
            return true;
        }
        let matches_last = self.last.as_ref().is_some_and(|l| {
            l.size == tree.size()
                && l.revision == tree.revision
                && self.failures == 0
                && !self.refresh
        });
        if tree.size() < self.floor() || matches_last {
            self.refresh = false;
            self.tried = self.tried.max(tree.size());
            self.recheck = Some(now + Duration::from_secs(1));
            self.publish(self.pushes.is_empty());
            return true;
        }
        let cp = Checkpoint {
            origin: snap.log.key.origin().to_string(),
            size: tree.size(),
            root: tree.root(),
        };
        let note = snap.log.key.sign(&snap.log.signer, &cp);
        self.attempt(Target::Reader(tree, cp, note)).await;
        true
    }

    /// The only caller of `send_push`, so the only code that sends add-checkpoint.
    async fn attempt(&mut self, target: Target) {
        self.publish(false);
        let (s, cp, note, tree, reader) = match &target {
            Target::Push(s) => {
                let lead = self
                    .pushes
                    .range((*s, 0)..=(*s, u64::MAX))
                    .next()
                    .map(|(_, p)| p)
                    .expect("rule 1 queued a push at this size");
                (
                    *s,
                    lead.cp.clone(),
                    lead.note.clone(),
                    lead.tree.clone(),
                    false,
                )
            }
            Target::Reader(tree, cp, note) => {
                (cp.size, cp.clone(), note.clone(), tree.clone(), true)
            }
        };
        let shared = self.shared.clone();
        let tree_rev = tree.revision;
        shared.hooks.hit("dispatch_commit_entered").await;
        // The dispatch commit: the order point between a Push and a reader or renewal send.
        let abandon = {
            let _order = shared.ingress.lock().expect("owner ingress");
            self.drain();
            let floor = self.floor();
            let abandon = if reader {
                !self.pushes.is_empty()
            } else {
                self.pushes
                    .keys()
                    .any(|&(size, _)| (floor..s).contains(&size))
            };
            if !abandon {
                self.sent = self.sent.max(s);
                if reader {
                    self.refresh = false;
                }
            }
            abandon
        };
        if abandon {
            self.publish(self.pushes.is_empty());
            return;
        }
        shared.hooks.hit("dispatch_committed").await;
        // Keys that may verify the answer: every key this process enforced and the keys of every Push at s.
        let mut keys = shared.keys.lock().expect("owner keys").clone();
        if !reader {
            for key in self.keys_at(s) {
                keys.extend(self.pushes[&key].keys.iter().cloned());
            }
        }
        let old = if self.held > s { 0 } else { self.held };
        let url = self.url.clone();
        let task = tokio::spawn(push_with_retry(
            shared.clone(),
            url,
            note,
            cp.clone(),
            tree,
            old,
            keys.clone(),
        ));
        let attempt = task.await.unwrap_or_else(|error| {
            eprintln!("witness {}: the push task failed: {error}", self.url);
            Attempt {
                ahead: None,
                staged: Staged::Failed,
                observed: None,
                new_held: None,
            }
        });
        if let Some(held) = attempt.new_held.or(attempt.observed) {
            self.held = held;
        }
        if let Some((witness, pushed)) = attempt.ahead
            && self.announced.insert(witness)
        {
            self.shared.event(WitnessEvent::Ahead {
                url: self.url.clone(),
                witness,
                pushed,
            });
        }
        let mut staged = attempt.staged;
        // Answer the Pushes at s before the store: a claim writes its own lines with base limits.
        if !reader {
            self.answer_pushes(s, &staged, &keys);
        }
        if let Staged::Cosigned(lines) = &staged {
            let stored = self.store(&cp, &keys, lines).await;
            if !stored {
                staged = Staged::Failed;
            }
        }
        let done = Instant::now();
        if self.shared.revision() == tree_rev {
            self.tried = self.tried.max(s);
            match staged {
                Staged::Cosigned(lines) => {
                    self.last = Some(Last {
                        size: s,
                        revision: self.shared.revision(),
                        lines,
                    });
                    self.failures = 0;
                    self.not_before = None;
                }
                Staged::Failed => {
                    self.failures += 1;
                    self.not_before = Some(done + backoff(self.failures));
                }
                Staged::Behind => {}
            }
        }
        self.publish(self.pushes.is_empty());
        self.shared.changed.send_modify(|n| *n += 1);
    }

    fn answer_pushes(&mut self, s: u64, staged: &Staged, keys: &[WitnessKey]) {
        let queued = self.keys_at(s);
        let Some(&lead) = queued.first() else { return };
        match staged {
            Staged::Cosigned(raw) => {
                for key in queued {
                    let own = &self.pushes[&key].keys;
                    let matched = raw
                        .iter()
                        .any(|l| verified(own.iter(), &self.pushes[&key].cp, l).is_some());
                    if key == lead || matched {
                        let push = self.pushes.remove(&key).expect("queued");
                        let accepted = accepted_lines(keys, &push.keys, &push.cp, raw);
                        let _ = push.reply.send(Outcome::Cosigned(accepted));
                    }
                }
            }
            Staged::Failed => {
                if let Some(push) = self.pushes.remove(&lead) {
                    let _ = push.reply.send(Outcome::Failed);
                }
            }
            Staged::Behind => {
                let floor = self.floor();
                for key in queued {
                    let push = self.pushes.remove(&key).expect("queued");
                    let _ = push.reply.send(Outcome::Behind { floor });
                }
            }
        }
    }

    /// One upsert of every line a key verifies, under the full key identity.
    async fn store(&self, cp: &Checkpoint, keys: &[WitnessKey], lines: &[NoteSignature]) -> bool {
        // The table holds no checkpoint of an empty log (CHECK size > 0).
        if cp.size == 0 {
            return true;
        }
        let rows: Vec<(String, String)> = lines
            .iter()
            .filter_map(|l| verified(keys.iter(), cp, l).map(|k| (k.vkey(), l.to_string())))
            .collect();
        let (size, root) = (
            i64::try_from(cp.size).unwrap_or(i64::MAX),
            cp.root.to_string(),
        );
        let stored = db_step(self.shared.db.clone(), move |conn| {
            Box::pin(async move {
                for (witness, line) in rows {
                    sqlx::query(UPSERT)
                        .bind(size)
                        .bind(&root)
                        .bind(witness)
                        .bind(line.trim_end())
                        .execute(&mut *conn)
                        .await?;
                }
                Ok(())
            })
        })
        .await;
        match stored {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                eprintln!(
                    "witness {}: storing the cosignature failed: {error:#}",
                    self.url
                );
                false
            }
            Err(error) => {
                eprintln!("witness {}: the store task failed: {error}", self.url);
                false
            }
        }
    }
}

pub const UPSERT: &str = "INSERT INTO log_cosignatures (size, root, witness, signature) VALUES ($1, $2, $3, $4) \
     ON CONFLICT (size, root, witness) DO UPDATE SET signature = EXCLUDED.signature, received_at = now()";

/// 1 s, 2 s, 4 s ... at most 30 s.
fn backoff(failures: u32) -> Duration {
    Duration::from_secs(1u64 << failures.saturating_sub(1).min(5)).min(Duration::from_secs(30))
}

/// The raw lines that a key in `known` or `own` verifies, with that key.
fn accepted_lines(
    known: &[WitnessKey],
    own: &[WitnessKey],
    cp: &Checkpoint,
    raw: &[NoteSignature],
) -> Vec<(WitnessKey, NoteSignature)> {
    raw.iter()
        .filter_map(|l| {
            verified(known.iter().chain(own.iter()), cp, l).map(|k| (k.clone(), l.clone()))
        })
        .collect()
}

/// Sends once, and once more from the size a 409 names. Runs in its own task so a panic is a
/// failed attempt and the owner loop survives.
async fn push_with_retry(
    shared: Arc<Shared>,
    url: String,
    note: Note,
    cp: Checkpoint,
    tree: Tree,
    mut old: u64,
    keys: Vec<WitnessKey>,
) -> Attempt {
    let mut observed = None;
    for round in 0..2 {
        let started = shared
            .observe
            .as_ref()
            .and_then(|o| o.metrics())
            .map(|_| crate::metrics::now());
        let pushed = send_push(&shared.http, &url, &note, &cp, &tree, old, &shared.hooks).await;
        let elapsed = started.map(|started| started.elapsed().as_secs_f64());
        let verifies = match &pushed {
            Ok(Pushed::Cosigned(lines)) => lines
                .iter()
                .any(|l| verified(keys.iter(), &cp, l).is_some()),
            _ => false,
        };
        if let (Some(metrics), Some(elapsed)) =
            (shared.observe.as_ref().and_then(|o| o.metrics()), elapsed)
        {
            metrics.witness_push(push_result(&pushed, verifies), elapsed);
        }
        match pushed {
            Ok(Pushed::Cosigned(lines)) if verifies => {
                return Attempt {
                    ahead: None,
                    staged: Staged::Cosigned(lines),
                    observed,
                    new_held: Some(cp.size),
                };
            }
            Ok(Pushed::Cosigned(_)) => {
                shared.event(WitnessEvent::Failed {
                    url: url.clone(),
                    error: "answered without a cosignature from a manifest witness key".into(),
                });
                return Attempt {
                    ahead: None,
                    staged: Staged::Failed,
                    observed,
                    new_held: Some(cp.size),
                };
            }
            Ok(Pushed::Conflict(size)) if size <= cp.size && size != old && round == 0 => {
                observed = Some(size);
                old = size;
            }
            Ok(Pushed::Conflict(size)) if size > cp.size => {
                return Attempt {
                    ahead: Some((size, cp.size)),
                    staged: Staged::Behind,
                    observed,
                    new_held: Some(size),
                };
            }
            Ok(Pushed::Conflict(size)) => {
                shared.event(WitnessEvent::Failed {
                    url: url.clone(),
                    error: format!(
                        "answered 409 with size {size} to a push of size {}",
                        cp.size
                    ),
                });
                return Attempt {
                    ahead: None,
                    staged: Staged::Failed,
                    observed: observed.or(Some(size)),
                    new_held: None,
                };
            }
            Ok(Pushed::Refused(reason)) => {
                shared.event(WitnessEvent::Refused {
                    url: url.clone(),
                    reason,
                });
                return Attempt {
                    ahead: None,
                    staged: Staged::Failed,
                    observed,
                    new_held: None,
                };
            }
            Err(error) => {
                shared.event(WitnessEvent::Failed {
                    url: url.clone(),
                    error: format!("size {}: {error:#}", cp.size),
                });
                return Attempt {
                    ahead: None,
                    staged: Staged::Failed,
                    observed,
                    new_held: None,
                };
            }
        }
    }
    Attempt {
        ahead: None,
        staged: Staged::Failed,
        observed,
        new_held: None,
    }
}

/// The only place that sends add-checkpoint. The consistency proof is built on the blocking pool.
async fn send_push(
    http: &reqwest::Client,
    url: &str,
    note: &Note,
    cp: &Checkpoint,
    tree: &Tree,
    old: u64,
    hooks: &Arc<Hooks>,
) -> anyhow::Result<Pushed> {
    let old = if old > cp.size { 0 } else { old };
    let proof = if old == 0 || old == cp.size {
        vec![]
    } else {
        let (tree, size, hooks) = (tree.clone(), cp.size, hooks.clone());
        tokio::task::spawn_blocking(move || {
            hooks.block("push_proof");
            consistency_proof(tree.prefix(size), old)
        })
        .await??
    };
    let body = AddCheckpoint {
        old_size: old,
        proof,
        note: note.clone(),
    };
    let resp = http
        .post(format!("{url}/add-checkpoint"))
        .body(body.to_string())
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    match status {
        StatusCode::OK => Ok(Pushed::Cosigned(
            text.lines()
                .map(NoteSignature::parse)
                .collect::<Result<_, _>>()?,
        )),
        StatusCode::CONFLICT => Ok(Pushed::Conflict(text.trim().parse()?)),
        StatusCode::UNPROCESSABLE_ENTITY => Ok(Pushed::Refused(text.trim().to_string())),
        _ => anyhow::bail!("{status}: {}", text.trim()),
    }
}

enum Pushed {
    Cosigned(Vec<NoteSignature>),
    Conflict(u64),
    /// 422: the witness rejected the consistency proof.
    Refused(String),
}

fn push_result(pushed: &anyhow::Result<Pushed>, verified: bool) -> Push {
    match pushed {
        Ok(Pushed::Cosigned(_)) if verified => Push::Cosigned,
        Ok(Pushed::Cosigned(_)) => Push::Invalid,
        Ok(Pushed::Conflict(_)) => Push::Conflict,
        Ok(Pushed::Refused(_)) => Push::Refused,
        Err(e)
            if e.downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout) =>
        {
            Push::Timeout
        }
        Err(_) => Push::Error,
    }
}
