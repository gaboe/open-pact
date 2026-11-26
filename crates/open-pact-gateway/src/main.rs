mod claims;
mod diag;
use open_pact_core::{
    AcceptRequest, DeviceAuthPurpose, EntryWithProof, MyEntries, MyEntriesRequest, evaluate_under,
};
use time::OffsetDateTime;
mod devices;
mod grace;
mod hooks;
mod invitations;
mod keys;
mod manifests;
mod metrics;
mod nonces;
mod ratelimit;
mod results;
#[cfg(test)]
mod s1_tests;
mod seal;
mod served;
mod siem;
mod standing;
#[cfg(test)]
mod testdb;
#[cfg(test)]
mod testwitness;
mod translog;
mod witness;

use std::collections::VecDeque;
use std::fmt::Display;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, Query, RawQuery, State, rejection::JsonRejection},
    http::{StatusCode, header},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use open_pact_core::{
    Checkpoint, Claim, CsrHash, Decision, Endorsement, EnrolRequest, Entry, EntryKind, Evaluation,
    FirstFailures, Frontier, Invitation, LogCheckpoint, LogHash, LogKey, LogPolicy, Manifest,
    MerkleCache, Note, NoteSignature, Pseudonym, PublicKey, Reason, SigningKey, WitnessKey, root,
    verified_trust_level, verify_claim,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

use devices::{Action, State as DeviceState, commitment};
use keys::Keys;
use ratelimit::Limiter;
use seal::SealingKey;
use translog::RowBatch;
use witness::{Outcome, Owners, Witnesses, db_step};

#[derive(Parser)]
#[command(
    name = "open-pact-gateway",
    about = "open-pact gateway; without a command it serves HTTP"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the HTTP API (the default)
    Serve,
    /// Create a one-time invitation; prints the opi1: string on stdout, a readable form on stderr
    Invite {
        /// Print one JSON document on stdout instead: the invitation, its expiry, the company key
        /// fingerprint and the note. Nothing goes to stderr
        #[arg(long)]
        json: bool,
        /// How long the invitation stays valid: 30m, 72h, 7d (at most 30d)
        #[arg(long, default_value = "72h", value_parser = invitations::parse_ttl)]
        ttl: time::Duration,
        /// Who the invitation is for. Stays in the gateway database and is sent in SIEM events
        /// when a SIEM sink is configured. It is never in the transparency log
        #[arg(long, default_value = "")]
        note: String,
        /// The gateway URL the owner's client connects to
        #[arg(long, env = "PUBLIC_URL")]
        url: String,
    },
    /// Read the log from the gateway database
    Log {
        #[command(subcommand)]
        command: LogCommand,
    },
    /// List, approve or revoke devices
    Devices {
        #[command(subcommand)]
        command: DevicesCommand,
    },
    /// Store, read or restore manifest versions
    Manifest {
        #[command(subcommand)]
        command: manifests::Command,
    },
    /// Read stored check results: list claims, show one with every check
    Claims {
        #[command(subcommand)]
        command: results::Command,
    },
    /// Show the gateway version, the manifest it enforces and how many devices are in each state
    Status {
        /// Print one JSON document. On a database error it prints {"error": ...} and exits non-zero
        #[arg(long)]
        json: bool,
    },
}

impl Cli {
    /// The command prints JSON, so its failure is JSON too.
    fn prints_json(&self) -> bool {
        matches!(
            self.command,
            Some(
                Command::Invite { json: true, .. }
                    | Command::Status { json: true }
                    | Command::Manifest {
                        command: manifests::Command::Set { json: true, .. }
                            | manifests::Command::History { json: true }
                            | manifests::Command::Activate { json: true, .. }
                    }
                    | Command::Devices {
                        command: DevicesCommand::List { json: true }
                    }
            )
        ) || matches!(&self.command, Some(Command::Claims { command }) if command.prints_json())
    }
}

#[derive(Subcommand)]
enum LogCommand {
    /// Print log entries as JSON lines
    Entries {
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value_t = 256)]
        limit: u64,
    },
}

#[derive(Subcommand)]
enum DevicesCommand {
    /// Every enrolment with its state and invitation note
    List {
        /// Print a JSON array instead: pseudonym, code, state, note, enrolled_at, manifest_hash
        #[arg(long)]
        json: bool,
    },
    /// Approve the pending device whose pseudonym starts with these hex digits (at least 8)
    Approve { prefix: String },
    /// Revoke a device by its full pseudonym. Final: the device cannot be approved again
    Revoke { pseudonym: String },
}

type Reply = (StatusCode, Json<Value>);

#[derive(Clone)]
struct App {
    db: PgPool,
    /// The pool of the read routes and of every tree step. Writes never use it.
    read_db: PgPool,
    enforced: Arc<Enforced>,
    current: Arc<RwLock<Arc<Enforced>>>,
    keys: Arc<Keys>,
    auto_approve: bool,
    limiter: Arc<Limiter>,
    nonce_limiter: Arc<Limiter>,
    max_nonces: i64,
    kek: Arc<SealingKey>,
    /// None unless metrics or the slow-request log are on.
    observe: Option<Arc<metrics::Observation>>,
    /// One owner task per witness; a manifest reload keeps it.
    owners: Arc<Owners>,
    /// How long a read route waits for a witnessed note before it answers 503.
    wait: Duration,
}

struct Enforced {
    siem: Option<siem::Exporter>,
    manifest: Arc<Manifest>,
    toml: Arc<str>,
    company: Endorsement,
    log: Arc<Log>,
    version: Option<i64>,
    /// Counts the snapshots this process has enforced; published with the snapshot in one write.
    revision: u64,
}

impl std::ops::Deref for App {
    type Target = Enforced;
    fn deref(&self) -> &Enforced {
        &self.enforced
    }
}

struct Log {
    signer: SigningKey,
    key: LogKey,
    witnesses: Witnesses,
    /// Only the fresh decision of `App::signed`.
    cache: Mutex<LogCache>,
    /// The perfect-subtree hashes of the published size. Only a tree step takes it, never a reader.
    grow: tokio::sync::Mutex<Frontier>,
    /// The published view. The lock covers one `Arc` clone or one swap.
    view: Mutex<Arc<LogView>>,
    /// Tree steps that started a fetch, and the highest fetch number whose view is published. Both
    /// change only under `grow`.
    fetches: AtomicU64,
    covered: AtomicU64,
}

impl Log {
    fn new(signer: SigningKey, key: LogKey, witnesses: Witnesses) -> Log {
        Log {
            signer,
            key,
            witnesses,
            cache: Mutex::default(),
            grow: tokio::sync::Mutex::default(),
            view: Mutex::default(),
            fetches: AtomicU64::new(0),
            covered: AtomicU64::new(0),
        }
    }
}

/// The checkpoint is signed once per tree size.
#[derive(Default)]
struct LogCache {
    signed: Option<(Checkpoint, Note)>,
}

/// How many of the latest sizes keep their root, so a candidate size costs O(1) to check.
const ROOT_WINDOW: usize = 4096;

/// The Merkle cache (the leaves and their subtree hashes), the root and the root of each of the last
/// `ROOT_WINDOW` sizes, published together and never changed after.
struct LogView {
    cache: MerkleCache,
    root: LogHash,
    /// Contiguous sizes up to `cache.len()`, oldest first.
    roots: VecDeque<(u64, LogHash)>,
}

impl Default for LogView {
    fn default() -> LogView {
        LogView {
            cache: MerkleCache::default(),
            root: root(&[]),
            roots: VecDeque::new(),
        }
    }
}

/// The committed log as one tree step saw it, with the revision of the snapshot that read it.
#[derive(Clone)]
struct Tree {
    view: Arc<LogView>,
    revision: u64,
}

impl Tree {
    fn size(&self) -> u64 {
        self.view.cache.len()
    }

    fn root(&self) -> LogHash {
        self.view.root
    }

    /// The root of the first `size` leaves, in O(log n) hashes.
    fn root_at(&self, size: u64) -> LogHash {
        self.view
            .cache
            .root(size)
            .expect("size was checked against the tree")
    }

    fn cache(&self) -> &MerkleCache {
        &self.view.cache
    }
}

/// How the SQL of a tree step runs: with the 2 s step limit of the owners and readers, or on a
/// plain pool connection with the base limits.
#[derive(Clone, Copy)]
enum TreeSql {
    Step,
    Base,
}

/// Catches the cache up to the committed log. One step at a time per log cache: a step takes
/// `grow` before its SQL, and returns the view of a fetch that started after it began, so at most
/// one raw batch exists. The CPU of the catch-up runs on the blocking pool.
fn tree_step(
    db: sqlx::PgPool,
    snap: Arc<Enforced>,
    sql: TreeSql,
    hooks: Arc<hooks::Hooks>,
) -> tokio::task::JoinHandle<anyhow::Result<Tree>> {
    tokio::spawn(async move {
        let log = &snap.log;
        let start = log.fetches.load(Ordering::SeqCst);
        hooks.hit("tree_start_captured").await;
        let mut frontier = log.grow.lock().await;
        let view = log.view.lock().expect("log view").clone();
        if log.covered.load(Ordering::SeqCst) > start {
            return Ok(Tree {
                view,
                revision: snap.revision,
            });
        }
        if frontier.len() != view.cache.len() {
            // A failed catch-up lost the frontier; rebuild it from the published leaves.
            let mut rebuilt = Frontier::default();
            view.cache
                .leaves()
                .iter()
                .for_each(|leaf| rebuilt.push(*leaf));
            *frontier = rebuilt;
        }
        let number = log.fetches.fetch_add(1, Ordering::SeqCst);
        let from = view.cache.len();
        let (freed, freed_rx) = tokio::sync::oneshot::channel();
        let batch = RowBatch::new(Some(freed), hooks.clone());
        let fetched = match sql {
            TreeSql::Step => db_step(db, move |conn| {
                Box::pin(translog::since_raw(conn, from, batch))
            })
            .await
            .map_err(anyhow::Error::from)
            .and_then(|result| result),
            TreeSql::Base => {
                let fetch = async {
                    let mut conn = db.acquire().await?;
                    translog::since_raw(&mut conn, from, batch).await
                };
                fetch.await
            }
        };
        let batch = match fetched {
            Ok(batch) => batch,
            Err(error) => {
                // Release `grow` only after a failed batch is freed, so no second fetch starts
                // while it is still live.
                let _ = freed_rx.await;
                return Err(error);
            }
        };
        if batch.is_empty() {
            log.covered.fetch_max(number + 1, Ordering::SeqCst);
            return Ok(Tree {
                view,
                revision: snap.revision,
            });
        }
        let taken = std::mem::take(&mut *frontier);
        let published = snap.clone();
        let blocking_hooks = hooks.clone();
        let built = tokio::task::spawn_blocking(move || {
            catch_up(&published.log, &view, taken, from, batch, &blocking_hooks)
        })
        .await?;
        let (grown, view) = built;
        *frontier = grown;
        let view = view?;
        log.covered.fetch_max(number + 1, Ordering::SeqCst);
        Ok(Tree {
            view,
            revision: snap.revision,
        })
    })
}

/// The CPU phase of a catch-up: decode, hash, window and publish. Returns the frontier whatever
/// happens, so a failed decode loses nothing.
fn catch_up(
    log: &Log,
    view: &LogView,
    mut frontier: Frontier,
    from: u64,
    batch: RowBatch,
    hooks: &hooks::Hooks,
) -> (Frontier, anyhow::Result<Arc<LogView>>) {
    let (rows, freed) = batch.into_parts();
    let entries = translog::decode(&rows, from);
    drop(rows);
    drop(freed);
    hooks.block("cache_catch_up");
    let entries = match entries {
        Ok(entries) => entries,
        Err(error) => return (frontier, Err(error)),
    };
    let mut cache = view.cache.clone();
    let mut roots = view.roots.clone();
    let m = entries.len();
    for (j, entry) in entries.iter().enumerate() {
        let leaf = entry.leaf_hash();
        cache.push(leaf);
        frontier.push(leaf);
        if j + ROOT_WINDOW >= m {
            roots.push_back((cache.len(), frontier.root()));
        }
    }
    while roots.len() > ROOT_WINDOW {
        roots.pop_front();
    }
    let next = Arc::new(LogView {
        root: frontier.root(),
        cache,
        roots,
    });
    *log.view.lock().expect("log view") = next.clone();
    (frontier, Ok(next))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    jws: String,
    /// Travels outside the JWS so the stored claim holds only its hash, `csr_sha256`.
    #[serde(default)]
    csr_pem: Option<String>,
    /// The manifest the device signed, sent while the gateway enforces another one. The gateway
    /// keeps no earlier manifest text, so it learns the consented terms from the device.
    #[serde(default)]
    manifest_toml: Option<String>,
}

#[derive(Deserialize)]
struct RangeQuery {
    from: Option<u64>,
    to: Option<u64>,
}

fn internal(e: impl Display) -> Reply {
    diag::line(format!("internal error: {e}"));
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"status": "error"})),
    )
}

fn bad_request(reason: impl Display) -> Reply {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"status": "error", "reason": reason.to_string()})),
    )
}

fn denied(reasons: Vec<String>) -> Reply {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"status": "denied", "reasons": reasons})),
    )
}

async fn bind_invitation(
    tx: &mut sqlx::PgConnection,
    req: &EnrolRequest,
    device: &Pseudonym,
    manifest: &str,
) -> sqlx::Result<bool> {
    sqlx::query(
        "UPDATE devices SET invitation = $1, enrol_owner_signature = $2, enrol_device_signature = $3 \
         WHERE pseudonym = $4 AND manifest_hash = $5",
    )
    .bind(req.invitation_code.hash().as_str())
    .bind(String::from(req.owner_signature.clone()))
    .bind(String::from(req.device_signature.clone()))
    .bind(device.as_str())
    .bind(manifest)
    .execute(tx)
    .await
    .map(|r| r.rows_affected() == 1)
}

/// The same answer for an unknown, expired, used and someone else's invitation.
fn invalid_invitation() -> Reply {
    denied(vec!["invalid or used invitation".into()])
}

/// What `App::checkpoint` serves: an enrolment signs the size it read; a claim counts the lines under
/// the manifest the device signed, and may advance once.
enum Mode<'a> {
    Enroll,
    Claim { policy: Option<&'a LogPolicy> },
}

impl App {
    fn metrics(&self) -> Option<&metrics::Metrics> {
        self.observe.as_deref()?.metrics()
    }

    /// The committed log with base database limits, for the handlers that never waited on a
    /// witness. It shares the cache and the one-batch bound with every other tree step.
    async fn tree(&self) -> Result<Tree, Reply> {
        #[cfg(test)]
        if self.owners.hooks().fault_in_tree() {
            return Err(internal("a test fault in tree()"));
        }
        let step = tree_step(
            self.read_db.clone(),
            self.enforced.clone(),
            TreeSql::Base,
            self.owners.hooks(),
        );
        let tree = step.await.map_err(internal)?.map_err(internal)?;
        if let Some(metrics) = self.metrics() {
            metrics.log_size(tree.size());
        }
        Ok(tree)
    }

    /// The checkpoint of `tree` signed by the log key, and, when it is the first call for this
    /// size, the replies of the Push that this call queued at every owner. The Push is queued
    /// while the cache lock still decides "fresh", so a later call that sees "not fresh" queues
    /// its Join after it.
    fn signed(
        &self,
        tree: &Tree,
        keys: &Arc<[WitnessKey]>,
    ) -> (
        Checkpoint,
        Note,
        Option<Vec<tokio::sync::oneshot::Receiver<Outcome>>>,
    ) {
        let mut cache = self.log.cache.lock().expect("log cache");
        if let Some((cp, note)) = cache
            .signed
            .clone()
            .filter(|(cp, _)| cp.size == tree.size())
        {
            return (cp, note, None);
        }
        let checkpoint = Checkpoint {
            origin: self.log.key.origin().to_string(),
            size: tree.size(),
            root: tree.root(),
        };
        let note = self.log.key.sign(&self.log.signer, &checkpoint);
        cache.signed = Some((checkpoint.clone(), note.clone()));
        let pending = self.owners.push_all(&checkpoint, &note, tree, keys);
        (checkpoint, note, Some(pending))
    }

    /// The current checkpoint for an enrolment or a claim: the log-signed note, extended with the
    /// witness lines stored for it, and what the witnesses gave. A new checkpoint goes to the
    /// witnesses before any client sees it. The handler counts the result with `count_served`.
    async fn checkpoint(&self, mode: Mode<'_>) -> Result<(Note, metrics::Served), Reply> {
        self.owners.hooks().hit("checkpoint_entered").await;
        let (policy, claim) = match mode {
            Mode::Enroll => (self.manifest.body().log.as_ref(), false),
            Mode::Claim { policy } => (policy, true),
        };
        let keys: Arc<[WitnessKey]> = policy
            .map_or(vec![], |p| {
                p.witnesses.iter().map(|w| w.key.clone()).collect()
            })
            .into();
        let quorum = policy.map_or(0, |p| p.witness_quorum);
        let tree = self.tree().await?;
        self.owners.hooks().hit("checkpoint_tree_read").await;
        let (checkpoint, note, pending) = self.signed(&tree, &keys);
        let (mut reply, mut count, _) = self.assembled(policy, &checkpoint, &note).await?;
        let short = count < quorum;
        if pending.is_some() || (short && self.log.witnesses.retry_due()) {
            let pending =
                pending.unwrap_or_else(|| self.owners.push_all(&checkpoint, &note, &tree, &keys));
            let outcomes = self.pushed(&checkpoint, pending).await?;
            (reply, count, _) = self.assembled(policy, &checkpoint, &note).await?;
            let behind = outcomes.iter().find_map(|o| match o {
                Outcome::Behind { floor } => Some(*floor),
                _ => None,
            });
            if claim
                && count < quorum
                && let Some(floor) = behind
                && let Some(advanced) = self.advance(policy, &keys, floor).await
            {
                reply = advanced.0;
                count = advanced.1;
            }
        } else if short {
            // Another request may be pushing this checkpoint right now.
            for joined in self.owners.join_all() {
                let _ = joined.await;
            }
            (reply, count, _) = self.assembled(policy, &checkpoint, &note).await?;
        }
        let served = if quorum == 0 {
            metrics::Served::LogSigned
        } else if count < quorum {
            metrics::Served::NotYet
        } else {
            metrics::Served::Witnessed
        };
        Ok((reply, served))
    }

    /// Awaits the owners' replies together and writes the lines they returned, as base did: awaited
    /// on the pool with base limits.
    async fn pushed(
        &self,
        checkpoint: &Checkpoint,
        pending: Vec<tokio::sync::oneshot::Receiver<Outcome>>,
    ) -> Result<Vec<Outcome>, Reply> {
        let mut outcomes = vec![];
        for reply in pending {
            outcomes.push(reply.await.unwrap_or(Outcome::Failed));
        }
        #[cfg(test)]
        if self.owners.hooks().fault_after_read() {
            return Err(internal("a test fault in pushed()"));
        }
        for outcome in &outcomes {
            let Outcome::Cosigned(lines) = outcome else {
                continue;
            };
            for (key, line) in lines.iter().filter(|_| checkpoint.size > 0) {
                sqlx::query(witness::UPSERT)
                    .bind(i64::try_from(checkpoint.size).map_err(internal)?)
                    .bind(checkpoint.root.to_string())
                    .bind(key.vkey())
                    .bind(line.to_string().trim_end())
                    .execute(&self.db)
                    .await
                    .map_err(internal)?;
            }
        }
        Ok(outcomes)
    }

    /// The log-signed note extended with the stored lines that `policy` counts, and their count.
    async fn assembled(
        &self,
        policy: Option<&LogPolicy>,
        checkpoint: &Checkpoint,
        note: &Note,
    ) -> Result<(Note, usize, Vec<served::Kept>), Reply> {
        let lines = self.stored_lines(checkpoint).await?;
        Ok(served::assemble(
            &self.log.key,
            policy,
            checkpoint,
            note.clone(),
            &lines,
            served::now_secs(),
            &self.owners.hooks(),
        ))
    }

    async fn stored_lines(&self, checkpoint: &Checkpoint) -> Result<Vec<NoteSignature>, Reply> {
        self.owners.hooks().hit("stored_lines_read").await;
        #[cfg(test)]
        if self.owners.hooks().fault_in_read() {
            return Err(internal("a test fault in the stored-line read"));
        }
        let lines: Vec<String> = sqlx::query_scalar(
            "SELECT signature FROM log_cosignatures WHERE size = $1 AND root = $2 ORDER BY witness",
        )
        .bind(i64::try_from(checkpoint.size).map_err(internal)?)
        .bind(checkpoint.root.to_string())
        .fetch_all(&self.db)
        .await
        .map_err(internal)?;
        lines
            .iter()
            .map(|l| NoteSignature::parse(l).map_err(internal))
            .collect()
    }

    /// A claim whose Push was answered `Behind` advances once to the newer tree. It answers the
    /// advanced note only when the client would accept it; any failure answers none, and the caller
    /// keeps the note of the size it read.
    async fn advance(
        &self,
        policy: Option<&LogPolicy>,
        keys: &Arc<[WitnessKey]>,
        floor: u64,
    ) -> Option<(Note, usize)> {
        let tree = self.tree().await.ok()?;
        self.owners.hooks().hit("checkpoint_advance_read").await;
        if tree.size() < floor {
            return None;
        }
        let (checkpoint, note, pending) = self.signed(&tree, keys);
        let pending =
            pending.unwrap_or_else(|| self.owners.push_all(&checkpoint, &note, &tree, keys));
        self.pushed(&checkpoint, pending).await.ok()?;
        let (reply, count, kept) = self.assembled(policy, &checkpoint, &note).await.ok()?;
        served::usable(
            &self.log.key,
            policy,
            &reply,
            &kept,
            served::now_secs(),
            &self.owners.hooks(),
        )
        .then_some((reply, count))
    }

    /// Counts a checkpoint that an answer went out with.
    fn count_served(&self, caller: metrics::Caller, served: metrics::Served) {
        if let Some(metrics) = self.metrics() {
            metrics.checkpoint_served(caller, served);
        }
    }

    /// A transaction on the pool, with the time it took to get a connection.
    async fn begin(
        &self,
        site: metrics::Site,
    ) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, Reply> {
        metrics::timed(
            self.metrics(),
            |m, secs| m.db_acquire(site, secs),
            self.db.begin(),
        )
        .await
        .map_err(internal)
    }

    async fn conn(&self) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, Reply> {
        metrics::timed(
            self.metrics(),
            |m, secs| m.db_acquire(metrics::Site::Conn, secs),
            self.db.acquire(),
        )
        .await
        .map_err(internal)
    }
}

async fn healthz(Extension(app): Extension<App>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&app.db).await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "db unavailable"),
    }
}

async fn manifest(Extension(app): Extension<App>) -> Json<Value> {
    Json(json!({"toml": &*app.toml, "company": app.company}))
}

async fn legacy_log() -> Reply {
    (
        StatusCode::GONE,
        Json(json!({
            "status": "gone",
            "reason": "the transparency log is now a Merkle tree with signed checkpoints; update open-pact-client and run join again",
        })),
    )
}

async fn log_key_text(Extension(app): Extension<App>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{}\n", app.log.key.vkey()),
    )
}

/// The 503 of both read routes. The client retries it once, after the delay it names.
fn unavailable(why: served::Why) -> axum::response::Response {
    diag::line(format!("checkpoint not served: {why:?}"));
    let headers = [(header::RETRY_AFTER, "5")];
    (
        StatusCode::SERVICE_UNAVAILABLE,
        headers,
        Json(json!({"status": "error", "reason": served::UNAVAILABLE})),
    )
        .into_response()
}

async fn log_checkpoint(
    Extension(app): Extension<App>,
    RawQuery(query): RawQuery,
) -> Result<axum::response::Response, Reply> {
    let deadline = Instant::now() + app.wait;
    let requested = served::request_policy(query.as_deref())?;
    let policy = requested.as_ref().or(app.manifest.body().log.as_ref());
    let has_witnesses = policy.is_some_and(|p| !p.witnesses.is_empty());
    match app.served(policy, deadline).await {
        served::Answer::Witnessed { note, .. } => {
            let served = if has_witnesses {
                metrics::Served::Witnessed
            } else {
                metrics::Served::LogSigned
            };
            app.count_served(metrics::Caller::Checkpoint, served);
            Ok((
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                note.to_string(),
            )
                .into_response())
        }
        served::Answer::Unavailable(why) => {
            app.count_served(metrics::Caller::Checkpoint, metrics::Served::NotYet);
            let headers = [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::RETRY_AFTER, "5"),
            ];
            diag::line(format!("checkpoint not served: {why:?}"));
            Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                headers,
                format!("{}\n", served::UNAVAILABLE),
            )
                .into_response())
        }
    }
}

async fn consistency(
    Extension(app): Extension<App>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Value>, Reply> {
    let tree = app.tree().await?;
    let (Some(from), to) = (q.from, q.to.unwrap_or(tree.size())) else {
        return Err(bad_request("from is required"));
    };
    if to > tree.size() {
        return Err(bad_request(format!("the log has {} entries", tree.size())));
    }
    let proof = tree
        .cache()
        .consistency_proof(from, to)
        .map_err(bad_request)?;
    Ok(Json(json!({"from": from, "to": to, "proof": proof})))
}

fn too_many(reason: &str) -> Reply {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"status": "denied", "reasons": [reason]})),
    )
}

async fn nonce(
    Extension(app): Extension<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Json<Value>, Reply> {
    let now = Instant::now();
    if app.nonce_limiter.blocked(peer.ip(), now) {
        if let Some(metrics) = app.metrics() {
            metrics.nonce_issue(metrics::NonceResult::RateLimited);
        }
        return Err(too_many(
            "too many nonces requested from this address; try again later",
        ));
    }
    app.nonce_limiter.record(peer.ip(), now);
    let issued = nonces::issue(&app.db, app.max_nonces, app.metrics())
        .await
        .map_err(internal)?;
    if let Some(metrics) = app.metrics() {
        metrics.nonce_issue(if issued.is_some() {
            metrics::NonceResult::Issued
        } else {
            metrics::NonceResult::CapReached
        });
    }
    match issued {
        Some(nonce) => Ok(Json(json!({ "nonce": nonce }))),
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"status": "error", "reason": "too many outstanding nonces; try again later"}),
            ),
        )),
    }
}

/// Hourly, so a purge entry in the log is at most an hour late and the log does not grow per tick.
async fn enforce_retention(app: App) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let enforced = app.current.read().expect("manifest snapshot").clone();
        match claims::purge(
            &app.db,
            &enforced.manifest.body().claim_retention,
            OffsetDateTime::now_utc(),
        )
        .await
        {
            Ok(purged) if purged.claims > 0 || purged.period_keys > 0 => eprintln!(
                "retention_purge: {} claims, {} period keys",
                purged.claims, purged.period_keys
            ),
            Ok(_) => {}
            Err(e) => eprintln!("retention purge: {e:#}"),
        }
    }
}

/// Expired nonces are refused anyway; deleting them keeps the table and the cap count small.
async fn delete_expired_nonces(db: PgPool) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        if let Err(e) = nonces::delete_expired(&db).await {
            eprintln!("deleting expired nonces: {e}");
        }
    }
}

/// Every refused enrolment counts against the address, whether the body, a signature, the
/// manifest or the invitation was wrong. Server errors do not count.
async fn enroll(
    Extension(app): Extension<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Result<Json<EnrolRequest>, JsonRejection>,
) -> Result<Json<Value>, Reply> {
    if app.limiter.blocked(peer.ip(), Instant::now()) {
        return Err(too_many(
            "too many failed enrolments from this address; try again later",
        ));
    }
    let result = try_enroll(&app, body).await;
    if matches!(&result, Err((status, _)) if status.is_client_error()) {
        app.limiter.record(peer.ip(), Instant::now());
    }
    result
}

async fn try_enroll(
    app: &App,
    body: Result<Json<EnrolRequest>, JsonRejection>,
) -> Result<Json<Value>, Reply> {
    let Json(req) = body.map_err(|e| denied(vec![e.body_text()]))?;
    let signed = &req.signed_manifest;
    let manifest = req.verify().map_err(|e| denied(vec![e.to_string()]))?;
    if signed.company.key != app.company.key {
        return Err(denied(vec![
            "manifest is not signed by this gateway's company key".into(),
        ]));
    }
    if manifest.hash() != app.manifest.hash() {
        return Err(denied(vec![format!(
            "owner signed {}, gateway enforces {}",
            manifest.hash(),
            app.manifest.hash()
        )]));
    }
    let device = Pseudonym::of(&req.device_key);
    let invitation = req.invitation_code.hash();
    let owner_key = serde_json::to_value(&signed.owner.key).map_err(internal)?;

    let mut tx = app.begin(metrics::Site::OtherTx).await?;
    translog::lock(&mut tx).await.map_err(internal)?;
    let existing: Option<(Value, String, String, Option<String>)> = sqlx::query_as(
        "SELECT owner_key, salt, state, invitation FROM devices WHERE pseudonym = $1 AND manifest_hash = $2 FOR UPDATE",
    )
    .bind(device.as_str())
    .bind(app.manifest.hash().as_str())
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    // The index of the DeviceApproved entry that this enrolment wrote when the gateway approves it.
    let mut approved_index: Option<u64> = None;
    let (salt, state, log_index) = match existing {
        Some((existing_owner, salt, state, stored_invitation)) => {
            if existing_owner != owner_key {
                return Err((
                    StatusCode::CONFLICT,
                    Json(
                        json!({"status": "denied", "reasons": ["device is enrolled by another owner key"]}),
                    ),
                ));
            }
            let accepted = match stored_invitation {
                Some(_) => invitations::used_by(&mut tx, &invitation, &device)
                    .await
                    .map_err(internal)?,
                // Enrolled before invitations existed: a fresh invitation binds the row and
                // pins the client, and the device keeps its state.
                None => {
                    invitations::consume(&mut tx, &invitation, &device)
                        .await
                        .map_err(internal)?
                        && bind_invitation(&mut tx, &req, &device, app.manifest.hash().as_str())
                            .await
                            .map_err(internal)?
                }
            };
            if !accepted {
                return Err(invalid_invitation());
            }
            let index: i64 = sqlx::query_scalar(
                "SELECT idx FROM log_entries WHERE kind = 'device_enrolled' AND data->>'commitment' = $1",
            )
            .bind(commitment(&salt, device.as_str()).map_err(internal)?)
            .fetch_one(&mut *tx)
            .await
            .map_err(internal)?;
            let state = DeviceState::parse(&state).map_err(internal)?;
            (salt, state, u64::try_from(index).map_err(internal)?)
        }
        None => {
            if devices::revoked_anywhere(&mut tx, &device)
                .await
                .map_err(internal)?
            {
                return Err(denied(vec!["device revoked".into()]));
            }
            if !invitations::consume(&mut tx, &invitation, &device)
                .await
                .map_err(internal)?
            {
                return Err(invalid_invitation());
            }
            let salt = hex::encode(rand::random::<[u8; 32]>());
            let state = if app.auto_approve {
                DeviceState::Approved
            } else {
                DeviceState::Pending
            };
            sqlx::query(
                "INSERT INTO devices (pseudonym, manifest_hash, owner_key, owner_signature, salt, state, invitation, \
                 enrol_owner_signature, enrol_device_signature) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(device.as_str())
            .bind(app.manifest.hash().as_str())
            .bind(&owner_key)
            .bind(String::from(signed.owner.signature.clone()))
            .bind(&salt)
            .bind(state.as_str())
            .bind(invitation.as_str())
            .bind(String::from(req.owner_signature.clone()))
            .bind(String::from(req.device_signature.clone()))
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
            let committed =
                json!({ "commitment": commitment(&salt, device.as_str()).map_err(internal)? });
            let entry = translog::append(&mut tx, EntryKind::DeviceEnrolled, committed.clone())
                .await
                .map_err(internal)?;
            if state == DeviceState::Approved {
                let approved = translog::append(&mut tx, EntryKind::DeviceApproved, committed)
                    .await
                    .map_err(internal)?;
                approved_index = Some(approved.index);
            }
            (salt, state, entry.index)
        }
    };
    // The time of the approval, taken right before the commit.
    let approved_at = OffsetDateTime::now_utc();
    tx.commit().await.map_err(internal)?;
    if let Some(index) = approved_index
        && let Some(exporter) = &app.siem
    {
        // The enrolment is committed. A failed note read must not fail it, so it only warns.
        match device_state_event(
            &app.db,
            &device,
            app.manifest.hash().as_str(),
            DeviceState::Approved,
            index,
            approved_at,
        )
        .await
        {
            Ok(event) => exporter.submit(event),
            Err(error) => eprintln!(
                "WARNING: {} is approved, but the SIEM event was not queued: {error:#}",
                device.as_str()
            ),
        }
    }
    let manifest_index: i64 = sqlx::query_scalar(
        "SELECT idx FROM log_entries WHERE kind = 'manifest_published' AND data->>'manifest' = $1",
    )
    .bind(app.manifest.hash().as_str())
    .fetch_one(&app.db)
    .await
    .map_err(internal)?;
    let (checkpoint, served) = app.checkpoint(Mode::Enroll).await?;
    app.count_served(metrics::Caller::Enroll, served);
    Ok(Json(json!({
        "status": "enrolled",
        "device": device,
        "state": state.as_str(),
        "salt": salt,
        "log_index": log_index,
        "manifest_log_index": manifest_index,
        "log_checkpoint": checkpoint.to_string(),
    })))
}

fn device_denied() -> Reply {
    denied(vec!["device access denied".into()])
}

async fn consume_nonce(app: &App, nonce: &str) -> Result<(), Reply> {
    match nonces::consume(&app.db, nonce).await.map_err(internal)? {
        Some(true) => Ok(()),
        Some(false) => Err(denied(vec!["expired nonce".into()])),
        None => Err(denied(vec!["unknown or used nonce".into()])),
    }
}

async fn authenticate_device(
    app: &App,
    request: &MyEntriesRequest,
    purpose: DeviceAuthPurpose,
) -> Result<(), Reply> {
    request.verify(purpose).map_err(|_| device_denied())?;
    consume_nonce(app, &request.nonce)
        .await
        .map_err(|_| device_denied())
}

async fn device_status(
    Extension(app): Extension<App>,
    body: Result<Json<MyEntriesRequest>, JsonRejection>,
) -> Result<Json<Value>, Reply> {
    let Json(request) = body.map_err(|_| device_denied())?;
    authenticate_device(&app, &request, DeviceAuthPurpose::DeviceStatus).await?;
    let enrolment = devices::bound(
        &mut *app.conn().await?,
        &request.pseudonym,
        app.manifest.hash().as_str(),
    )
    .await
    .map_err(internal)?
    .ok_or_else(device_denied)?;
    Ok(Json(json!({"state": enrolment.state.as_str()})))
}

/// Moves an enrolled device to the manifest the gateway enforces, once its owner and device both
/// signed the acceptance. The state, salt and grace clocks stay. Every other enrolment of the
/// device goes, so one row remains. A repeat answers the same, and a lost response can be retried.
async fn accept_manifest(
    Extension(app): Extension<App>,
    body: Result<Json<AcceptRequest>, JsonRejection>,
) -> Result<Json<Value>, Reply> {
    let Json(req) = body.map_err(|e| denied(vec![e.body_text()]))?;
    req.verify().map_err(|e| denied(vec![e.to_string()]))?;
    let current = app.manifest.hash();
    if &req.manifest != current {
        return Err(denied(vec![format!(
            "owner accepted {}, gateway enforces {current}",
            req.manifest
        )]));
    }
    consume_nonce(&app, &req.nonce).await?;
    let owner_key = serde_json::to_value(&req.owner.key).map_err(internal)?;
    let mut tx = app.begin(metrics::Site::OtherTx).await?;
    translog::lock(&mut tx).await.map_err(internal)?;
    let bound = devices::lock_bound(&mut tx, &req.pseudonym, current.as_str())
        .await
        .map_err(internal)?
        .ok_or_else(device_denied)?;
    if bound.owner_key != owner_key {
        return Err(denied(vec![
            "the owner key differs from the one that enrolled this device".into(),
        ]));
    }
    let repeat = bound.manifest == current.as_str();
    if !repeat && req.previous.as_str() != bound.manifest {
        return Err(denied(vec![format!(
            "the acceptance names {}, but this device's enrolment in use is {}",
            req.previous, bound.manifest
        )]));
    }
    sqlx::query("DELETE FROM devices WHERE pseudonym = $1 AND manifest_hash <> $2")
        .bind(req.pseudonym.as_str())
        .bind(&bound.manifest)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    if !repeat {
        sqlx::query(
            "UPDATE devices SET manifest_hash = $1, owner_signature = $2, \
             accept_owner_signature = $3, accept_device_signature = $4 \
             WHERE pseudonym = $5 AND manifest_hash = $6",
        )
        .bind(current.as_str())
        .bind(String::from(req.owner.signature.clone()))
        .bind(String::from(req.owner_signature.clone()))
        .bind(String::from(req.device_signature.clone()))
        .bind(req.pseudonym.as_str())
        .bind(&bound.manifest)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        translog::append(
            &mut tx,
            EntryKind::ManifestAccepted,
            json!({
                "commitment": commitment(&bound.salt, req.pseudonym.as_str()).map_err(internal)?,
                "manifest": current,
            }),
        )
        .await
        .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    Ok(Json(
        json!({"status": "accepted", "state": bound.state.as_str(), "manifest": current}),
    ))
}

/// The device's enrolment under the current manifest, when it is approved; otherwise the 403.
async fn approved_enrolment(
    app: &App,
    conn: &mut sqlx::PgConnection,
    pseudonym: &Pseudonym,
) -> Result<devices::Enrolment, Reply> {
    devices::bound(conn, pseudonym, app.manifest.hash().as_str())
        .await
        .map_err(internal)?
        .filter(|e| e.state == DeviceState::Approved)
        .ok_or_else(device_denied)
}

async fn log_mine(
    Extension(app): Extension<App>,
    RawQuery(query): RawQuery,
    body: Result<Json<MyEntriesRequest>, JsonRejection>,
) -> Result<axum::response::Response, Reply> {
    let Json(request) = body.map_err(|_| device_denied())?;
    authenticate_device(&app, &request, DeviceAuthPurpose::LogMine).await?;
    let requested = served::request_policy(query.as_deref())?;
    let policy = requested.as_ref().or(app.manifest.body().log.as_ref());
    let has_witnesses = policy.is_some_and(|p| !p.witnesses.is_empty());
    // A pending or revoked device gets the base 403 whether or not a checkpoint is ready. The
    // connection goes back to the pool before any wait for a witness.
    {
        let mut conn = app.conn().await?;
        approved_enrolment(&app, &mut conn, &request.pseudonym).await?;
    }
    app.owners.hooks().hit("served_entered").await;
    let deadline = Instant::now() + app.wait;
    let (note, tree) = match app.served(policy, deadline).await {
        served::Answer::Witnessed { note, tree } => (note, tree),
        served::Answer::Unavailable(why) => {
            app.count_served(metrics::Caller::Mine, metrics::Served::NotYet);
            return Ok(unavailable(why));
        }
    };
    let served = if has_witnesses {
        metrics::Served::Witnessed
    } else {
        metrics::Served::LogSigned
    };
    let cp = Checkpoint::parse(&note.text).map_err(internal)?;
    // The wait above can last seconds, so the approval is read again on the connection that reads
    // the entries: a device revoked during the wait gets the 403, not its entries.
    let mut tx = metrics::timed(
        app.metrics(),
        |m, secs| m.db_acquire(metrics::Site::OtherTx, secs),
        translog::begin_proof(&app.db),
    )
    .await
    .map_err(internal)?;
    let enrolment = approved_enrolment(&app, &mut tx, &request.pseudonym).await?;
    let commitment =
        devices::commitment(&enrolment.salt, request.pseudonym.as_str()).map_err(internal)?;
    let entries = translog::mine(&mut tx, cp.size, &enrolment.manifest, &commitment)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    let with_proof = |entry: Entry| -> Result<EntryWithProof, Reply> {
        let proof = tree
            .cache()
            .inclusion_proof(cp.size, entry.index)
            .map_err(internal)?;
        Ok(EntryWithProof { entry, proof })
    };
    let mut manifest = None;
    let mut device = Vec::new();
    for entry in entries {
        if entry.kind == EntryKind::ManifestPublished {
            manifest = Some(with_proof(entry)?);
        } else {
            device.push(with_proof(entry)?);
        }
    }
    let manifest = manifest.ok_or_else(|| internal("manifest log entry missing"))?;
    app.count_served(metrics::Caller::Mine, served);
    Ok(Json(MyEntries {
        checkpoint: note.to_string(),
        manifest,
        device,
    })
    .into_response())
}

async fn claim(
    Extension(app): Extension<App>,
    body: Result<Json<ClaimRequest>, JsonRejection>,
) -> Result<Json<Value>, Reply> {
    let Ok(Json(ClaimRequest {
        jws,
        csr_pem,
        manifest_toml,
    })) = body
    else {
        return Err(denied(vec![
            "body must be {\"jws\": \"<compact JWS>\", \"csr_pem\": \"<PEM>\", \"manifest_toml\": \"<TOML>\"}, csr_pem and manifest_toml optional"
                .into(),
        ]));
    };
    let mut clock = metrics::StageClock::new(app.metrics());
    let verified = verify_claim(&jws).map_err(|e| denied(vec![e.to_string()]))?;
    let claim = verified.claim();
    clock.mark(metrics::Stage::Verify);
    consume_nonce(&app, &claim.nonce).await?;
    clock.mark(metrics::Stage::Nonce);
    let foreign = match &claim.log_checkpoint {
        Some(cp) => foreign_checkpoint(&app.tree().await?, cp),
        None => None,
    };
    clock.mark(metrics::Stage::Tree);
    let manifest_hash = claim.manifest.as_str();
    let mut tx = app.begin(metrics::Site::ClaimTx).await?;
    clock.mark(metrics::Stage::Begin);
    let bound = devices::lock_bound(&mut tx, &claim.device, app.manifest.hash().as_str())
        .await
        .map_err(internal)?;
    let own = devices::lock(&mut tx, &claim.device, manifest_hash)
        .await
        .map_err(internal)?;
    clock.mark(metrics::Stage::Lock);
    let enrolled = own.is_some();
    let state = bound.as_ref().filter(|_| enrolled).map(|b| b.state);
    let mut reasons: Vec<String> = match state {
        None => vec!["device not enrolled".into()],
        Some(state) => state.denial().map(str::to_string).into_iter().collect(),
    };
    // A device can hold one enrolment per manifest it joined under. Only the enrolment in use
    // counts, so a claim under an older one cannot take a fresh grace clock or dodge the denial
    // of the enrolment in use.
    if let (true, Some(bound)) = (enrolled, &bound)
        && bound.manifest != manifest_hash
    {
        reasons.push(format!(
            "the claim is under {manifest_hash}, but this device's enrolment in use is {}",
            bound.manifest
        ));
    }
    let consented = if enrolled && &claim.manifest != app.manifest.hash() {
        match consented_manifest(&app.manifest, &claim.manifest, manifest_toml.as_deref()) {
            Ok(manifest) => Arc::new(manifest),
            Err(reason) => {
                reasons.push(reason);
                devices::record_claim(
                    &mut tx,
                    &claim.device,
                    manifest_hash,
                    OffsetDateTime::now_utc(),
                    devices::ClaimResult::Denied,
                    None,
                    &reasons,
                )
                .await
                .map_err(internal)?;
                tx.commit().await.map_err(internal)?;
                return Err(denied(reasons));
            }
        }
    } else {
        app.manifest.clone()
    };
    let now = OffsetDateTime::now_utc();
    let first_failures = if enrolled {
        grace::load(&mut tx, &claim.device, manifest_hash)
            .await
            .map_err(internal)?
    } else {
        FirstFailures::new()
    };

    let Evaluation {
        decision,
        controls,
        first_failures,
    } = evaluate_under(&consented, &app.manifest, claim, now, &first_failures);
    clock.mark(metrics::Stage::Evaluate);
    let oversharing = matches!(&decision, Decision::Deny { reasons } if reasons.iter().any(Reason::breaks_disclosure_contract));
    let strings = |rs: &[Reason]| rs.iter().map(ToString::to_string).collect::<Vec<_>>();
    let nearest_deadline = nearest_grace_deadline(&decision, now);
    let (warnings, decision_reasons) = match &decision {
        Decision::Allow { warnings } => (strings(warnings), vec![]),
        Decision::Deny { reasons } => (vec![], strings(reasons)),
    };
    reasons.extend(decision_reasons);
    reasons.extend(foreign);
    let csr = match (&claim.csr_sha256, &csr_pem) {
        (None, None) => None,
        (Some(hash), Some(pem)) => match keys::bare_csr_der(pem) {
            Ok(der) if CsrHash::of(&der) == *hash => Some(pem),
            Ok(_) => {
                reasons.push("csr_pem does not match the claim's csr_sha256".into());
                None
            }
            Err(e) => {
                reasons.push(e);
                None
            }
        },
        (Some(_), None) => {
            reasons.push("the claim signs csr_sha256 but the request has no csr_pem".into());
            None
        }
        (None, Some(_)) => {
            reasons.push("csr_pem needs its csr_sha256 in the signed claim".into());
            None
        }
    };
    let mut certificate_pem = None;
    let mut access_until = None;
    if let (true, Some(csr)) = (reasons.is_empty(), csr)
        && let Some(not_after) = certificate_expiry(&app.manifest, nearest_deadline, now)
    {
        let cn = claim.device.as_str().trim_start_matches("pseudonym:");
        match app.keys.ca.issue(csr, cn, not_after) {
            Ok(pem) => {
                access_until = Some(keys::certificate_not_after(&pem).map_err(internal)?);
                certificate_pem = Some(pem);
            }
            Err(e) => reasons.push(e),
        }
    }
    clock.mark(metrics::Stage::Certificate);
    if enrolled {
        grace::save(&mut tx, &claim.device, manifest_hash, &first_failures)
            .await
            .map_err(internal)?;
        let (result, listed) = devices::claim_outcome(&warnings, &reasons, oversharing);
        devices::record_claim(
            &mut tx,
            &claim.device,
            manifest_hash,
            now,
            result,
            access_until,
            &listed,
        )
        .await
        .map_err(internal)?;
    }
    if enrolled && !oversharing {
        let payload =
            stored_claim(claim, certificate_pem.as_deref(), access_until).map_err(internal)?;
        claims::store(
            &mut tx,
            &app.kek,
            &consented.body().claim_retention,
            now,
            &claim.device,
            &payload,
            verified.jws(),
            reasons.is_empty(),
        )
        .await
        .map_err(internal)?;
    }
    let device_note = if enrolled && !oversharing && app.siem.is_some() {
        devices::note(&mut tx, &claim.device, manifest_hash)
            .await
            .map_err(internal)?
    } else {
        String::new()
    };
    clock.mark(metrics::Stage::Store);
    tx.commit().await.map_err(internal)?;
    clock.mark(metrics::Stage::Commit);
    app.owners.hooks().hit("claim_committed").await;
    if enrolled
        && !oversharing
        && let Some(exporter) = &app.siem
    {
        exporter.submit(siem::event(
            &consented,
            claim,
            &device_note,
            &reasons,
            &warnings,
            access_until,
            &controls,
        ));
    }
    clock.mark(metrics::Stage::Siem);
    if !reasons.is_empty() {
        return Err(denied(reasons));
    }
    let policy = consented.body().log.as_ref();
    let (checkpoint, served) = app.checkpoint(Mode::Claim { policy }).await?;
    app.owners.hooks().hit("claim_checkpointed").await;
    clock.mark(metrics::Stage::Checkpoint);
    app.count_served(metrics::Caller::Claim, served);
    Ok(Json(json!({
        "status": "accepted",
        "warnings": warnings,
        "certificate_pem": certificate_pem,
        "ca_pem": app.keys.ca.cert_pem,
        "log_checkpoint": checkpoint.to_string(),
    })))
}

/// The manifest a device enrolled under `signed` consented to, while the gateway enforces
/// `enforced`. The device row holds only the hash, and the gateway set that hash only after it
/// checked the company signature at enrolment, so text with the same hash is that manifest.
fn consented_manifest(
    enforced: &Manifest,
    signed: &open_pact_core::ManifestHash,
    toml: Option<&str>,
) -> Result<Manifest, String> {
    let run_accept = format!(
        "this device signed manifest {signed}, the gateway now enforces {}; \
         run `open-pact-client accept`",
        enforced.hash()
    );
    let toml = toml.ok_or_else(|| {
        format!("{run_accept}; update open-pact-client if it does not send its signed manifest")
    })?;
    let manifest = Manifest::parse(toml.as_bytes())
        .map_err(|_| "manifest_toml is not a valid manifest".to_string())?;
    if manifest.hash() != signed {
        return Err(format!(
            "manifest_toml is {}, not the manifest this device signed; {run_accept}",
            manifest.hash()
        ));
    }
    Ok(manifest)
}

/// The claim as the company keeps it, with the fingerprint of the certificate issued for it. The
/// client's `trust_level` is kept as `asserted_trust_level`, next to the level the gateway verified.
fn stored_claim(
    claim: &Claim,
    certificate_pem: Option<&str>,
    access_until: Option<OffsetDateTime>,
) -> anyhow::Result<Value> {
    let mut payload = serde_json::to_value(claim)?;
    let fields = payload.as_object_mut().expect("a claim is a JSON object");
    let asserted = fields.remove("trust_level");
    fields.insert("asserted_trust_level".into(), asserted.into());
    fields.insert(
        "verified_trust_level".into(),
        serde_json::to_value(verified_trust_level(claim))?,
    );
    if let Some(pem) = certificate_pem {
        payload["certificate_sha256"] = keys::certificate_sha256(pem)?.into();
    }
    if let Some(until) = access_until {
        payload["certificate_not_after"] = results::stamp(until).into();
    }
    Ok(payload)
}

/// When the VPN certificate of a claim accepted at `now` ends, or None when none may be issued. The
/// gateway decides it from the manifest it enforces, never from the one the device signed, so a
/// shorter send interval takes effect before the device accepts it. The end is one absolute time,
/// in whole seconds as X.509 holds them: it is never after `nearest_deadline`, however late the
/// signer runs.
fn certificate_expiry(
    enforced: &Manifest,
    nearest_deadline: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> Option<OffsetDateTime> {
    let lease = open_pact_core::vpn_lease(
        enforced.body().schedule.as_ref(),
        &enforced.body().claim_max_age,
        nearest_deadline,
        now,
    );
    let end = OffsetDateTime::from_unix_timestamp((now + lease).unix_timestamp()).ok()?;
    (end > now).then_some(end)
}

/// When the first warning of an accepted claim turns into a denial. None when no warning has a
/// grace that ends.
fn nearest_grace_deadline(
    decision: &open_pact_core::Decision,
    now: OffsetDateTime,
) -> Option<OffsetDateTime> {
    let open_pact_core::Decision::Allow { warnings } = decision else {
        return None;
    };
    warnings
        .iter()
        .filter_map(|reason| match reason {
            open_pact_core::Reason::NotAccepted { grace, .. }
            | open_pact_core::Reason::Failed { grace, .. }
            | open_pact_core::Reason::Unknown { grace, .. } => match grace {
                open_pact_core::Grace::Left(left) if *left != open_pact_core::timestamp::MAX => {
                    now.checked_add(*left)
                }
                _ => None,
            },
            _ => None,
        })
        .min()
}

async fn index(Extension(app): Extension<App>) -> Result<Html<String>, Reply> {
    let tree = app.tree().await?;
    Ok(Html(format!(
        include_str!("index.html"),
        manifest = app.manifest.hash(),
        company = app.company.key.fingerprint(),
        log_size = tree.size(),
        log_root = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(tree.root().0)
        },
        log_witnesses = app.log.witnesses.keys().len(),
        ca = app.keys.ca.fingerprint,
    )))
}

async fn publish_manifest(db: &PgPool, manifest: &Manifest) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    publish_manifest_in(&mut tx, manifest).await?;
    tx.commit().await?;
    Ok(())
}

async fn publish_manifest_in(
    tx: &mut sqlx::PgConnection,
    manifest: &Manifest,
) -> anyhow::Result<()> {
    translog::lock(tx).await?;
    let published: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM log_entries WHERE kind = 'manifest_published' AND data->>'manifest' = $1)",
    )
    .bind(manifest.hash().as_str())
    .fetch_one(&mut *tx)
    .await?;
    if !published {
        let entry = translog::append(
            &mut *tx,
            EntryKind::ManifestPublished,
            json!({ "manifest": manifest.hash() }),
        )
        .await?;
        eprintln!(
            "log entry {}: manifest_published {}",
            entry.index,
            manifest.hash()
        );
    }
    Ok(())
}

/// Connections of the read pool: the read routes and every tree step use it, so a write path that
/// stalls PostgreSQL leaves them a connection.
const DEFAULT_READ_POOL: u32 = 4;

fn read_pool_connections() -> anyhow::Result<u32> {
    let connections: u32 = env_number("READ_POOL_CONNECTIONS", DEFAULT_READ_POOL)?;
    anyhow::ensure!(connections > 0, "READ_POOL_CONNECTIONS must be at least 1");
    Ok(connections)
}

/// A pool of up to `connections` connections with the options of `db`. It opens no connection
/// until a read needs one.
fn read_pool(db: &PgPool, connections: u32) -> PgPool {
    PgPoolOptions::new()
        .max_connections(connections)
        .connect_lazy_with(db.connect_options().as_ref().clone())
}

async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let max_connections: u32 = env_number("DATABASE_MAX_CONNECTIONS", 10)?;
    anyhow::ensure!(
        max_connections > 0,
        "DATABASE_MAX_CONNECTIONS must be at least 1"
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await
        {
            Ok(db) => return Ok(db),
            Err(e) if tokio::time::Instant::now() < deadline => {
                eprintln!("database not ready, retrying: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn witness_urls() -> Vec<String> {
    std::env::var("WITNESS_URLS")
        .unwrap_or_default()
        .split([',', ' ', '\n'])
        .filter(|u| !u.is_empty())
        .map(String::from)
        .collect()
}

/// Re-sends the current checkpoint so the cosignatures stay younger than checkpoint_max_age
/// while the log does not grow.
fn witness_refresh(manifest: &Manifest, has_witnesses: bool) -> anyhow::Result<Option<Duration>> {
    match manifest
        .body()
        .log
        .as_ref()
        .and_then(|p| p.checkpoint_max_age.min_duration())
    {
        Some(age) if has_witnesses => {
            let quarter = u64::try_from(age.whole_seconds() / 4).unwrap_or(600);
            Ok(Some(Duration::from_secs(env_number(
                "WITNESS_REFRESH_SECS",
                quarter.clamp(10, 600),
            )?)))
        }
        _ => Ok(None),
    }
}

async fn refresh_cosignatures(mut app: App) {
    let mut last = Instant::now();
    let mut version = app.version;
    loop {
        let delay = witness_refresh(&app.manifest, !app.owners.is_empty())
            .ok()
            .flatten()
            .map(|every| every.saturating_sub(last.elapsed()))
            .unwrap_or(Duration::from_secs(10))
            .min(Duration::from_secs(10));
        tokio::time::sleep(delay).await;
        app.enforced = app.current.read().expect("manifest snapshot").clone();
        let Ok(Some(every)) = witness_refresh(&app.manifest, !app.owners.is_empty()) else {
            continue;
        };
        if version == app.version && last.elapsed() < every {
            continue;
        }
        version = app.version;
        last = Instant::now();
        app.owners.refresh_all();
    }
}

/// Denies a claim whose checkpoint is not a state of this gateway's log.
fn foreign_checkpoint(tree: &Tree, cp: &LogCheckpoint) -> Option<String> {
    let known = cp.size > 0 && cp.size <= tree.size() && tree.root_at(cp.size) == cp.root;
    (!known).then(|| {
        format!(
            "the claim's log checkpoint (size {}) is not a state of this gateway's log (size {})",
            cp.size,
            tree.size()
        )
    })
}

fn log_origin() -> anyhow::Result<String> {
    parse_log_origin(std::env::var("LOG_ORIGIN").ok())
}

fn parse_log_origin(origin: Option<String>) -> anyhow::Result<String> {
    let origin =
        origin.ok_or_else(|| anyhow::anyhow!("LOG_ORIGIN is required to start the gateway"))?;
    if origin.is_empty() || origin.contains(|c: char| c.is_whitespace() || c == '+') {
        anyhow::bail!("LOG_ORIGIN must be non-empty, without spaces or '+': {origin:?}");
    }
    Ok(origin)
}

fn env_flag(name: &str) -> anyhow::Result<bool> {
    match std::env::var(name).as_deref() {
        Err(_) | Ok("" | "false" | "0") => Ok(false),
        Ok("true" | "1") => Ok(true),
        Ok(other) => anyhow::bail!("{name} must be true or false, got {other:?}"),
    }
}

fn env_number<T: std::str::FromStr>(name: &str, default: T) -> anyhow::Result<T> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(v) => v
            .parse()
            .map_err(|_| anyhow::anyhow!("{name} must be a number, got {v:?}")),
    }
}

fn log_key(keys: &Keys) -> anyhow::Result<LogKey> {
    Ok(LogKey::new(&log_origin()?, &PublicKey::from(&keys.log)))
}

/// What `invite --json` prints.
#[derive(serde::Serialize)]
struct InviteDocument {
    invitation: String,
    expires_at: String,
    company_key_fingerprint: String,
    note: String,
}

async fn invite(
    db: &PgPool,
    kek: &SealingKey,
    url: &str,
    ttl: time::Duration,
    note: &str,
    json: bool,
    out: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let parsed = url.parse::<axum::http::Uri>()?;
    if !matches!(parsed.scheme_str(), Some("https" | "http")) || parsed.host().is_none() {
        anyhow::bail!("--url must be an http(s) URL, got {url:?}");
    }
    let keys = Keys::load_or_create(db, kek).await?;
    let (code, expires) = invitations::create(db, ttl, note).await?;
    let company = PublicKey::from(&keys.manifest);
    let invitation = Invitation::new(url, &company, &log_key(&keys)?, code);
    let expires_at = open_pact_core::timestamp::rfc3339_secs(expires);
    if json {
        let document = InviteDocument {
            invitation: invitation.encode(),
            expires_at,
            company_key_fingerprint: company.fingerprint(),
            note: note.to_owned(),
        };
        writeln!(out, "{}", serde_json::to_string_pretty(&document)?)?;
        return Ok(());
    }
    eprint!(
        "One-time invitation, valid until {expires_at}{}\n{}",
        if note.is_empty() {
            String::new()
        } else {
            format!(", for {note}")
        },
        invitation.describe()
    );
    eprintln!(
        "Send the opi1: line to the owner. Confirm the company key fingerprint over a second channel.\n\
         Approve the device with: open-pact-gateway devices approve <first 8+ hex digits of its pseudonym>"
    );
    writeln!(out, "{}", invitation.encode())?;
    Ok(())
}

/// What `status --json` prints.
#[derive(serde::Serialize)]
struct StatusDocument {
    version: &'static str,
    manifest_hash: String,
    auto_approve: bool,
    devices: devices::StateCounts,
    company_key_fingerprint: String,
    manifest_source: &'static str,
    manifest_version: Option<i64>,
}

async fn status(
    db: &PgPool,
    kek: &SealingKey,
    manifest: &Manifest,
    auto_approve: bool,
) -> anyhow::Result<StatusDocument> {
    let keys = Keys::load_or_create(db, kek).await?;
    let active = manifests::active(db).await?;
    Ok(StatusDocument {
        version: env!("CARGO_PKG_VERSION"),
        manifest_hash: active
            .as_ref()
            .map_or_else(|| manifest.hash().to_string(), |row| row.hash.clone()),
        manifest_source: if active.is_some() {
            "database"
        } else if std::env::var_os("MANIFEST_PATH").is_some() {
            "file"
        } else {
            "builtin"
        },
        manifest_version: active.map(|row| row.version),
        auto_approve,
        devices: devices::counts(db).await?,
        company_key_fingerprint: PublicKey::from(&keys.manifest).fingerprint(),
    })
}

fn manifest_path() -> String {
    std::env::var("MANIFEST_PATH").unwrap_or_else(|_| "examples/manifest.toml".into())
}

/// The manifest this process enforces: the file at `MANIFEST_PATH`, or the example manifest.
fn read_manifest() -> anyhow::Result<(String, String, Manifest)> {
    let path = manifest_path();
    let toml = std::fs::read_to_string(&path)?;
    let manifest = Manifest::parse(toml.as_bytes())?;
    Ok((path, toml, manifest))
}

/// The hash of the startup file, or None when that file does not exist. Only a missing file is
/// tolerated: `manifest set` reports this hash and must not fail for want of it.
fn startup_manifest_hash() -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(manifest_path()) {
        Ok(toml) => Ok(Some(Manifest::parse(toml.as_bytes())?.hash().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

async fn admin_devices(db: &PgPool, command: DevicesCommand) -> anyhow::Result<()> {
    let (device, action) = match command {
        DevicesCommand::List { json: false } => {
            print!("{}", devices::list(db).await?);
            return Ok(());
        }
        DevicesCommand::List { json: true } => {
            print!("{}", devices::list_json(db).await?);
            return Ok(());
        }
        DevicesCommand::Approve { prefix } => (
            devices::pending_by_prefix(db, &prefix).await?,
            Action::Approve,
        ),
        DevicesCommand::Revoke { pseudonym } => {
            (devices::full_pseudonym(&pseudonym)?, Action::Revoke)
        }
    };
    let applied = devices::apply(db, &device, action).await?;
    for (manifest, state) in &applied.states {
        println!("{} {device} for {manifest}", state.as_str());
    }
    if let Some(change) = &applied.change {
        // The change is committed. A SIEM that cannot be reached must not make the command fail.
        if let Err(error) = announce_state(db, &device, change).await {
            eprintln!(
                "WARNING: {device} is {state}, but the SIEM event was not sent: {error:#}",
                state = change.state.as_str()
            );
        }
    }
    Ok(())
}

/// Sends one `device_state` event to the SIEM the server is configured with, if there is one.
async fn announce_state(db: &PgPool, device: &str, change: &devices::Change) -> anyhow::Result<()> {
    let Some(sink) = siem::OneShot::from_env()? else {
        return Ok(());
    };
    let pseudonym = Pseudonym::try_from(device.to_owned()).map_err(anyhow::Error::msg)?;
    let event = device_state_event(
        db,
        &pseudonym,
        &change.manifest,
        change.state,
        change.log_index,
        change.at,
    )
    .await?;
    tokio::task::spawn_blocking(move || sink.send(&event)).await?
}

/// The `device_state` event for `device` under `manifest`, with the note of its invitation. It
/// carries the log entry `log_index` that recorded the change, and the time `at` of the change.
async fn device_state_event(
    db: &PgPool,
    device: &Pseudonym,
    manifest: &str,
    state: devices::State,
    log_index: u64,
    at: OffsetDateTime,
) -> anyhow::Result<Value> {
    let note = devices::note(&mut *db.acquire().await?, device, manifest).await?;
    Ok(siem::state_event(
        device,
        &note,
        state.as_str(),
        log_index,
        at,
    ))
}

fn router(app: App) -> Router {
    let observation = app.observe.clone();
    let router = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/v1/manifest", get(self::manifest))
        .route("/v1/enroll", post(enroll))
        .route("/v1/log", get(legacy_log))
        .route("/v1/log/key", get(self::log_key_text))
        .route("/v1/log/checkpoint", get(log_checkpoint))
        .route("/v1/log/proof/consistency", get(consistency))
        .route("/v1/nonce", post(nonce))
        .route("/v1/claim", post(claim))
        .route("/v1/log/mine", post(log_mine))
        .route("/v1/device/status", post(device_status))
        .route("/v1/device/accept", post(accept_manifest))
        .layer(axum::middleware::from_fn_with_state(app, snapshot));
    match observation {
        Some(observation) => metrics::layer(router, observation),
        None => router,
    }
}

async fn snapshot(
    State(mut app): State<App>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    app.enforced = app.current.read().expect("manifest snapshot").clone();
    request.extensions_mut().insert(app);
    next.run(request).await
}

async fn reload_manifest(app: &App) -> anyhow::Result<()> {
    let Some(row) = manifests::active(&app.db).await? else {
        return Ok(());
    };
    let current = app.current.read().expect("manifest snapshot").clone();
    if current.version == Some(row.version) {
        return Ok(());
    }
    let mut enforced = manifests::enforced(&row.toml, &app.keys, Some(row.version))?;
    enforced.siem = current.siem.clone();
    enforced.revision = current.revision + 1;
    publish_manifest(&app.db, &enforced.manifest).await?;
    eprintln!(
        "enforcing database manifest version {} {}",
        row.version,
        enforced.manifest.hash()
    );
    // The owners accept a line of the new manifest's witnesses before the snapshot that asks for it.
    app.owners.add_keys(enforced.log.witnesses.keys());
    *app.current.write().expect("manifest snapshot") = Arc::new(enforced);
    app.owners.hooks().hit("reload_published").await;
    app.owners.reload_all();
    Ok(())
}

async fn poll_manifest(app: App) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        if let Err(error) = reload_manifest(&app).await {
            eprintln!("manifest reload: {error:#}");
        }
    }
}

async fn serve(db: PgPool, read_connections: u32) -> anyhow::Result<()> {
    let read_db = read_pool(&db, read_connections);
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    // Checked first: a bad token or certificate refuses startup before any other work.
    let observation = metrics::Settings::from_env()?;
    // The diagnostic writer starts before the listener, so its start failure is reported here.
    diag::start();
    let registry = observation
        .listener
        .is_some()
        .then(|| Arc::new(metrics::Metrics::new()));
    let observe = metrics::Observation::new(registry.clone(), observation.slow_ms);
    if let (Some(listener), Some(registry)) = (observation.listener, registry) {
        let bound = metrics::start(listener, registry, db.clone(), read_db.clone()).await?;
        eprintln!("metrics on {bound}");
    }
    if let Some(ms) = observation.slow_ms {
        eprintln!("logging requests slower than {ms} ms");
    }
    let active = manifests::active(&db).await?;
    let (manifest_path, toml, manifest) = match &active {
        Some(row) => (
            "database".into(),
            row.toml.clone(),
            Manifest::parse(row.toml.as_bytes())?,
        ),
        None => read_manifest()?,
    };
    eprintln!("enforcing {manifest_path} {}", manifest.hash());
    if manifest.body().min_trust_level > open_pact_core::TrustLevel::L0 {
        eprintln!(
            "min_trust_level {:?} needs attestation, which is not available: every claim will be denied",
            manifest.body().min_trust_level
        );
    }
    let auto_approve = env_flag("AUTO_APPROVE")?;
    let limiter = Limiter::new(
        env_number("ENROL_MAX_FAILURES", 10)?,
        Duration::from_secs(env_number("ENROL_FAILURE_WINDOW_SECS", 600)?),
        100_000,
    );
    let nonce_limiter = Limiter::new(
        env_number("NONCE_MAX_PER_WINDOW", 600)?,
        Duration::from_secs(env_number("NONCE_WINDOW_SECS", 60)?),
        100_000,
    );
    let max_nonces = env_number("NONCE_MAX_OUTSTANDING", 10_000)?;
    let kek = SealingKey::kek_from_env()?;
    let keys = Keys::load_or_create(&db, &kek).await?;
    let policy = manifest.body().log.as_ref();
    let wait_ms: u64 = env_number("CHECKPOINT_WAIT_MS", 3000)?;
    if !(500..=3000).contains(&wait_ms) {
        anyhow::bail!(
            "CHECKPOINT_WAIT_MS {wait_ms} is outside 500 to 3000: the client's status timeout is built on the upper end"
        );
    }
    let urls = witness::normalize_urls(witness_urls());
    let log = Log::new(keys.log.clone(), log_key(&keys)?, Witnesses::new(policy));
    eprintln!("log key {}", log.key.vkey());
    for w in log.witnesses.keys() {
        eprintln!("manifest witness {}", w.vkey());
    }
    for url in &urls {
        eprintln!("pushing checkpoints to {url}");
    }
    if urls.len() < log.witnesses.quorum {
        eprintln!(
            "WARNING: the manifest requires {} witness cosignatures but WITNESS_URLS lists {} witnesses; clients will raise a log alarm",
            log.witnesses.quorum,
            urls.len()
        );
    }
    witness_refresh(&manifest, !urls.is_empty())?;
    publish_manifest(&db, &manifest).await?;
    let company = Endorsement::sign(&keys.manifest, manifest.hash());
    eprintln!("company key {}", company.key.fingerprint());
    eprintln!("CA {}", keys.ca.fingerprint);
    if auto_approve {
        eprintln!("AUTO_APPROVE=true: enrolled devices are approved without IT");
    }
    let retention = &manifest.body().claim_retention;
    let sealed = claims::seal_plaintext(&db, &kek, manifest.hash(), retention).await?;
    if sealed > 0 {
        eprintln!("sealed {sealed} plaintext claims from an earlier version");
    }
    eprintln!(
        "claim_retention {retention}: database backups hold sealed month keys, so a backup made \
         before a purge still decrypts its claims with the KEK until the backup expires; keep \
         database backups only as long as device owners were told"
    );
    let dated = claims::set_missing_deadlines(&db, &kek, manifest.hash(), retention).await?;
    if dated > 0 {
        eprintln!(
            "gave {dated} claims from an earlier version a deadline: {retention} after receipt \
             under the current manifest, due now under any other manifest"
        );
    }
    tokio::spawn(delete_expired_nonces(db.clone()));
    let siem = siem::from_env(&manifest);
    let enforced = Arc::new(Enforced {
        siem,
        manifest: Arc::new(manifest),
        toml: toml.into(),
        company,
        log: Arc::new(log),
        version: active.map(|row| row.version),
        revision: 0,
    });
    let current = Arc::new(RwLock::new(enforced.clone()));
    let owners = Owners::start(
        urls,
        enforced.log.witnesses.keys().to_vec(),
        current.clone(),
        db.clone(),
        read_db.clone(),
        observe.clone(),
    )?;
    let app = App {
        enforced,
        current,
        owners: Arc::new(owners),
        wait: Duration::from_millis(wait_ms),
        db,
        read_db,
        keys: Arc::new(keys),
        auto_approve,
        limiter: Arc::new(limiter),
        nonce_limiter: Arc::new(nonce_limiter),
        max_nonces,
        kek: Arc::new(kek),
        observe,
    };
    tokio::spawn(enforce_retention(app.clone()));
    tokio::spawn(poll_manifest(app.clone()));
    tokio::spawn(refresh_cosignatures(app.clone()));
    let app = router(app);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let served = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;
    // The queued diagnostic lines are written before the process exits, for at most two seconds.
    let _ = tokio::task::spawn_blocking(|| diag::shutdown(diag::SHUTDOWN_WAIT)).await;
    served?;
    Ok(())
}

async fn log_entries(
    db: &PgPool,
    from: u64,
    limit: u64,
    output: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let to = from
        .checked_add(limit)
        .ok_or_else(|| anyhow::anyhow!("from + limit exceeds the log index range"))?;
    for entry in translog::range(&mut *db.acquire().await?, from, to).await? {
        serde_json::to_writer(&mut *output, &entry)?;
        writeln!(output)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::io::Write;

    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error) => match usage_error_line(&args, &error) {
            Some(line) => {
                let _ = writeln!(std::io::stdout(), "{line}");
                std::process::exit(2)
            }
            None => error.exit(),
        },
    };
    let json = cli.prints_json();
    match run(cli).await {
        Err(error) if json => {
            let _ = writeln!(
                std::io::stdout(),
                "{}",
                json!({ "error": format!("{error:#}") })
            );
            std::process::exit(1)
        }
        result => result,
    }
}

/// The claims commands only read, so they do not migrate. A schema older than this gateway fails
/// with a hint, and nothing is written.
async fn check_schema_current(db: &PgPool) -> anyhow::Result<()> {
    let table: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(db)
        .await?;
    let applied: Vec<i64> = if table {
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success")
            .fetch_all(db)
            .await?
    } else {
        Vec::new()
    };
    let older = sqlx::migrate!("./migrations")
        .migrations
        .iter()
        .any(|migration| !applied.contains(&migration.version));
    if older {
        anyhow::bail!(
            "the database schema is older than this gateway; start the gateway once to migrate it"
        );
    }
    Ok(())
}

/// The error line for a command line that does not parse, when it asked for JSON. Help and version
/// output, and the errors of a command line that did not ask for JSON, stay as clap prints them.
fn usage_error_line(args: &[std::ffi::OsString], error: &clap::Error) -> Option<String> {
    let asked = args
        .iter()
        .skip(1)
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--json");
    if !error.use_stderr() || !asked {
        return None;
    }
    let text = error.to_string();
    let first = text.split("\n\n").next().unwrap_or_default().trim();
    let first = first.strip_prefix("error: ").unwrap_or(first);
    Some(json!({ "error": first }).to_string())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let command = cli.command.unwrap_or(Command::Serve);
    // A bad pool size refuses startup before any connection is made.
    let read_connections = matches!(command, Command::Serve)
        .then(read_pool_connections)
        .transpose()?;
    let db = connect(&std::env::var("DATABASE_URL")?).await?;
    if matches!(command, Command::Claims { .. }) {
        check_schema_current(&db).await?;
    } else {
        sqlx::migrate!("./migrations").run(&db).await?;
    }
    match command {
        Command::Serve => serve(db, read_connections.unwrap_or(DEFAULT_READ_POOL)).await,
        Command::Invite {
            json,
            ttl,
            note,
            url,
        } => {
            invite(
                &db,
                &SealingKey::kek_from_env()?,
                &url,
                ttl,
                note.trim(),
                json,
                &mut std::io::stdout(),
            )
            .await
        }
        Command::Manifest { command } => manifests::run(&db, command).await,
        Command::Devices { command } => admin_devices(&db, command).await,
        Command::Claims { command } => {
            let startup = read_manifest().ok().map(|(_, _, manifest)| manifest);
            results::run(&db, &SealingKey::kek_from_env()?, startup.as_ref(), command).await
        }
        Command::Status { json } => {
            let manifest = match manifests::active(&db).await? {
                Some(row) => Manifest::parse(row.toml.as_bytes())?,
                None => read_manifest()?.2,
            };
            let document = status(
                &db,
                &SealingKey::kek_from_env()?,
                &manifest,
                env_flag("AUTO_APPROVE")?,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&document)?);
            } else {
                println!(
                    "version {}\nmanifest {}\ncompany key {}\nauto approve {}\ndevices: {} pending, {} approved, {} revoked",
                    document.version,
                    document.manifest_hash,
                    document.company_key_fingerprint,
                    document.auto_approve,
                    document.devices.pending,
                    document.devices.approved,
                    document.devices.revoked
                );
            }
            Ok(())
        }
        Command::Log {
            command: LogCommand::Entries { from, limit },
        } => log_entries(&db, from, limit, &mut std::io::stdout()).await,
    }
}

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = term.recv() => eprintln!("SIGTERM: finishing open requests"),
        _ = tokio::signal::ctrl_c() => eprintln!("SIGINT: finishing open requests"),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;

    const DEMO: &str = include_str!("../../../examples/manifest.toml");
    const TEST_KEK: [u8; 32] = [5; 32];

    /// Owners for `urls`, enforcing the keys of the snapshot in `current`.
    fn owners_for(
        current: &Arc<RwLock<Arc<Enforced>>>,
        db: &PgPool,
        read_db: &PgPool,
        urls: Vec<String>,
        observe: Option<Arc<metrics::Observation>>,
    ) -> Arc<Owners> {
        let keys = current.read().unwrap().log.witnesses.keys().to_vec();
        Arc::new(
            Owners::start(
                urls,
                keys,
                current.clone(),
                db.clone(),
                read_db.clone(),
                observe,
            )
            .unwrap(),
        )
    }

    fn tree_of(leaves: Vec<LogHash>) -> Tree {
        Tree {
            view: Arc::new(LogView {
                root: root(&leaves),
                cache: leaves.into_iter().collect(),
                roots: VecDeque::new(),
            }),
            revision: 0,
        }
    }

    async fn manifest_app(toml: &str) -> App {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&TEST_KEK);
        let keys = Keys::load_or_create(&db, &kek).await.unwrap();
        let enforced = Arc::new(manifests::enforced(toml, &keys, None).unwrap());
        let current = Arc::new(RwLock::new(enforced.clone()));
        let read_db = testdb::read_pool(&db, 2);
        App {
            owners: owners_for(&current, &db, &read_db, vec![], None),
            wait: Duration::from_secs(3),
            db,
            read_db,
            enforced,
            current,
            keys: Arc::new(keys),
            auto_approve: false,
            limiter: Arc::new(Limiter::new(100, Duration::from_secs(60), 100)),
            nonce_limiter: Arc::new(Limiter::new(100, Duration::from_secs(60), 100)),
            max_nonces: 10000,
            kek: Arc::new(kek),
            observe: None,
        }
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
    async fn manifest_reloads_keep_one_siem_sink() {
        let mut app = manifest_app(DEMO).await;
        let path =
            std::env::temp_dir().join(format!("open-pact-siem-{}.ndjson", std::process::id()));
        let sink = siem::Exporter::file_for_test(path);
        let mut enforced = manifests::enforced(DEMO, &app.keys, None).unwrap();
        enforced.siem = Some(sink.clone());
        app.enforced = Arc::new(enforced);
        *app.current.write().unwrap() = app.enforced.clone();
        let mut sinks = std::collections::HashSet::from([sink.sink_id()]);
        for toml in [DEMO.to_owned(), manifest_a(), DEMO.to_owned()] {
            manifests::set_for_test(&app.db, &app.keys, &toml).await;
            reload_manifest(&app).await.unwrap();
            let current = app.current.read().unwrap();
            let sink = current
                .siem
                .as_ref()
                .expect("reload keeps the configured sink");
            sinks.insert(sink.sink_id());
        }
        assert_eq!(sinks.len(), 1, "reload must not create another SIEM sink");
    }

    #[test]
    fn invalid_supplied_manifest_has_a_fixed_reason() {
        let enforced = Manifest::parse(DEMO.as_bytes()).unwrap();
        let signed = Manifest::parse(manifest_a().as_bytes()).unwrap();
        let reason = consented_manifest(
            &enforced,
            signed.hash(),
            Some("fictional_private_marker = \"fictional-private-value\"\n"),
        )
        .err()
        .unwrap();
        assert_eq!(reason, "manifest_toml is not a valid manifest");
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn invalid_supplied_manifest_does_not_store_parser_text() {
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let a = manifest_a();
        let owned = device_on(&db, &a).await;
        let claim = claim_under(&app, &owned.device, &a).await;
        let (status, _) = send_claim(
            &app,
            &owned.device,
            &claim,
            Some("fictional_private_marker = \"fictional-private-value\"\n"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let reasons: Vec<String> =
            sqlx::query_scalar("SELECT last_reasons FROM devices WHERE pseudonym = $1")
                .bind(owned.pseudonym.as_str())
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(reasons, ["manifest_toml is not a valid manifest"]);
        let listed = devices::list_json(&db).await.unwrap();
        assert!(!listed.contains("fictional_private_marker"), "{listed}");
        assert!(!listed.contains("fictional-private-value"), "{listed}");
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
    async fn witness_refresh_keeps_a_one_second_interval() {
        const CHILD: &str = "OPEN_PACT_TEST_WITNESS_REFRESH_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "tests::witness_refresh_keeps_a_one_second_interval",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("WITNESS_REFRESH_SECS", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let pushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = pushes.clone();
        let witness = Router::new().route(
            "/add-checkpoint",
            post(move || {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, witness).await.unwrap() });
        let mut app = manifest_app(DEMO).await;
        app.owners = owners_for(&app.current, &app.db, &app.read_db, vec![url], None);
        let refresh = tokio::spawn(refresh_cosignatures(app));
        let result = tokio::time::timeout(Duration::from_secs(4), async {
            while pushes.load(std::sync::atomic::Ordering::Relaxed) < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        refresh.abort();
        server.abort();
        let _ = refresh.await;
        let _ = server.await;
        assert!(
            result.is_ok(),
            "expected two witness pushes within four seconds, saw {}",
            pushes.load(std::sync::atomic::Ordering::Relaxed)
        );
    }

    /// Three mock witnesses: one fails, one refuses the proof, one is ahead. The app pushes to them.
    async fn app_with_broken_witnesses(
        observe: Option<Arc<metrics::Observation>>,
    ) -> (App, tokio::task::JoinHandle<()>) {
        let witness = Router::new()
            .route(
                "/failing/add-checkpoint",
                post(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route(
                "/refusing/add-checkpoint",
                post(|| async { (StatusCode::UNPROCESSABLE_ENTITY, "bad proof") }),
            )
            .route(
                "/ahead/add-checkpoint",
                post(|| async { (StatusCode::CONFLICT, "0") }),
            )
            .route("/empty/add-checkpoint", post(|| async { StatusCode::OK }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, witness).await.unwrap() });
        let mut app = manifest_app(DEMO).await;
        app.observe = observe.clone();
        let urls = ["failing", "refusing", "ahead", "empty"].map(|name| format!("{base}/{name}"));
        app.owners = owners_for(&app.current, &app.db, &app.read_db, urls.to_vec(), observe);
        (app, server)
    }

    /// Each add-checkpoint answer of a witness is counted under its own result.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
    async fn witness_pushes_are_counted_by_result() {
        let metrics = Arc::new(metrics::Metrics::new());
        let observation = metrics::Observation::new(Some(metrics.clone()), None);
        let (app, server) = app_with_broken_witnesses(observation).await;
        app.checkpoint(Mode::Enroll).await.unwrap();
        server.abort();
        let text = metrics.scrape(&app.db, &app.read_db);
        for result in ["error", "refused", "conflict", "invalid"] {
            let line = format!("openpact_witness_push_seconds_count{{result=\"{result}\"}} 1");
            assert!(text.contains(&line), "{result} missing: {text}");
        }
        assert!(!text.contains("result=\"cosigned\""), "{text}");
    }

    /// With observation off, the witness pushes and the checkpoint read no clock.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
    async fn witness_pushes_read_no_clock_when_observation_is_off() {
        let (app, server) = app_with_broken_witnesses(None).await;
        let before = metrics::clock_reads();
        app.checkpoint(Mode::Enroll).await.unwrap();
        server.abort();
        assert_eq!(metrics::clock_reads(), before);
    }

    /// With observation off, a claim, its nonce and its checkpoint read no clock.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
    async fn a_claim_reads_no_clock_when_observation_is_off() {
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let (key, claim) = enrolled_claim(&app, &db, DEMO).await;
        let before = metrics::clock_reads();
        let (status, body) = send_claim(&app, &key, &claim, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(metrics::clock_reads(), before);
    }

    /// The index of the one log entry of `kind`.
    async fn log_index_of(db: &sqlx::PgPool, kind: &str) -> i64 {
        sqlx::query_scalar("SELECT idx FROM log_entries WHERE kind = $1")
            .bind(kind)
            .fetch_one(db)
            .await
            .unwrap()
    }

    /// An enrolment that the gateway approves by itself sends one approved `device_state` event
    /// after it commits, with the note of the invitation it used.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn an_auto_approved_enrolment_sends_one_approved_event() {
        let sink = std::env::temp_dir().join(format!(
            "open-pact-auto-approve-{:032x}.ndjson",
            rand::random::<u128>()
        ));
        let (app, db) = test_app_configured(
            DEMO,
            100,
            100,
            10,
            true,
            Some(siem::Exporter::file_for_test(sink.clone())),
        )
        .await;
        let manifest = Manifest::parse(DEMO.as_bytes()).unwrap();
        let mut tx = db.begin().await.unwrap();
        translog::append(
            &mut tx,
            EntryKind::ManifestPublished,
            json!({"manifest": manifest.hash().as_str()}),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let keys = Keys::load_or_create(&db, &SealingKey::new(&TEST_KEK))
            .await
            .unwrap();
        let owner = open_pact_core::dev_key::generate();
        let device_key = open_pact_core::dev_key::generate();
        let note = "Laptop, Example Person";
        let (code, _) = invitations::create(&db, time::Duration::hours(1), note)
            .await
            .unwrap();
        let signed = open_pact_core::SignedManifest {
            toml: DEMO.into(),
            company: Endorsement::sign(&keys.manifest, manifest.hash()),
            owner: Endorsement::sign(&owner, manifest.hash()),
        };
        let request = EnrolRequest::sign(signed, code, &owner, &device_key).unwrap();
        let (status, body) =
            post_json(&app, "/v1/enroll", &serde_json::to_value(request).unwrap()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["state"], "approved");

        // The exporter delivers on its own thread, so wait for the whole first line.
        let text = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let text = std::fs::read_to_string(&sink).unwrap_or_default();
                if text.ends_with('\n') {
                    return text;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the SIEM exporter delivers the event");
        let _ = std::fs::remove_file(&sink);
        let sent: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(sent.len(), 1, "{sent:?}");
        let event = &sent[0]["open_pact"];
        assert_eq!(event["event"], "device_state");
        assert_eq!(event["state"], "approved");
        assert_eq!(
            event["device_pseudonym"],
            Pseudonym::of(&PublicKey::from(&device_key)).as_str()
        );
        assert_eq!(event["device_note"], note);
        // The event names the DeviceApproved entry that the enrolment wrote.
        assert_eq!(
            event["log_index"],
            log_index_of(&db, "device_approved").await
        );
    }

    /// `devices approve` and `devices revoke` send one `device_state` event for a change and none for
    /// an action that changes nothing. The child process reads `GATEWAY_SIEM_FILE` as the CLI does.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn device_commands_send_one_event_per_real_change() {
        const CHILD: &str = "OPEN_PACT_TEST_DEVICE_EVENTS_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let sink = std::env::temp_dir().join(format!(
                "open-pact-device-events-{:032x}.ndjson",
                rand::random::<u128>()
            ));
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "tests::device_commands_send_one_event_per_real_change",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("GATEWAY_SIEM_FILE", &sink)
                .output()
                .unwrap();
            let _ = std::fs::remove_file(&sink);
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let sink = std::path::PathBuf::from(std::env::var_os("GATEWAY_SIEM_FILE").unwrap());
        let events = || -> Vec<Value> {
            std::fs::read_to_string(&sink)
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        };
        let db = testdb::fresh().await;
        let manifest = format!("sha256:{}", "ab".repeat(32));
        let device = format!("pseudonym:{}", "01".repeat(32));
        testdb::enrolled_device(&db, &device, &manifest).await;
        let invitation = format!("sha256:{}", "cd".repeat(32));
        sqlx::query("INSERT INTO invitations (hash, note, expires_at) VALUES ($1, 'Laptop, Example Person', now() + interval '1 day')")
            .bind(&invitation)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("UPDATE devices SET state = 'pending', invitation = $1 WHERE pseudonym = $2")
            .bind(&invitation)
            .bind(&device)
            .execute(&db)
            .await
            .unwrap();
        let approve = || DevicesCommand::Approve {
            prefix: "01010101".into(),
        };
        let revoke = || DevicesCommand::Revoke {
            pseudonym: device.clone(),
        };

        admin_devices(&db, approve()).await.unwrap();
        let sent = events();
        assert_eq!(sent.len(), 1, "{sent:?}");
        let body = &sent[0]["open_pact"];
        assert_eq!(body["event"], "device_state");
        assert_eq!(body["state"], "approved");
        assert_eq!(body["device_pseudonym"], device);
        assert_eq!(body["device_note"], "Laptop, Example Person");
        let approved_index = log_index_of(&db, "device_approved").await;
        assert_eq!(body["log_index"], approved_index);

        // The command refuses a device that is no longer pending. The change itself is a no-op.
        assert!(admin_devices(&db, approve()).await.is_err());
        let again = devices::apply(&db, &device, Action::Approve).await.unwrap();
        assert!(again.change.is_none());
        assert_eq!(events().len(), 1);

        admin_devices(&db, revoke()).await.unwrap();
        let sent = events();
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert_eq!(sent[1]["open_pact"]["state"], "revoked");
        // Revocation is logged after approval, so its event orders after the approval's.
        let revoked_index = log_index_of(&db, "device_revoked").await;
        assert_eq!(sent[1]["open_pact"]["log_index"], revoked_index);
        assert!(
            revoked_index > approved_index,
            "{revoked_index} <= {approved_index}"
        );

        admin_devices(&db, revoke()).await.unwrap();
        assert_eq!(events().len(), 2);
    }

    /// R4-L2: `invite --ttl` is checked where the command line is read, before any database or
    /// key is touched, and bad input is an error message, never a panic.
    #[test]
    fn invite_refuses_a_bad_ttl_on_the_command_line() {
        let invite = |ttl: &str| {
            Cli::try_parse_from([
                "open-pact-gateway",
                "invite",
                &format!("--ttl={ttl}"),
                "--url=https://pact.example.com",
            ])
        };
        assert!(invite("7d").is_ok());
        for bad in ["", "é", "9223372036854775807d", "-5h", "FICTIONAL"] {
            let Err(err) = invite(bad) else {
                panic!("{bad:?} accepted");
            };
            assert!(err.to_string().contains("TTL"), "{bad:?}: {err}");
        }
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
    async fn reloaded_manifest_requires_an_old_device_to_accept() {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&TEST_KEK);
        let keys = Keys::load_or_create(&db, &kek).await.unwrap();
        let old = manifest_a();
        let enforced = Arc::new(manifests::enforced(&old, &keys, None).unwrap());
        let current = Arc::new(RwLock::new(enforced.clone()));
        let read_db = testdb::read_pool(&db, 2);
        let app = App {
            owners: owners_for(&current, &db, &read_db, vec![], None),
            wait: Duration::from_secs(3),
            db: db.clone(),
            read_db,
            enforced,
            current,
            keys: Arc::new(keys),
            auto_approve: false,
            limiter: Arc::new(Limiter::new(100, Duration::from_secs(60), 100)),
            nonce_limiter: Arc::new(Limiter::new(100, Duration::from_secs(60), 100)),
            max_nonces: 10000,
            kek: Arc::new(kek),
            observe: None,
        };
        let router = router(app.clone());
        let (key, _) = enrolled_claim(&router, &db, &old).await;
        manifests::set_for_test(&db, &app.keys, DEMO).await;
        reload_manifest(&app).await.unwrap();
        let response = router
            .clone()
            .oneshot(Request::get("/v1/manifest").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let document: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["toml"], DEMO);
        let claim = fresh_claim(&router, &key, &Manifest::parse(old.as_bytes()).unwrap()).await;
        let (_, body) = send_claim(&router, &key, &claim, None).await;
        assert!(
            body.to_string().contains("open-pact-client accept"),
            "{body}"
        );
        let status = status(&db, &app.kek, &app.manifest, false).await.unwrap();
        assert_eq!(status.manifest_source, "database");
        assert_eq!(status.manifest_version, Some(1));
        assert_eq!(
            status.manifest_hash,
            Manifest::parse(DEMO.as_bytes()).unwrap().hash().as_str()
        );
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn closed_log_routes_and_operator_entries() {
        let (app, db) = test_app_with(DEMO, 100, 100).await;
        let mut conn = db.acquire().await.unwrap();
        let first = translog::append(
            &mut conn,
            EntryKind::ManifestPublished,
            json!({"manifest":"fictional"}),
        )
        .await
        .unwrap();
        let second = translog::append(
            &mut conn,
            EntryKind::DeviceEnrolled,
            json!({"commitment":"fictional"}),
        )
        .await
        .unwrap();
        drop(conn);
        for (path, expected) in [
            ("/v1/log/entries", StatusCode::NOT_FOUND),
            ("/v1/log/proof/inclusion?index=0", StatusCode::NOT_FOUND),
            ("/v1/log/key", StatusCode::OK),
            ("/v1/log/checkpoint", StatusCode::OK),
            ("/v1/log/proof/consistency?from=1", StatusCode::OK),
        ] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{path}");
        }
        let cli = Cli::try_parse_from([
            "open-pact-gateway",
            "log",
            "entries",
            "--from",
            "1",
            "--limit",
            "1",
        ])
        .unwrap();
        let Some(Command::Log {
            command: LogCommand::Entries { from, limit },
        }) = cli.command
        else {
            panic!("log entries command")
        };
        let mut output = Vec::new();
        log_entries(&db, from, limit, &mut output).await.unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("{}\n", serde_json::to_string(&second).unwrap())
        );
        let mut output = Vec::new();
        log_entries(&db, 0, 256, &mut output).await.unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&first).unwrap(),
                serde_json::to_string(&second).unwrap()
            )
        );
        assert!(
            log_entries(&db, u64::MAX, 1, &mut Vec::new())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn public_summary_page_does_not_show_counts() {
        let (app, _) = test_app_with(DEMO, 100, 100).await;
        let response = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        for label in [
            "devices approved",
            "stored claims allowed",
            "stored claims denied",
        ] {
            assert!(!page.contains(label), "public page contains {label}");
        }
        assert!(page.contains("Transparency log checkpoint"));
    }

    async fn test_app(enrol_limit: u32, nonce_limit: u32) -> Router {
        test_app_with(DEMO, enrol_limit, nonce_limit).await.0
    }

    async fn test_app_with(toml: &str, enrol_limit: u32, nonce_limit: u32) -> (Router, PgPool) {
        test_app_with_pool_limit(toml, enrol_limit, nonce_limit, 10).await
    }

    async fn test_app_with_pool_limit(
        toml: &str,
        enrol_limit: u32,
        nonce_limit: u32,
        max_connections: u32,
    ) -> (Router, PgPool) {
        test_app_configured(toml, enrol_limit, nonce_limit, max_connections, false, None).await
    }

    async fn test_app_configured(
        toml: &str,
        enrol_limit: u32,
        nonce_limit: u32,
        max_connections: u32,
        auto_approve: bool,
        siem: Option<siem::Exporter>,
    ) -> (Router, PgPool) {
        test_app_observed(
            toml,
            enrol_limit,
            nonce_limit,
            max_connections,
            auto_approve,
            siem,
            None,
        )
        .await
    }

    async fn test_app_observed(
        toml: &str,
        enrol_limit: u32,
        nonce_limit: u32,
        max_connections: u32,
        auto_approve: bool,
        siem: Option<siem::Exporter>,
        observe: Option<Arc<metrics::Observation>>,
    ) -> (Router, PgPool) {
        let db = testdb::fresh_with_max_connections(max_connections).await;
        let kek = SealingKey::new(&TEST_KEK);
        let keys = Keys::load_or_create(&db, &kek).await.unwrap();
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        let log_key = LogKey::new("log.example.org/test", &PublicKey::from(&keys.log));
        // A manifest that lists the demo witness gets a healthy fake one for the whole test.
        let mut urls = vec![];
        if manifest
            .body()
            .log
            .as_ref()
            .is_some_and(|p| p.witnesses.iter().any(|w| w.name == testwitness::DEMO_NAME))
        {
            let witness = testwitness::FakeWitness::demo(&log_key).await;
            urls.push(witness.url.clone());
            std::mem::forget(witness);
        }
        let log = Log::new(
            keys.log.clone(),
            log_key,
            Witnesses::new(manifest.body().log.as_ref()),
        );
        let minute = Duration::from_secs(60);
        let enforced = Arc::new(Enforced {
            siem,
            company: Endorsement::sign(&keys.manifest, manifest.hash()),
            manifest: Arc::new(manifest),
            toml: toml.into(),
            log: Arc::new(log),
            version: None,
            revision: 0,
        });
        let current = Arc::new(RwLock::new(enforced.clone()));
        let read_db = testdb::read_pool(&db, max_connections.min(2));
        let app = router(App {
            owners: owners_for(&current, &db, &read_db, urls, observe.clone()),
            wait: Duration::from_secs(3),
            enforced,
            current,
            db: db.clone(),
            read_db,
            keys: Arc::new(keys),
            auto_approve,
            limiter: Arc::new(Limiter::new(enrol_limit, minute, 100)),
            nonce_limiter: Arc::new(Limiter::new(nonce_limit, minute, 100)),
            max_nonces: 10_000,
            kek: Arc::new(kek),
            observe,
        });
        (app, db)
    }

    async fn observed_app(nonce_limit: u32) -> (Router, PgPool, Arc<metrics::Metrics>) {
        let metrics = Arc::new(metrics::Metrics::new());
        let observation = metrics::Observation::new(Some(metrics.clone()), None);
        let (app, db) =
            test_app_observed(DEMO, 10, nonce_limit, 10, false, None, observation).await;
        (app, db, metrics)
    }

    fn class(status: StatusCode) -> String {
        format!("{}xx", status.as_u16() / 100)
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
    async fn a_claim_and_a_reused_nonce_are_counted_by_status_class_and_stage() {
        let (app, db, metrics) = observed_app(100).await;
        let (key, claim) = enrolled_claim(&app, &db, DEMO).await;
        let (first, body) = send_claim(&app, &key, &claim, None).await;
        assert_eq!(first, StatusCode::OK, "{body}");
        let (second, _) = send_claim(&app, &key, &claim, None).await;
        assert_eq!(second, StatusCode::FORBIDDEN);
        let text = metrics.scrape(&db, &db);
        let count = |route: &str, status: &str| {
            format!(
                "openpact_http_request_duration_seconds_count{{route=\"{route}\",method=\"POST\",status=\"{status}\"}}"
            )
        };
        assert!(
            text.contains(&format!("{} 1", count("/v1/claim", &class(first)))),
            "{text}"
        );
        assert!(
            text.contains(&format!("{} 1", count("/v1/claim", &class(second)))),
            "{text}"
        );
        assert!(
            text.contains(&format!("{} 1", count("/v1/nonce", "2xx"))),
            "{text}"
        );
        for stage in [
            "verify",
            "nonce",
            "begin",
            "lock",
            "evaluate",
            "commit",
            "siem",
            "checkpoint",
        ] {
            assert!(
                text.contains(&format!(
                    "openpact_claim_stage_seconds_count{{stage=\"{stage}\"}}"
                )),
                "stage {stage} missing: {text}"
            );
        }
        // The demo manifest asks for a witness quorum and no witness is configured.
        assert!(
            text.contains(
                "openpact_checkpoint_served_total{caller=\"claim\",result=\"not_yet\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains("openpact_nonce_issue_total{result=\"issued\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("openpact_nonce_lock_wait_seconds_count 1"),
            "{text}"
        );
        assert!(
            text.contains("openpact_db_acquire_seconds_count{site=\"nonce_tx\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("openpact_db_acquire_seconds_count{site=\"claim_tx\"} 1"),
            "{text}"
        );
        assert!(text.contains("openpact_db_pool_max 10"), "{text}");
        assert!(text.contains("openpact_log_size "), "{text}");
        assert!(!text.contains("aborted_total{"), "{text}");
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
    async fn a_nonce_request_over_the_limit_is_counted_as_rate_limited() {
        let (app, db, metrics) = observed_app(1).await;
        assert_eq!(
            post_json(&app, "/v1/nonce", &Value::Null).await.0,
            StatusCode::OK
        );
        assert_eq!(
            post_json(&app, "/v1/nonce", &Value::Null).await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
        let text = metrics.scrape(&db, &db);
        assert!(
            text.contains("openpact_nonce_issue_total{result=\"issued\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("openpact_nonce_issue_total{result=\"rate_limited\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("route=\"/v1/nonce\",method=\"POST\",status=\"4xx\"} 1"),
            "{text}"
        );
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
    async fn the_public_router_has_no_metrics_path_and_without_observation_it_records_nothing() {
        let (observed, _db, _metrics) = observed_app(100).await;
        let (plain, _db) = test_app_with(DEMO, 10, 100).await;
        for app in [&observed, &plain] {
            let request = Request::get("/metrics").body(Body::empty()).unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        assert_eq!(
            post_json(&plain, "/v1/nonce", &Value::Null).await.0,
            StatusCode::OK
        );
    }

    async fn post_json(app: &Router, path: &str, body: &Value) -> (StatusCode, Value) {
        let mut req = Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 7], 40000))));
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// An approved device under `toml` and a compliant claim from it with a fresh nonce.
    async fn enrolled_claim(app: &Router, db: &PgPool, toml: &str) -> (SigningKey, Claim) {
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        let key = open_pact_core::dev_key::generate();
        let device = Pseudonym::of(&PublicKey::from(&key));
        testdb::enrolled_device(db, device.as_str(), manifest.hash().as_str()).await;
        let claim = fresh_claim(app, &key, &manifest).await;
        (key, claim)
    }

    /// A compliant claim under the demo manifest from `key`, made for `manifest`, with a fresh nonce.
    async fn fresh_claim(app: &Router, key: &SigningKey, manifest: &Manifest) -> Claim {
        let device_key = PublicKey::from(key);
        let device = Pseudonym::of(&device_key);
        let (_, nonce) = post_json(app, "/v1/nonce", &Value::Null).await;
        Claim {
            manifest: manifest.hash().clone(),
            device,
            device_key,
            nonce: nonce["nonce"].as_str().unwrap().into(),
            time: OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
                .unwrap(),
            client: "open-pact-client 0.0.1".into(),
            os: open_pact_core::Os::Linux,
            trust_level: open_pact_core::TrustLevel::L0,
            virtualized: Some(open_pact_core::Virtualized::No),
            results: [
                ("disk_encryption", "full"),
                ("firewall", "on"),
                ("screen_lock", "le_5min"),
                ("os_supported", "yes"),
                ("antimalware_active", "yes"),
                ("preboot_auth", "user_secret"),
                ("os_auto_updates", "on"),
                ("antimalware_realtime", "on"),
                ("process_audit", "n/a"),
                ("remote_wipe", "n/a"),
                ("powershell_logging", "n/a"),
                ("log_cleared", "n/a"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into()))
            .chain([
                ("os_patch_age_days".into(), 14.into()),
                ("antimalware_signature_age_days".into(), 0.into()),
                ("managed_repos_outside".into(), 0.into()),
                ("password_min_length".into(), 12.into()),
            ])
            .collect(),
            csr_sha256: None,
            log_checkpoint: None,
        }
    }

    async fn auth_request(app: &Router, key: &SigningKey, purpose: DeviceAuthPurpose) -> Value {
        let (_, nonce) = post_json(app, "/v1/nonce", &Value::Null).await;
        let nonce = nonce["nonce"].as_str().unwrap().to_string();
        let device_key = PublicKey::from(key);
        let pseudonym = Pseudonym::of(&device_key);
        let statement = open_pact_core::device_auth_statement(purpose, &pseudonym, &nonce);
        serde_json::to_value(MyEntriesRequest {
            pseudonym,
            nonce,
            device_key,
            signature: open_pact_core::Signature::sign(key, &statement),
        })
        .unwrap()
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn concurrent_log_mine_requests_do_not_exhaust_the_pool() {
        let (app, db) = test_app_with_pool_limit(DEMO, 100, 100, 1).await;
        let manifest = Manifest::parse(DEMO.as_bytes()).unwrap();
        let mut tx = db.begin().await.unwrap();
        translog::append(
            &mut tx,
            EntryKind::ManifestPublished,
            json!({"manifest": manifest.hash().as_str()}),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let mut devices = Vec::new();
        for _ in 0..20 {
            let key = open_pact_core::dev_key::generate();
            let pseudonym = Pseudonym::of(&PublicKey::from(&key));
            testdb::enrolled_device(&db, pseudonym.as_str(), manifest.hash().as_str()).await;
            devices.push((key, pseudonym));
        }
        let mut tx = db.begin().await.unwrap();
        for (_, pseudonym) in &devices {
            let commitment = devices::commitment("00", pseudonym.as_str()).unwrap();
            for kind in [EntryKind::DeviceEnrolled, EntryKind::DeviceApproved] {
                translog::append(&mut tx, kind, json!({"commitment": commitment}))
                    .await
                    .unwrap();
            }
        }
        tx.commit().await.unwrap();

        let mut requests = Vec::new();
        for (key, _) in devices {
            requests.push(auth_request(&app, &key, DeviceAuthPurpose::LogMine).await);
        }

        let mut tasks = tokio::task::JoinSet::new();
        for request in requests {
            let app = app.clone();
            tasks.spawn(async move { post_json(&app, "/v1/log/mine", &request).await });
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!tasks.is_empty(), "log requests must still be in flight");
        let nonce = tokio::time::timeout(
            Duration::from_secs(5),
            post_json(&app, "/v1/nonce", &Value::Null),
        )
        .await
        .expect("nonce endpoint must remain available during log requests");
        assert_eq!(nonce.0, StatusCode::OK);

        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(result) = tasks.join_next().await {
                let (status, body) = result.unwrap();
                assert_eq!(status, StatusCode::OK, "{body}");
            }
        })
        .await
        .expect("all log requests must complete promptly");
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn own_log_is_isolated_and_status_is_private() {
        let (app, db) = test_app_with(DEMO, 100, 100).await;
        let (first, first_claim) = enrolled_claim(&app, &db, DEMO).await;
        let (second, second_claim) = enrolled_claim(&app, &db, DEMO).await;
        sqlx::query("DELETE FROM devices")
            .execute(&db)
            .await
            .unwrap();
        let mut tx = db.begin().await.unwrap();
        translog::append(
            &mut tx,
            EntryKind::ManifestPublished,
            json!({"manifest": first_claim.manifest.as_str()}),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let keys = Keys::load_or_create(&db, &SealingKey::new(&TEST_KEK))
            .await
            .unwrap();
        let mut private_values = Vec::new();
        for key in [&first, &second] {
            let owner = open_pact_core::dev_key::generate();
            let note = "private owner at example.org";
            let (code, _) = invitations::create(&db, time::Duration::hours(1), note)
                .await
                .unwrap();
            private_values.extend([
                note.to_string(),
                code.hash().to_string(),
                String::from(code.clone()),
            ]);
            let signed = open_pact_core::SignedManifest {
                toml: DEMO.into(),
                company: Endorsement::sign(&keys.manifest, &first_claim.manifest),
                owner: Endorsement::sign(&owner, &first_claim.manifest),
            };
            let request = EnrolRequest::sign(signed, code, &owner, key).unwrap();
            let (status, body) =
                post_json(&app, "/v1/enroll", &serde_json::to_value(request).unwrap()).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            devices::apply(
                &db,
                Pseudonym::of(&PublicKey::from(key)).as_str(),
                devices::Action::Approve,
            )
            .await
            .unwrap();
        }
        for (key, own, other) in [
            (&first, &first_claim, &second_claim),
            (&second, &second_claim, &first_claim),
        ] {
            let request = auth_request(&app, key, DeviceAuthPurpose::LogMine).await;
            let (status, response) = post_json(&app, "/v1/log/mine", &request).await;
            assert_eq!(status, StatusCode::OK, "{response}");
            let mine: MyEntries = serde_json::from_value(response.clone()).unwrap();
            let cp = LogKey::new("log.example.org/test", &PublicKey::from(&keys.log))
                .verify(&Note::parse(&mine.checkpoint).unwrap())
                .unwrap();
            let salt: String = sqlx::query_scalar("SELECT salt FROM devices WHERE pseudonym = $1")
                .bind(own.device.as_str())
                .fetch_one(&db)
                .await
                .unwrap();
            let other_salt: String =
                sqlx::query_scalar("SELECT salt FROM devices WHERE pseudonym = $1")
                    .bind(other.device.as_str())
                    .fetch_one(&db)
                    .await
                    .unwrap();
            let own = devices::commitment(&salt, own.device.as_str()).unwrap();
            let other = devices::commitment(&other_salt, other.device.as_str()).unwrap();
            assert_eq!(mine.device.len(), 2);
            assert!(!response.to_string().contains(&other));
            assert!(!response.to_string().contains("invitation"));
            for value in &private_values {
                assert!(!response.to_string().contains(value));
            }
            for item in &mine.device {
                assert_eq!(item.entry.data["commitment"], own);
            }
            for item in std::iter::once(&mine.manifest).chain(&mine.device) {
                open_pact_core::verify_inclusion(
                    &item.entry.leaf_hash(),
                    item.entry.index,
                    cp.size,
                    &item.proof,
                    &cp.root,
                )
                .unwrap();
            }
            assert_eq!(
                post_json(&app, "/v1/log/mine", &request).await.0,
                StatusCode::FORBIDDEN
            );
        }
        let mut denial = None;
        for state in ["pending", "approved", "revoked"] {
            sqlx::query("UPDATE devices SET state = $1 WHERE pseudonym = $2")
                .bind(state)
                .bind(first_claim.device.as_str())
                .execute(&db)
                .await
                .unwrap();
            let request = auth_request(&app, &first, DeviceAuthPurpose::DeviceStatus).await;
            let (status, body) = post_json(&app, "/v1/device/status", &request).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, json!({"state": state}));
            if state != "approved" {
                let request = auth_request(&app, &first, DeviceAuthPurpose::LogMine).await;
                let (status, body) = post_json(&app, "/v1/log/mine", &request).await;
                assert_eq!(status, StatusCode::FORBIDDEN);
                if let Some(previous) = &denial {
                    assert_eq!(&body, previous);
                }
                denial = Some(body);
            }
        }
        let unknown = open_pact_core::dev_key::generate();
        for path in ["/v1/log/mine", "/v1/device/status"] {
            let purpose = if path == "/v1/log/mine" {
                DeviceAuthPurpose::LogMine
            } else {
                DeviceAuthPurpose::DeviceStatus
            };
            let request = auth_request(&app, &unknown, purpose).await;
            let (status, body) = post_json(&app, path, &request).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(Some(body), denial);
        }
        for (path, wrong_purpose) in [
            ("/v1/log/mine", DeviceAuthPurpose::DeviceStatus),
            ("/v1/device/status", DeviceAuthPurpose::LogMine),
        ] {
            let request = auth_request(&app, &second, wrong_purpose).await;
            assert_eq!(
                post_json(&app, path, &request).await.0,
                StatusCode::FORBIDDEN
            );
            let mut request = auth_request(&app, &second, wrong_purpose).await;
            request["signature"] = open_pact_core::sign_claim(&second_claim, &second)
                .unwrap()
                .into();
            assert_eq!(
                post_json(&app, path, &request).await.0,
                StatusCode::FORBIDDEN
            );
        }
    }

    const PASSWORD_RULE: &str = r#"[[control]]
id = "password_min_length"
source = "company_policy"
check = "builtin:password_min_length@1"
output = { integer = { min = 0, max = 2147483647 }, values = ["none"] }
required = { macos = { min = 10 }, windows = { min = 10 }, linux = { min = 10 } }
grace = "1d"
"#;

    /// Manifest A: the demo before IT added the password rule, with claims kept for 6 months.
    fn manifest_a() -> String {
        let toml = DEMO
            .replace(PASSWORD_RULE, "")
            .replace(r#"claim_retention = "12mo""#, r#"claim_retention = "6mo""#);
        assert!(!toml.contains("password_min_length") && toml.contains(r#""6mo""#));
        toml
    }

    struct Owned {
        device: SigningKey,
        owner: SigningKey,
        pseudonym: Pseudonym,
    }

    /// An approved device enrolled under `toml` by a real owner key.
    async fn device_on(db: &PgPool, toml: &str) -> Owned {
        let (device, owner) = (
            open_pact_core::dev_key::generate(),
            open_pact_core::dev_key::generate(),
        );
        let pseudonym = Pseudonym::of(&PublicKey::from(&device));
        let hash = Manifest::parse(toml.as_bytes()).unwrap().hash().clone();
        sqlx::query(
            "INSERT INTO devices (pseudonym, manifest_hash, owner_key, owner_signature, salt, state) \
             VALUES ($1, $2, $3, $4, '00', 'approved')",
        )
        .bind(pseudonym.as_str())
        .bind(hash.as_str())
        .bind(serde_json::to_value(PublicKey::from(&owner)).unwrap())
        .bind(String::from(Endorsement::sign(&owner, &hash).signature))
        .execute(db)
        .await
        .unwrap();
        Owned {
            device,
            owner,
            pseudonym,
        }
    }

    /// A claim under manifest `toml` that reports only the controls `toml` lists.
    async fn claim_under(app: &Router, device: &SigningKey, toml: &str) -> Claim {
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        let mut claim = fresh_claim(app, device, &manifest).await;
        claim
            .results
            .retain(|id, _| manifest.body().control(id).is_some());
        claim
    }

    async fn send_claim(
        app: &Router,
        device: &SigningKey,
        claim: &Claim,
        toml: Option<&str>,
    ) -> (StatusCode, Value) {
        let jws = open_pact_core::sign_claim(claim, device).unwrap();
        post_json(
            app,
            "/v1/claim",
            &json!({"jws": jws, "manifest_toml": toml}),
        )
        .await
    }

    async fn accept_request(app: &Router, owned: &Owned, previous: &str) -> AcceptRequest {
        let (_, nonce) = post_json(app, "/v1/nonce", &Value::Null).await;
        AcceptRequest::sign_with(
            Manifest::parse(previous.as_bytes()).unwrap().hash().clone(),
            Manifest::parse(DEMO.as_bytes()).unwrap().hash().clone(),
            nonce["nonce"].as_str().unwrap().into(),
            &owned.owner,
            &PublicKey::from(&owned.device),
            |s| Ok::<_, open_pact_core::Error>(open_pact_core::Signature::sign(&owned.device, s)),
        )
        .unwrap()
    }

    async fn post_accept(app: &Router, req: &AcceptRequest) -> (StatusCode, Value) {
        post_json(
            app,
            "/v1/device/accept",
            &serde_json::to_value(req).unwrap(),
        )
        .await
    }

    async fn bound_hash(db: &PgPool, device: &Pseudonym) -> (String, String) {
        sqlx::query_as("SELECT manifest_hash, state FROM devices WHERE pseudonym = $1")
            .bind(device.as_str())
            .fetch_one(db)
            .await
            .unwrap()
    }

    fn demo_with(replacements: &[(&str, &str)]) -> Manifest {
        let mut toml = DEMO.to_string();
        for (from, to) in replacements {
            assert!(toml.contains(from), "{from} is not in the demo");
            toml = toml.replacen(from, to, 1);
        }
        Manifest::parse(toml.as_bytes()).unwrap()
    }

    fn at(text: &str) -> OffsetDateTime {
        open_pact_core::timestamp::parse_rfc3339(text).unwrap()
    }

    /// The demo sends every 55 minutes on the VPN, so its certificate lasts 110 minutes.
    #[test]
    fn the_certificate_lasts_twice_the_vpn_interval() {
        let now = at("2026-11-17T09:00:00Z");
        assert_eq!(
            certificate_expiry(&demo_with(&[]), None, now),
            Some(now + time::Duration::minutes(110))
        );
    }

    #[test]
    fn claim_max_age_bounds_the_certificate() {
        let now = at("2026-11-17T09:00:00Z");
        let short = demo_with(&[("claim_max_age = \"24h\"", "claim_max_age = \"1h\"")]);
        assert_eq!(
            certificate_expiry(&short, None, now),
            Some(now + time::Duration::hours(1))
        );
    }

    #[test]
    fn a_day_bounds_the_certificate() {
        let now = at("2026-11-17T09:00:00Z");
        let long = demo_with(&[
            ("claim_max_age = \"24h\"", "claim_max_age = \"7d\""),
            ("interval = \"55m\"", "interval = \"24h\""),
        ]);
        assert_eq!(
            certificate_expiry(&long, None, now),
            Some(now + time::Duration::hours(24))
        );
    }

    #[test]
    fn the_nearest_grace_deadline_bounds_the_certificate() {
        let now = at("2026-11-17T09:00:00Z");
        let demo = demo_with(&[]);
        let deadline = now + time::Duration::minutes(25);
        assert_eq!(
            certificate_expiry(&demo, Some(deadline), now),
            Some(deadline)
        );
        assert_eq!(
            certificate_expiry(&demo, Some(now), now),
            None,
            "a deadline that has come gives no certificate"
        );
    }

    /// The end is whole seconds and one absolute time, so a clock reading with a fraction can never
    /// put it after the grace deadline.
    #[test]
    fn the_certificate_never_ends_after_the_grace_deadline() {
        let demo = demo_with(&[]);
        let now = at("2026-11-17T09:00:00.900Z");
        let deadline = at("2026-11-17T09:00:30.500Z");
        let end = certificate_expiry(&demo, Some(deadline), now).unwrap();
        assert_eq!(end, at("2026-11-17T09:00:30Z"));
        assert!(end <= deadline);
        assert_eq!(
            certificate_expiry(&demo, Some(now + time::Duration::milliseconds(50)), now),
            None,
            "less than a second of grace left gives no certificate"
        );
    }

    #[test]
    fn a_manifest_without_a_schedule_gives_claim_max_age_up_to_a_day() {
        let now = at("2026-11-17T09:00:00Z");
        let head = DEMO.split("\n[schedule]").next().unwrap();
        let without = Manifest::parse(head.as_bytes()).unwrap();
        assert_eq!(
            certificate_expiry(&without, None, now),
            Some(now + time::Duration::hours(24))
        );
    }

    #[test]
    fn the_warning_that_runs_out_first_sets_the_deadline() {
        let now = at("2026-11-17T09:00:00Z");
        let warning = |grace: open_pact_core::Grace| open_pact_core::Reason::NotAccepted {
            id: "firewall".into(),
            grace,
        };
        let left = |length: time::Duration| open_pact_core::Grace::Left(length);
        let allowed = open_pact_core::Decision::Allow {
            warnings: vec![
                warning(left(time::Duration::hours(3))),
                warning(left(time::Duration::minutes(40))),
            ],
        };
        assert_eq!(
            nearest_grace_deadline(&allowed, now),
            Some(now + time::Duration::minutes(40))
        );
        let endless = open_pact_core::Decision::Allow {
            warnings: vec![warning(left(open_pact_core::timestamp::MAX))],
        };
        assert_eq!(nearest_grace_deadline(&endless, now), None);
        let clean = open_pact_core::Decision::Allow { warnings: vec![] };
        assert_eq!(nearest_grace_deadline(&clean, now), None);
        let denied = open_pact_core::Decision::Deny {
            reasons: vec![warning(left(time::Duration::minutes(1)))],
        };
        assert_eq!(nearest_grace_deadline(&denied, now), None);
    }

    /// Sends a claim under DEMO with a certificate request, after it sets `results`.
    async fn send_with_csr(
        app: &Router,
        owned: &Owned,
        results: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let mut claim = claim_under(app, &owned.device, DEMO).await;
        for (id, value) in results {
            claim.results.insert(id.to_string(), (*value).into());
        }
        let (pem, der) = bare_csr();
        claim.csr_sha256 = Some(CsrHash::of(&der));
        let jws = open_pact_core::sign_claim(&claim, &owned.device).unwrap();
        post_json(app, "/v1/claim", &json!({"jws": jws, "csr_pem": pem})).await
    }

    fn certificate_end(body: &Value) -> OffsetDateTime {
        keys::certificate_not_after(body["certificate_pem"].as_str().expect("a certificate"))
            .unwrap()
    }

    /// A clean claim gets a certificate for twice the VPN interval. A failing control inside its
    /// grace gets one that ends at the grace deadline, and the device row keeps that end.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn a_certificate_ends_at_twice_the_vpn_interval_or_at_the_grace_deadline() {
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let owned = device_on(&db, DEMO).await;

        let (status, body) = send_with_csr(&app, &owned, &[]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let left = certificate_end(&body) - OffsetDateTime::now_utc();
        assert!(
            left > time::Duration::minutes(109) && left <= time::Duration::minutes(110),
            "a clean claim: {left}"
        );

        let (status, body) = send_with_csr(&app, &owned, &[("firewall", "off")]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["warnings"].to_string().contains("access ends in"),
            "{body}"
        );
        let left = certificate_end(&body) - OffsetDateTime::now_utc();
        assert!(
            left > time::Duration::minutes(109) && left <= time::Duration::minutes(110),
            "a warning with a day of grace left still gets the interval: {left}"
        );

        sqlx::query(
            "UPDATE control_failures SET first_failed_at = now() - interval '23 hours 30 minutes'",
        )
        .execute(&db)
        .await
        .unwrap();
        let (status, body) = send_with_csr(&app, &owned, &[("firewall", "off")]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let left = certificate_end(&body) - OffsetDateTime::now_utc();
        assert!(
            left > time::Duration::minutes(29) && left <= time::Duration::minutes(30),
            "the grace deadline is 30 minutes away: {left}"
        );
        let stored: Option<OffsetDateTime> =
            sqlx::query_scalar("SELECT last_access_until FROM devices WHERE pseudonym = $1")
                .bind(owned.pseudonym.as_str())
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(stored, Some(certificate_end(&body)));
    }

    /// IT shortens the send interval and the gateway enforces the new text. A device that has not
    /// accepted it still holds its enrolment under the old text, which the device signed. The
    /// certificate lasts twice the enforced interval, whatever interval the signed text holds.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn the_certificate_follows_the_enforced_schedule_not_the_signed_one() {
        let enforced = DEMO.replacen("interval = \"55m\"", "interval = \"5m\"", 1);
        assert_ne!(enforced, DEMO);
        let without_schedule = DEMO.split("\n[schedule]").next().unwrap().to_string();
        let (app, db) = test_app_with(&enforced, 10, 100).await;
        for (case, signed) in [
            ("a signed 55m schedule", manifest_a()),
            ("a signed manifest without a schedule", without_schedule),
        ] {
            let owned = device_on(&db, &signed).await;
            let mut claim = claim_under(&app, &owned.device, &signed).await;
            let (pem, der) = bare_csr();
            claim.csr_sha256 = Some(CsrHash::of(&der));
            let jws = open_pact_core::sign_claim(&claim, &owned.device).unwrap();
            let (status, body) = post_json(
                &app,
                "/v1/claim",
                &json!({"jws": jws, "csr_pem": pem, "manifest_toml": signed}),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{case}: {body}");
            let left = certificate_end(&body) - OffsetDateTime::now_utc();
            assert!(
                left > time::Duration::minutes(9) && left <= time::Duration::minutes(10),
                "{case}: the enforced 5m interval gives 10 minutes: {left}"
            );
        }
    }

    /// An accepted claim with no certificate ended its access when it was decided, so the device row
    /// records that time. A null end is left for rows written before the gateway kept it.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn an_accepted_claim_without_a_certificate_records_its_own_time_as_the_end() {
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let owned = device_on(&db, DEMO).await;
        let claim = claim_under(&app, &owned.device, DEMO).await;
        let (status, body) = send_claim(&app, &owned.device, &claim, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (at, until): (Option<OffsetDateTime>, Option<OffsetDateTime>) = sqlx::query_as(
            "SELECT last_claim_at, last_access_until FROM devices WHERE pseudonym = $1",
        )
        .bind(owned.pseudonym.as_str())
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(at.is_some());
        assert_eq!(until, at);
    }

    /// The gateway runs B, which adds a required control with grace 1d, and holds no copy of A.
    /// A device approved under A keeps working inside the grace, is denied after it, and after its
    /// owner accepts B it is on B, still approved, and compliant without a warning.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn an_approved_device_keeps_working_across_a_manifest_change_until_its_owner_accepts() {
        let (a, b) = (manifest_a(), Manifest::parse(DEMO.as_bytes()).unwrap());
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let owned = device_on(&db, &a).await;

        let mut claim = claim_under(&app, &owned.device, &a).await;
        let (pem, der) = bare_csr();
        claim.csr_sha256 = Some(CsrHash::of(&der));
        let jws = open_pact_core::sign_claim(&claim, &owned.device).unwrap();
        let (status, body) = post_json(
            &app,
            "/v1/claim",
            &json!({"jws": jws, "csr_pem": pem, "manifest_toml": a}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["certificate_pem"].is_string(),
            "a VPN certificate inside the grace"
        );
        let warnings = body["warnings"].to_string();
        for part in [
            "password_min_length",
            "open-pact-client accept",
            "access ends in",
        ] {
            assert!(warnings.contains(part), "{part} missing from {warnings}");
        }
        let (received, delete_after): (OffsetDateTime, OffsetDateTime) =
            sqlx::query_as("SELECT received_at, delete_after FROM claims")
                .fetch_one(&db)
                .await
                .unwrap();
        let kept = (delete_after - received).whole_days();
        assert!(
            (180..=185).contains(&kept),
            "a claim under A keeps A's 6mo retention, not B's 12mo: {kept} days"
        );

        sqlx::query("UPDATE control_failures SET first_failed_at = now() - interval '2 days'")
            .execute(&db)
            .await
            .unwrap();
        let mut claim = claim_under(&app, &owned.device, &a).await;
        let (pem, der) = bare_csr();
        claim.csr_sha256 = Some(CsrHash::of(&der));
        let jws = open_pact_core::sign_claim(&claim, &owned.device).unwrap();
        let (status, body) = post_json(
            &app,
            "/v1/claim",
            &json!({"jws": jws, "csr_pem": pem, "manifest_toml": a}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["reasons"].to_string().contains(
                "password_min_length is required by a new manifest that waits for your acceptance; run `open-pact-client accept`, grace 1d ended"
            ),
            "{body}"
        );
        assert!(
            body.get("certificate_pem").is_none(),
            "no VPN certificate after the grace"
        );

        let (status, body) = post_accept(&app, &accept_request(&app, &owned, &a).await).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            bound_hash(&db, &owned.pseudonym).await,
            (b.hash().to_string(), "approved".into())
        );
        let accepted: Vec<Value> =
            sqlx::query_scalar("SELECT data FROM log_entries WHERE kind = 'manifest_accepted'")
                .fetch_all(&db)
                .await
                .unwrap();
        assert_eq!(
            accepted,
            [json!({
                "commitment": devices::commitment("00", owned.pseudonym.as_str()).unwrap(),
                "manifest": b.hash(),
            })]
        );

        let claim = fresh_claim(&app, &owned.device, &b).await;
        let (status, body) = send_claim(&app, &owned.device, &claim, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["warnings"], json!([]));
    }

    /// Item 8: the gateway holds no copy of A. The device's copy works only if its hash is A's.
    /// Status and the private log answer for the device on A, with A's log entry.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn a_device_on_an_unknown_earlier_manifest_is_judged_by_the_text_it_signed() {
        let a = manifest_a();
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let owned = device_on(&db, &a).await;
        for (toml, expected) in [
            (None, "run `open-pact-client accept`"),
            (
                Some(DEMO.to_string()),
                "not the manifest this device signed",
            ),
            (
                Some(format!("{a}\n")),
                "not the manifest this device signed",
            ),
        ] {
            let claim = claim_under(&app, &owned.device, &a).await;
            let (status, body) = send_claim(&app, &owned.device, &claim, toml.as_deref()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            assert!(body["reasons"].to_string().contains(expected), "{body}");
        }
        assert_eq!(stored_text(&db).await.len(), 0);

        let a_hash = Manifest::parse(a.as_bytes()).unwrap().hash().clone();
        let mut tx = db.begin().await.unwrap();
        translog::append(
            &mut tx,
            EntryKind::ManifestPublished,
            json!({"manifest": a_hash.as_str()}),
        )
        .await
        .unwrap();
        let commitment = devices::commitment("00", owned.pseudonym.as_str()).unwrap();
        for kind in [EntryKind::DeviceEnrolled, EntryKind::DeviceApproved] {
            translog::append(&mut tx, kind, json!({"commitment": commitment}))
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        let request = auth_request(&app, &owned.device, DeviceAuthPurpose::DeviceStatus).await;
        let (status, body) = post_json(&app, "/v1/device/status", &request).await;
        assert_eq!(
            (status, body),
            (StatusCode::OK, json!({"state": "approved"}))
        );
        let request = auth_request(&app, &owned.device, DeviceAuthPurpose::LogMine).await;
        let (status, body) = post_json(&app, "/v1/log/mine", &request).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mine: MyEntries = serde_json::from_value(body).unwrap();
        assert_eq!(mine.manifest.entry.data["manifest"], a_hash.as_str());
        assert_eq!(mine.device.len(), 2);
    }

    /// Item 10: a control A collects and B tightens fails under B with its own grace, and is not
    /// reported as missing.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn a_tightened_control_fails_under_the_new_manifest_with_its_grace() {
        let tightened = DEMO.replace(
            "required = { macos = { max = 30 }, windows = { max = 30 }, linux = { max = 30 } }\ngrace = \"1d\"",
            "required = { macos = { max = 14 }, windows = { max = 14 }, linux = { max = 14 } }\ngrace = \"1d\"",
        );
        assert_ne!(tightened, DEMO);
        let (app, db) = test_app_with(&tightened, 10, 100).await;
        let owned = device_on(&db, DEMO).await;
        let mut claim = claim_under(&app, &owned.device, DEMO).await;
        claim.results.insert("os_patch_age_days".into(), 20.into());
        let (status, body) = send_claim(&app, &owned.device, &claim, Some(DEMO)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["warnings"],
            json!(["os_patch_age_days = 20, <= 14 required, access ends in 24h"])
        );
    }

    /// An acceptance from another device key, with another owner key, a forged owner signature, or
    /// a join or status signature in place of the acceptance signature leaves the device on A.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn an_acceptance_with_a_wrong_device_key_or_owner_signature_is_refused() {
        let a = manifest_a();
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let owned = device_on(&db, &a).await;
        let a_hash = bound_hash(&db, &owned.pseudonym).await.0;

        let stranger = Owned {
            device: open_pact_core::dev_key::generate(),
            owner: owned.owner.clone(),
            pseudonym: owned.pseudonym.clone(),
        };
        let mut other_device = accept_request(&app, &stranger, &a).await;
        other_device.pseudonym = owned.pseudonym.clone();
        let unknown_device = accept_request(&app, &stranger, &a).await;
        let other_owner = accept_request(
            &app,
            &Owned {
                device: owned.device.clone(),
                owner: open_pact_core::dev_key::generate(),
                pseudonym: owned.pseudonym.clone(),
            },
            &a,
        )
        .await;
        let mut forged_owner = accept_request(&app, &owned, &a).await;
        forged_owner.owner_signature =
            open_pact_core::Signature::sign(&open_pact_core::dev_key::generate(), b"accept");
        let mut status_signature = accept_request(&app, &owned, &a).await;
        status_signature.device_signature = open_pact_core::Signature::sign(
            &owned.device,
            &open_pact_core::device_auth_statement(
                DeviceAuthPurpose::DeviceStatus,
                &owned.pseudonym,
                &status_signature.nonce,
            ),
        );
        let mut join_signature = accept_request(&app, &owned, &a).await;
        let join = open_pact_core::enrol_statement(
            &join_signature.manifest,
            &open_pact_core::InvitationCode::from_bytes([3; 32]).hash(),
            &join_signature.owner.key,
            &join_signature.device_key,
        );
        join_signature.device_signature = open_pact_core::Signature::sign(&owned.device, &join);
        join_signature.owner_signature = open_pact_core::Signature::sign(&owned.owner, &join);
        for (case, req) in [
            ("another device key", other_device),
            ("a device that is not enrolled", unknown_device),
            ("another owner key", other_owner),
            ("a forged owner signature", forged_owner),
            ("a device status signature", status_signature),
            ("a join signature", join_signature),
        ] {
            let (status, body) = post_accept(&app, &req).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{case}: {body}");
            assert_eq!(
                bound_hash(&db, &owned.pseudonym).await,
                (a_hash.clone(), "approved".into()),
                "{case}"
            );
        }

        for _ in 0..2 {
            let (status, body) = post_accept(&app, &accept_request(&app, &owned, &a).await).await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        let accepted: i64 =
            sqlx::query_scalar("SELECT count(*) FROM log_entries WHERE kind = 'manifest_accepted'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(accepted, 1, "a repeated acceptance changes nothing");
    }

    /// Item 7: acceptance moves only the hash; a pending or revoked device stays so.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn acceptance_keeps_a_pending_or_revoked_state() {
        let a = manifest_a();
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        for state in ["pending", "revoked"] {
            let owned = device_on(&db, &a).await;
            sqlx::query("UPDATE devices SET state = $1 WHERE pseudonym = $2")
                .bind(state)
                .bind(owned.pseudonym.as_str())
                .execute(&db)
                .await
                .unwrap();
            let (status, body) = post_accept(&app, &accept_request(&app, &owned, &a).await).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["state"], state);
            assert_eq!(bound_hash(&db, &owned.pseudonym).await.1, state);
        }
    }

    fn hash_of(toml: &str) -> String {
        Manifest::parse(toml.as_bytes()).unwrap().hash().to_string()
    }

    /// Manifest A with another claim retention, so it has a hash of its own.
    fn manifest_a_with_retention(retention: &str) -> String {
        let toml = manifest_a().replace(
            r#"claim_retention = "6mo""#,
            &format!(r#"claim_retention = "{retention}""#),
        );
        assert!(toml.contains(retention));
        toml
    }

    /// A second enrolment of the device of `owned` under `toml`, enrolled `hours_ago` hours before
    /// the first. It copies the owner, state and salt of the row under `from`, as a join under
    /// another manifest does.
    async fn another_enrolment(db: &PgPool, owned: &Owned, from: &str, toml: &str, hours_ago: i32) {
        let hash = Manifest::parse(toml.as_bytes()).unwrap().hash().clone();
        sqlx::query(
            "INSERT INTO devices (pseudonym, manifest_hash, owner_key, owner_signature, salt, state, enrolled_at) \
             SELECT pseudonym, $2, owner_key, owner_signature, salt, state, now() - make_interval(hours => $4) \
             FROM devices WHERE pseudonym = $1 AND manifest_hash = $3",
        )
        .bind(owned.pseudonym.as_str())
        .bind(hash.as_str())
        .bind(from)
        .bind(hours_ago)
        .execute(db)
        .await
        .unwrap();
    }

    /// Ends the grace of every control that failed so far.
    async fn end_graces(db: &PgPool) {
        sqlx::query("UPDATE control_failures SET first_failed_at = now() - interval '2 days'")
            .execute(db)
            .await
            .unwrap();
    }

    /// F1: a device with an approved enrolment under A1 in use and one under A2, older. The gateway
    /// runs C. A claim under A1 is judged by A1's grace. A claim under A2 is refused as not the
    /// enrolment in use, even though A2 has no grace left to lose.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn a_claim_under_an_enrolment_not_in_use_is_refused() {
        let (a1, a2) = (manifest_a(), manifest_a_with_retention("3mo"));
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let owned = device_on(&db, &a1).await;
        another_enrolment(&db, &owned, &hash_of(&a1), &a2, 1).await;

        let claim = claim_under(&app, &owned.device, &a1).await;
        let (status, body) = send_claim(&app, &owned.device, &claim, Some(&a1)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        end_graces(&db).await;

        let claim = claim_under(&app, &owned.device, &a1).await;
        let (status, body) = send_claim(&app, &owned.device, &claim, Some(&a1)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["reasons"].to_string().contains("grace 1d ended"),
            "{body}"
        );

        let claim = claim_under(&app, &owned.device, &a2).await;
        let (status, body) = send_claim(&app, &owned.device, &claim, Some(&a2)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["reasons"].to_string().contains(&format!(
                "this device's enrolment in use is {}",
                hash_of(&a1)
            )),
            "{body}"
        );
        assert!(body.get("certificate_pem").is_none());
    }

    /// F1: a device approved under A and under B, with the gateway on B. B's grace has ended. A claim
    /// under A, which does not require the control, must not pass in B's place.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn a_claim_under_an_older_approved_enrolment_cannot_stand_in_for_the_one_in_use() {
        let a = manifest_a();
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let owned = device_on(&db, DEMO).await;
        another_enrolment(&db, &owned, &hash_of(DEMO), &a, 1).await;
        let short_password = |claim: &mut Claim| {
            claim.results.insert("password_min_length".into(), 5.into());
        };
        let mut claim = claim_under(&app, &owned.device, DEMO).await;
        short_password(&mut claim);
        let (status, body) = send_claim(&app, &owned.device, &claim, Some(DEMO)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        end_graces(&db).await;

        let mut claim = claim_under(&app, &owned.device, DEMO).await;
        short_password(&mut claim);
        let (status, body) = send_claim(&app, &owned.device, &claim, Some(DEMO)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["reasons"].to_string().contains("grace 1d ended"),
            "{body}"
        );

        let claim = claim_under(&app, &owned.device, &a).await;
        let (status, body) = send_claim(&app, &owned.device, &claim, Some(&a)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["reasons"].to_string().contains("enrolment in use is"),
            "{body}"
        );
    }

    /// F1: an acceptance leaves one enrolment of the device. An acceptance that names an enrolment
    /// other than the one in use is refused, and a repeat of the accepted one still answers.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn an_acceptance_leaves_exactly_one_enrolment() {
        let a1 = manifest_a();
        let a2 = manifest_a_with_retention("3mo");
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let owned = device_on(&db, &a1).await;
        another_enrolment(&db, &owned, &hash_of(&a1), &a2, 1).await;

        let (status, body) = post_accept(&app, &accept_request(&app, &owned, &a2).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["reasons"].to_string().contains("enrolment in use is"),
            "{body}"
        );
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE pseudonym = $1")
            .bind(owned.pseudonym.as_str())
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(rows, 2, "a refused acceptance changes nothing");

        let (status, body) = post_accept(&app, &accept_request(&app, &owned, &a1).await).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = post_accept(&app, &accept_request(&app, &owned, &a1).await).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT manifest_hash, state FROM devices WHERE pseudonym = $1")
                .bind(owned.pseudonym.as_str())
                .fetch_all(&db)
                .await
                .unwrap();
        assert_eq!(rows, [(hash_of(DEMO), "approved".to_string())]);
    }

    /// S1: a pending device whose manifest changed hears its state before the request to accept.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn a_pending_device_is_told_its_state_before_the_accept_notice() {
        let a = manifest_a();
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let owned = device_on(&db, &a).await;
        sqlx::query("UPDATE devices SET state = 'pending' WHERE pseudonym = $1")
            .bind(owned.pseudonym.as_str())
            .execute(&db)
            .await
            .unwrap();
        let claim = claim_under(&app, &owned.device, &a).await;
        let (status, body) = send_claim(&app, &owned.device, &claim, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let reasons = body["reasons"].as_array().unwrap();
        assert_eq!(reasons[0], "device awaiting IT approval", "{body}");
        assert!(
            body["reasons"]
                .to_string()
                .contains("run `open-pact-client accept`"),
            "{body}"
        );
    }

    fn bare_csr() -> (String, Vec<u8>) {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params
            .serialize_request(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        (csr.pem().unwrap(), csr.der().to_vec())
    }

    /// Every stored record, and the JSON payload of its JWS, as text.
    async fn stored_text(db: &PgPool) -> Vec<String> {
        let kek = SealingKey::new(&TEST_KEK);
        claims::open_all(db, &kek)
            .await
            .unwrap()
            .into_iter()
            .map(|record| {
                use base64::Engine;
                let payload = record["jws"].as_str().unwrap().split('.').nth(1).unwrap();
                let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload)
                    .unwrap();
                format!("{record} {}", String::from_utf8(payload).unwrap())
            })
            .collect()
    }

    /// No sent request is kept in any column of any table, nor in any opened claim or its JWS:
    /// not as PEM, not as base64 of its DER in either alphabet, not under a `csr_pem` key.
    async fn assert_no_request_retained(db: &PgPool, pems: &[String]) {
        use base64::Engine;
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT table_name::text FROM information_schema.tables WHERE table_schema = 'public'",
        )
        .fetch_all(db)
        .await
        .unwrap();
        let mut texts = stored_text(db).await;
        for table in tables {
            texts.push(
                sqlx::query_scalar(&format!(
                    "SELECT coalesce(string_agg(row_to_json(t)::text, ' '), '') FROM {table} t"
                ))
                .fetch_one(db)
                .await
                .unwrap(),
            );
        }
        let texts = texts.join("\n");
        // The key of a stored request body. A refusal reason in `devices.last_reasons` names the field in words.
        assert!(!texts.contains("\"csr_pem\"") && !texts.contains("CERTIFICATE REQUEST"));
        for pem in pems {
            let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let der = base64::engine::general_purpose::STANDARD
                .decode(&body)
                .unwrap();
            let url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&der);
            for encoded in [&body, &url] {
                let chunk = &encoded[encoded.len() / 2..encoded.len() / 2 + 40];
                assert!(!texts.contains(chunk), "a sent request is retained");
            }
        }
    }

    /// M3: the request travels beside the JWS; the company keeps its hash and the certificate's.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn issues_a_certificate_without_storing_the_certificate_request() {
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let (key, mut claim) = enrolled_claim(&app, &db, DEMO).await;
        let (pem, der) = bare_csr();
        claim.csr_sha256 = Some(CsrHash::of(&der));
        let jws = open_pact_core::sign_claim(&claim, &key).unwrap();
        let (status, body) =
            post_json(&app, "/v1/claim", &json!({"jws": jws, "csr_pem": pem})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let certificate = body["certificate_pem"].as_str().unwrap();

        let stored = stored_text(&db).await;
        assert_eq!(stored.len(), 1);
        assert!(stored[0].contains(&keys::certificate_sha256(certificate).unwrap()));
        assert_no_request_retained(&db, &[pem]).await;
    }

    /// M3: a request with anything besides its key, or another request than the claim signs, gets no certificate.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn refuses_a_certificate_request_the_claim_does_not_sign_or_that_carries_text() {
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let mut subject = rcgen::CertificateParams::default();
        subject.distinguished_name = rcgen::DistinguishedName::new();
        subject
            .distinguished_name
            .push(rcgen::DnType::CommonName, "FICTIONAL private note");
        let texty = subject
            .serialize_request(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        let (other_pem, _) = bare_csr();
        let sent_pems = [texty.pem().unwrap(), other_pem];
        for (signed, sent) in [
            (CsrHash::of(texty.der()), &sent_pems[0]),
            (CsrHash::of(&bare_csr().1), &sent_pems[1]),
        ] {
            let (key, mut claim) = enrolled_claim(&app, &db, DEMO).await;
            claim.csr_sha256 = Some(signed);
            let jws = open_pact_core::sign_claim(&claim, &key).unwrap();
            let (status, body) =
                post_json(&app, "/v1/claim", &json!({"jws": jws, "csr_pem": sent})).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            assert!(body["reasons"].to_string().contains("csr"), "{body}");
        }
        assert_eq!(
            stored_text(&db).await.len(),
            2,
            "both denied claims are kept"
        );
        assert_no_request_retained(&db, &sent_pems).await;
    }

    async fn post_from(app: &Router, path: &str, body: &str) -> StatusCode {
        let mut req = Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 7], 40000))));
        app.clone().oneshot(req).await.unwrap().status()
    }

    /// M7: refusals before the invitation check (a broken body or signature) also count.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn every_refused_enrolment_counts_towards_the_limit() {
        let app = test_app(3, 100).await;
        for _ in 0..3 {
            assert_eq!(
                post_from(&app, "/v1/enroll", "{}").await,
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            post_from(&app, "/v1/enroll", "{}").await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    /// M2: one address cannot fill the nonce table.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn nonces_are_limited_per_address() {
        let app = test_app(10, 2).await;
        for _ in 0..2 {
            assert_eq!(post_from(&app, "/v1/nonce", "").await, StatusCode::OK);
        }
        assert_eq!(
            post_from(&app, "/v1/nonce", "").await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    /// H5: a claim with a field the manifest does not list is denied and not stored.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn does_not_store_a_claim_with_metadata_the_manifest_does_not_list() {
        let toml = DEMO.replace(r#""virtualized", "log_checkpoint"]"#, "]");
        assert_ne!(toml, DEMO);
        let (app, db) = test_app_with(&toml, 10, 100).await;
        let (key, mut claim) = enrolled_claim(&app, &db, &toml).await;
        claim.log_checkpoint = Some(open_pact_core::LogCheckpoint {
            size: 1,
            root: LogHash([0; 32]),
        });
        let jws = open_pact_core::sign_claim(&claim, &key).unwrap();
        let (status, body) = post_json(&app, "/v1/claim", &json!({ "jws": jws })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["reasons"]
                .to_string()
                .contains("virtualized is not in disclosed_metadata")
        );
        assert!(
            body["reasons"]
                .to_string()
                .contains("log_checkpoint is not in disclosed_metadata")
        );
        assert_eq!(stored_text(&db).await, Vec::<String>::new());
    }

    /// H7: an asserted level cannot meet a policy, and the company keeps it apart from the verified one.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn an_asserted_trust_level_counts_as_l0() {
        let l2 = DEMO.replace(r#"min_trust_level = "L0""#, r#"min_trust_level = "L2""#);
        let (app, db) = test_app_with(&l2, 10, 100).await;
        let (key, mut claim) = enrolled_claim(&app, &db, &l2).await;
        claim.trust_level = open_pact_core::TrustLevel::L2;
        let jws = open_pact_core::sign_claim(&claim, &key).unwrap();
        let (status, body) = post_json(&app, "/v1/claim", &json!({ "jws": jws })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["reasons"].to_string().contains("needs attestation"),
            "{body}"
        );

        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let (key, mut claim) = enrolled_claim(&app, &db, DEMO).await;
        claim.trust_level = open_pact_core::TrustLevel::L1;
        let jws = open_pact_core::sign_claim(&claim, &key).unwrap();
        let (status, body) = post_json(&app, "/v1/claim", &json!({ "jws": jws })).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let stored = claims::open_all(&db, &SealingKey::new(&TEST_KEK))
            .await
            .unwrap();
        assert_eq!(stored[0]["claim"]["asserted_trust_level"], "L1");
        assert_eq!(stored[0]["claim"]["verified_trust_level"], "L0");
        assert_eq!(stored[0]["claim"]["trust_level"], Value::Null);
    }

    #[test]
    fn a_claim_checkpoint_must_be_a_state_of_this_log() {
        let tree = tree_of((0u8..5).map(|i| open_pact_core::leaf_hash(&[i])).collect());
        let at = |size: u64| LogCheckpoint {
            size,
            root: tree.root_at(size),
        };
        assert_eq!(foreign_checkpoint(&tree, &at(3)), None);
        assert_eq!(foreign_checkpoint(&tree, &at(5)), None);
        let wrong_root = LogCheckpoint {
            root: at(2).root,
            ..at(3)
        };
        assert!(foreign_checkpoint(&tree, &wrong_root).is_some());
        let beyond = LogCheckpoint {
            size: 999_999,
            root: LogHash([0; 32]),
        };
        assert!(foreign_checkpoint(&tree, &beyond).is_some());
        assert!(foreign_checkpoint(&tree, &at(0)).is_some());
    }

    #[test]
    fn log_origin_requires_a_configured_origin() {
        assert_eq!(
            parse_log_origin(Some("gateway.example.org/log".into())).unwrap(),
            "gateway.example.org/log"
        );
        let error = parse_log_origin(None).unwrap_err().to_string();
        assert!(error.contains("LOG_ORIGIN is required"), "{error}");
    }

    #[test]
    fn gateway_main_semantics_internal_reply_hides_details() {
        let (status, body) = internal("FICTIONAL secret");

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.0, json!({"status": "error"}));
    }

    #[test]
    fn gateway_main_semantics_bad_request_reply_includes_reason() {
        let (status, body) = bad_request("FICTIONAL bad input");

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body.0,
            json!({"status": "error", "reason": "FICTIONAL bad input"})
        );
    }

    #[test]
    fn gateway_main_semantics_denied_reply_includes_reasons() {
        let (status, body) = denied(vec!["first".into(), "second".into()]);

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body.0,
            json!({"status": "denied", "reasons": ["first", "second"]})
        );
    }

    #[test]
    fn gateway_main_semantics_invalid_invitation_reply() {
        let (status, body) = invalid_invitation();

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body.0,
            json!({"status": "denied", "reasons": ["invalid or used invitation"]})
        );
    }

    #[tokio::test]
    async fn gateway_main_semantics_legacy_log_reply() {
        let (status, body) = legacy_log().await;

        assert_eq!(status, StatusCode::GONE);
        assert_eq!(
            body.0,
            json!({
                "status": "gone",
                "reason": "the transparency log is now a Merkle tree with signed checkpoints; update open-pact-client and run join again"
            })
        );
    }

    #[test]
    fn gateway_main_semantics_rate_limit_reply() {
        let (status, body) = too_many("FICTIONAL limit");

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            body.0,
            json!({"status": "denied", "reasons": ["FICTIONAL limit"]})
        );
    }

    #[test]
    fn gateway_main_semantics_device_denied_reply() {
        let (status, body) = device_denied();

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body.0,
            json!({"status": "denied", "reasons": ["device access denied"]})
        );
    }

    #[test]
    fn gateway_main_semantics_manifest_consent_matches_signed_manifest() {
        let enforced = Manifest::parse(DEMO.as_bytes()).unwrap();
        let signed_toml = manifest_a();
        let signed = Manifest::parse(signed_toml.as_bytes()).unwrap();

        let accepted = consented_manifest(&enforced, signed.hash(), Some(&signed_toml)).unwrap();
        assert_eq!(accepted.hash(), signed.hash());

        let error = consented_manifest(&enforced, signed.hash(), Some(DEMO))
            .expect_err("a different manifest must require consent");
        assert_eq!(
            error,
            format!(
                "manifest_toml is {}, not the manifest this device signed; this device signed manifest {}, the gateway now enforces {}; run `open-pact-client accept`",
                enforced.hash(),
                signed.hash(),
                enforced.hash()
            )
        );
    }

    #[test]
    fn gateway_main_semantics_log_origin_rejects_empty_value() {
        let error =
            parse_log_origin(Some(String::new())).expect_err("an empty log origin is invalid");

        assert_eq!(
            error.to_string(),
            "LOG_ORIGIN must be non-empty, without spaces or '+': \"\""
        );
    }

    #[test]
    fn gateway_main_semantics_log_origin_rejects_invalid_characters() {
        for (origin, expected) in [
            (
                "fictional+log",
                "LOG_ORIGIN must be non-empty, without spaces or '+': \"fictional+log\"",
            ),
            (
                "fictional log",
                "LOG_ORIGIN must be non-empty, without spaces or '+': \"fictional log\"",
            ),
        ] {
            let error = parse_log_origin(Some(origin.into()))
                .expect_err("invalid log origin characters must be rejected");
            assert_eq!(error.to_string(), expected);
        }

        assert_eq!(
            parse_log_origin(Some("fictional.example/log".into())).unwrap(),
            "fictional.example/log"
        );
    }

    fn gateway_main_in_owned_child(test_name: &str) -> bool {
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        const MARKER: &str = "OPEN_PACT_PRIVATE_GATEWAY_TEST_CHILD";
        if std::env::var(MARKER).as_deref() == Ok(test_name) {
            return false;
        }

        struct TempDir(std::path::PathBuf);

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        struct OwnedChild(Option<Child>);

        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if let Some(child) = self.0.as_mut() {
                    if child.try_wait().ok().flatten().is_some() {
                        return;
                    }
                    match child.kill() {
                        Ok(()) => {
                            child.wait().expect("reap the killed fixture child");
                        }
                        Err(error) => {
                            assert!(
                                child.try_wait().ok().flatten().is_some(),
                                "could not stop the fixture child: {error}"
                            );
                        }
                    }
                }
            }
        }

        let directory = std::env::temp_dir().join(format!(
            "open-pact-gateway-fixture-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir(&directory).expect("create private fixture directory");
        let directory = TempDir(directory);
        let home = directory.0.join("home");
        let temporary = directory.0.join("tmp");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&temporary).unwrap();
        let stdout_path = directory.0.join("stdout");
        let stderr_path = directory.0.join("stderr");
        let stdout = std::fs::File::create(&stdout_path).unwrap();
        let stderr = std::fs::File::create(&stderr_path).unwrap();
        let exact_name = format!("tests::{test_name}");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut child = OwnedChild(Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &exact_name, "--nocapture", "--format=pretty"])
                .env_clear()
                .env(MARKER, test_name)
                .env("HOME", &home)
                .env("TMPDIR", &temporary)
                .env("PGUSER", "fictional")
                .env("PGHOSTADDR", "127.0.0.1")
                .env("PGHOST", "fictional.invalid")
                .env("PGPORT", "1")
                .env("PGDATABASE", "fictional")
                .env("PGPASSWORD", "fictional")
                .stdin(Stdio::null())
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .expect("start the isolated fixture child"),
        ));
        let (status, timed_out) = loop {
            if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
                child.0 = None;
                break (status, false);
            }
            if Instant::now() >= deadline {
                let process = child.0.as_mut().unwrap();
                process.kill().expect("stop the timed out fixture child");
                let status = process.wait().expect("reap the timed out fixture child");
                child.0 = None;
                break (status, true);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let stdout = std::fs::read(&stdout_path).unwrap();
        let stderr = std::fs::read(&stderr_path).unwrap();
        let stdout = String::from_utf8_lossy(&stdout);
        let stderr = String::from_utf8_lossy(&stderr);
        assert!(
            !timed_out && status.success(),
            "fixture child: {status}, timed out: {timed_out}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            stdout.lines().any(|line| line == "running 1 test"),
            "{stdout}"
        );
        let passed = format!("test {exact_name} ... ok");
        assert!(stdout.lines().any(|line| line == passed), "{stdout}");
        assert!(
            stdout.lines().any(|line| line
                .starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")),
            "{stdout}"
        );
        true
    }

    #[tokio::test]
    async fn gateway_main_semantics_invite_rejects_disallowed_scheme_before_database() {
        if gateway_main_in_owned_child(
            "gateway_main_semantics_invite_rejects_disallowed_scheme_before_database",
        ) {
            return;
        }
        let db = PgPoolOptions::new()
            .connect_lazy("postgres://fictional:fictional@127.0.0.1:1/fictional")
            .unwrap();
        db.close().await;

        let error = invite(
            &db,
            &SealingKey::new(&TEST_KEK),
            "ftp://fictional.example/path",
            time::Duration::hours(1),
            "FICTIONAL",
            false,
            &mut Vec::new(),
        )
        .await
        .expect_err("a disallowed URL scheme must be rejected");

        assert_eq!(
            error.to_string(),
            "--url must be an http(s) URL, got \"ftp://fictional.example/path\""
        );
    }

    #[tokio::test]
    async fn gateway_main_semantics_log_entries_rejects_range_overflow() {
        if gateway_main_in_owned_child("gateway_main_semantics_log_entries_rejects_range_overflow")
        {
            return;
        }
        let db = PgPoolOptions::new()
            .connect_lazy("postgres://fictional:fictional@127.0.0.1:1/fictional")
            .unwrap();
        db.close().await;
        let mut output = vec![b'X'];

        let error = log_entries(&db, u64::MAX, 1, &mut output)
            .await
            .expect_err("an overflowing log range must be rejected");

        assert_eq!(
            error.to_string(),
            "from + limit exceeds the log index range"
        );
        assert_eq!(output, [b'X']);
    }

    #[test]
    fn a_command_line_that_does_not_parse_gets_a_json_error_when_it_asked_for_json() {
        let line = |args: &[&str]| {
            let mut all = vec!["open-pact-gateway"];
            all.extend_from_slice(args);
            let all: Vec<std::ffi::OsString> = all.into_iter().map(Into::into).collect();
            let error = Cli::try_parse_from(&all).map(|_| ()).unwrap_err();
            usage_error_line(&all, &error)
        };
        for args in [
            &[
                "invite",
                "--json",
                "--ttl",
                "invalid",
                "--url",
                "https://pact.example.com",
            ][..],
            &["status", "--json", "--bogus"],
            &["devices", "list", "--json", "--bogus"],
        ] {
            let text = line(args).unwrap_or_else(|| panic!("{args:?} has no JSON error"));
            let document: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(document.as_object().unwrap().len(), 1, "{text}");
            assert!(!document["error"].as_str().unwrap().is_empty(), "{text}");
            assert!(!text.contains('\n'), "{text}");
        }
        assert_eq!(line(&["status", "--bogus"]), None);
        assert_eq!(line(&["invite", "--ttl", "invalid"]), None);
    }

    #[test]
    fn the_json_flags_parse_and_make_failures_json() {
        let parse = |args: &[&str]| {
            let mut all = vec!["open-pact-gateway"];
            all.extend_from_slice(args);
            Cli::try_parse_from(all).unwrap()
        };
        assert!(parse(&["status", "--json"]).prints_json());
        assert!(parse(&["devices", "list", "--json"]).prints_json());
        assert!(parse(&["claims", "list", "--json"]).prints_json());
        assert!(parse(&["claims", "show", "7", "--json"]).prints_json());
        assert!(!parse(&["claims", "list"]).prints_json());
        assert!(!parse(&["claims", "show", "7"]).prints_json());
        assert!(parse(&["invite", "--json", "--url=https://pact.example.com"]).prints_json());
        assert!(!parse(&["status"]).prints_json());
        assert!(!parse(&["devices", "list"]).prints_json());
        assert!(!parse(&["invite", "--url=https://pact.example.com"]).prints_json());
        assert!(!parse(&[]).prints_json());
    }

    /// `claims list --since` read these spellings while clap used chrono's `FromStr`.
    fn since_reads(text: &str, expected: &str) {
        let cli = Cli::try_parse_from(["open-pact-gateway", "claims", "list", "--since", text])
            .unwrap_or_else(|error| panic!("{text:?}: {error}"));
        let Some(Command::Claims {
            command: results::Command::List {
                since: Some(since), ..
            },
        }) = cli.command
        else {
            panic!("claims list command")
        };
        assert_eq!(
            open_pact_core::timestamp::rfc3339_auto(since),
            expected,
            "{text:?}"
        );
    }

    macro_rules! since_spellings {
        ($($name:ident: $text:expr => $expected:expr;)*) => {
            $(
                #[test]
                fn $name() {
                    since_reads($text, $expected);
                }
            )*
        };
    }

    since_spellings! {
        since_reads_rfc3339_with_z: "2026-10-12T09:00:00Z" => "2026-10-12T09:00:00Z";
        since_reads_an_offset_without_a_colon: "2026-10-12T09:00:00+0000" => "2026-10-12T09:00:00Z";
        since_reads_an_offset_with_a_space: "2026-10-12T09:00:00 +00 00" => "2026-10-12T09:00:00Z";
        since_reads_a_utc_suffix_after_a_space: "2026-10-12 09:00:00 UTC" => "2026-10-12T09:00:00Z";
        since_reads_a_lowercase_utc_suffix: "2026-10-12 09:00:00 utc" => "2026-10-12T09:00:00Z";
        since_reads_one_digit_fields: "2026-1-2T3:4:5Z" => "2026-01-02T03:04:05Z";
        since_reads_trailing_white_space: "2026-10-12T09:00:00Z " => "2026-10-12T09:00:00Z";
        since_reads_white_space_between_the_parts: "2026 - 10 - 12T 09 : 00 : 00 Z" => "2026-10-12T09:00:00Z";
        since_reads_a_signed_year: "+2026-10-12T09:00:00Z" => "2026-10-12T09:00:00Z";
        since_reads_a_unicode_minus_in_the_offset: "2026-10-12T09:00:00\u{2212}02:00" => "2026-10-12T11:00:00Z";
        since_reads_a_space_before_the_time: "2026-10-12 09:00:00+02:00" => "2026-10-12T07:00:00Z";
        since_reads_a_lowercase_t_and_z: "2026-10-12t09:00:00z" => "2026-10-12T09:00:00Z";
        since_reads_a_fraction: "2026-10-12T09:00:00.5+02:00" => "2026-10-12T07:00:00.500Z";
        since_reads_a_leap_second: "2016-12-31T23:59:60Z" => "2017-01-01T00:00:00Z";
    }

    #[test]
    fn since_refuses_text_chrono_refused_and_instants_past_the_range_of_time() {
        for text in [
            "2026-10-12",
            "2026-10-12T09:00:00",
            "2026-10-12T09:00:00+24:00",
            "9999-12-31T23:59:59-23:59",
            "+10000-01-01T00:00:00Z",
        ] {
            let error =
                Cli::try_parse_from(["open-pact-gateway", "claims", "list", "--since", text])
                    .map(|_| ())
                    .unwrap_err();
            assert!(
                error.to_string().contains("not an RFC 3339 time"),
                "{text}: {error}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL and LOG_ORIGIN"]
    async fn invite_json_prints_one_document_and_nothing_else() {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&TEST_KEK);
        let mut out = Vec::new();

        invite(
            &db,
            &kek,
            "https://pact.example.com",
            time::Duration::hours(72),
            "MacBook, K. Example",
            true,
            &mut out,
        )
        .await
        .unwrap();

        let document: Value = serde_json::from_slice(&out).expect("one JSON document");
        let invitation = Invitation::decode(document["invitation"].as_str().unwrap()).unwrap();
        assert_eq!(invitation.gateway, "https://pact.example.com");
        assert_eq!(document["note"], "MacBook, K. Example");
        assert_eq!(document["company_key_fingerprint"], invitation.company);
        let expires = document["expires_at"].as_str().unwrap();
        let expires = open_pact_core::timestamp::parse_rfc3339(expires).unwrap();
        let hours = (expires - OffsetDateTime::now_utc()).whole_hours();
        assert!((70..=72).contains(&hours), "{hours}");

        let mut plain = Vec::new();
        invite(
            &db,
            &kek,
            "https://pact.example.com",
            time::Duration::hours(1),
            "",
            false,
            &mut plain,
        )
        .await
        .unwrap();
        let plain = String::from_utf8(plain).unwrap();
        assert!(
            plain.starts_with("opi1:") && plain.lines().count() == 1,
            "{plain}"
        );
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn status_reports_version_manifest_and_device_counts() {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&TEST_KEK);
        let manifest = Manifest::parse(DEMO.as_bytes()).unwrap();
        for (n, state) in [(1u8, "pending"), (2, "approved"), (3, "approved")] {
            let pseudonym = format!("pseudonym:{}", hex::encode([n; 32]));
            testdb::enrolled_device(&db, &pseudonym, manifest.hash().as_str()).await;
            sqlx::query("UPDATE devices SET state = $1 WHERE pseudonym = $2")
                .bind(state)
                .bind(&pseudonym)
                .execute(&db)
                .await
                .unwrap();
        }

        let document = status(&db, &kek, &manifest, true).await.unwrap();

        let keys = Keys::load_or_create(&db, &kek).await.unwrap();
        assert_eq!(
            serde_json::to_value(&document).unwrap(),
            json!({
                "version": env!("CARGO_PKG_VERSION"),
                "manifest_hash": manifest.hash().as_str(),
                "manifest_source": "builtin",
                "manifest_version": null,
                "auto_approve": true,
                "devices": {"pending": 1, "approved": 2, "revoked": 0},
                "company_key_fingerprint": PublicKey::from(&keys.manifest).fingerprint(),
            })
        );
    }

    #[tokio::test]
    async fn status_reports_a_database_error() {
        let db = PgPoolOptions::new()
            .connect_lazy("postgres://fictional:fictional@127.0.0.1:1/fictional")
            .unwrap();
        db.close().await;
        let manifest = Manifest::parse(DEMO.as_bytes()).unwrap();

        let error = status(&db, &SealingKey::new(&TEST_KEK), &manifest, false)
            .await
            .err()
            .expect("a closed pool is an error");

        let printed = json!({ "error": format!("{error:#}") });
        assert!(!printed["error"].as_str().unwrap().is_empty());
        assert_eq!(printed.as_object().unwrap().len(), 1);
    }
    /// `devices list --json` shows how the gateway decided the last claim of each enrolment.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn devices_list_shows_the_last_claim_decision_of_each_device() {
        let (app, db) = test_app_with(DEMO, 10, 100).await;
        let manifest = Manifest::parse(DEMO.as_bytes()).unwrap();
        let (key, first) = enrolled_claim(&app, &db, DEMO).await;
        let (idle, _) = enrolled_claim(&app, &db, DEMO).await;
        let last = |rows: Vec<Value>, key: &SigningKey| {
            let pseudonym = Pseudonym::of(&PublicKey::from(key));
            rows.into_iter()
                .find(|row| row["pseudonym"] == pseudonym.as_str())
                .unwrap()
        };
        let listed = || async {
            let text = devices::list_json(&db).await.unwrap();
            serde_json::from_str::<Vec<Value>>(&text).unwrap()
        };

        let row = last(listed().await, &key);
        assert_eq!(row["last_claim_at"], Value::Null);
        assert_eq!(row["last_result"], Value::Null);
        assert_eq!(row["last_reasons"], json!([]));

        let mut stale = first.clone();
        stale.results.insert("os_patch_age_days".into(), 40.into());
        let (status, body) = send_claim(&app, &key, &stale, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let row = last(listed().await, &key);
        assert_eq!(row["last_result"], "accepted_with_warnings");
        assert_eq!(row["last_reasons"], body["warnings"]);
        assert!(!row["last_reasons"].as_array().unwrap().is_empty());
        let at = row["last_claim_at"].as_str().unwrap().to_owned();
        assert!(at.ends_with('Z') && at.len() == 20, "{at}");

        let clean = fresh_claim(&app, &key, &manifest).await;
        let (status, body) = send_claim(&app, &key, &clean, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let row = last(listed().await, &key);
        assert_eq!(row["last_result"], "accepted");
        assert_eq!(row["last_reasons"], json!([]));

        let mut leaking = fresh_claim(&app, &key, &manifest).await;
        leaking
            .results
            .insert("firewall".into(), "fictional-secret-value".into());
        let (status, body) = send_claim(&app, &key, &leaking, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let row = last(listed().await, &key);
        assert_eq!(row["last_result"], "denied");
        assert!(!row.to_string().contains("fictional-secret-value"), "{row}");

        sqlx::query("UPDATE devices SET state = 'revoked' WHERE pseudonym = $1")
            .bind(Pseudonym::of(&PublicKey::from(&key)).as_str())
            .execute(&db)
            .await
            .unwrap();
        let revoked = fresh_claim(&app, &key, &manifest).await;
        let (status, _) = send_claim(&app, &key, &revoked, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let row = last(listed().await, &key);
        assert_eq!(row["last_result"], "denied");
        assert_eq!(row["last_reasons"], json!(["device revoked"]));

        let row = last(listed().await, &idle);
        assert_eq!(
            row["last_result"],
            Value::Null,
            "another device is untouched"
        );
    }
}
