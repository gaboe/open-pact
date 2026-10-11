mod claims;
mod devices;
mod grace;
mod invitations;
mod keys;
mod nonces;
mod ratelimit;
mod seal;
#[cfg(test)]
mod testdb;
mod translog;

use std::fmt::Display;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Query, State, rejection::JsonRejection},
    http::{StatusCode, header},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use open_pact_core::{
    Checkpoint, Decision, Endorsement, EnrolRequest, Entry, EntryKind, Evaluation, FirstFailures,
    Invitation, LogHash, LogKey, Manifest, Note, Pseudonym, PublicKey, Reason, SigningKey, Span,
    WitnessKey, consistency_proof, evaluate, inclusion_proof, root, verify_claim,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

use devices::{Action, State as DeviceState, commitment};
use keys::Keys;
use ratelimit::Limiter;
use seal::SealingKey;

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
        /// How long the invitation stays valid: 30m, 72h, 7d (at most 30d)
        #[arg(long, default_value = "72h")]
        ttl: String,
        /// Who the invitation is for. Stays in the gateway database, never in the log
        #[arg(long, default_value = "")]
        note: String,
        /// The gateway URL the owner's client connects to
        #[arg(long, env = "PUBLIC_URL")]
        url: String,
    },
    /// List, approve or revoke devices
    Devices {
        #[command(subcommand)]
        command: DevicesCommand,
    },
}

#[derive(Subcommand)]
enum DevicesCommand {
    /// Every enrolment with its state and invitation note
    List,
    /// Approve the pending device whose pseudonym starts with these hex digits (at least 8)
    Approve { prefix: String },
    /// Revoke a device by its full pseudonym. Final: the device cannot be approved again
    Revoke { pseudonym: String },
}

type Reply = (StatusCode, Json<Value>);

#[derive(Clone)]
struct App {
    db: PgPool,
    manifest: Arc<Manifest>,
    toml: Arc<str>,
    company: Endorsement,
    keys: Arc<Keys>,
    log: Arc<Log>,
    auto_approve: bool,
    limiter: Arc<Limiter>,
    nonce_limiter: Arc<Limiter>,
    max_nonces: i64,
    kek: Arc<SealingKey>,
}

struct Log {
    signer: SigningKey,
    key: LogKey,
    witnesses: Vec<WitnessKey>,
    cache: Mutex<LogCache>,
}

/// Rows are append-only, so leaf hashes are read from the database once, and the checkpoint is
/// signed once per tree size.
#[derive(Default)]
struct LogCache {
    leaves: Vec<LogHash>,
    signed: Option<(Checkpoint, Note)>,
}

/// The largest page `GET /v1/log/entries` serves.
const MAX_ENTRIES: u64 = 256;

struct Tree {
    leaves: Vec<LogHash>,
}

impl Tree {
    fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    fn prefix(&self, size: u64) -> &[LogHash] {
        &self.leaves[..usize::try_from(size).expect("size was checked against the tree")]
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    jws: String,
}

#[derive(Deserialize)]
struct RangeQuery {
    from: Option<u64>,
    to: Option<u64>,
}

#[derive(Deserialize)]
struct InclusionQuery {
    index: u64,
    size: Option<u64>,
}

fn internal(e: impl Display) -> Reply {
    eprintln!("internal error: {e}");
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

impl App {
    /// The committed log. Reads only rows the cache does not hold yet.
    async fn tree(&self) -> Result<Tree, Reply> {
        let known = self.log.cache.lock().expect("log cache").leaves.len();
        let new = translog::since(&mut *self.conn().await?, known as u64)
            .await
            .map_err(internal)?;
        let mut cache = self.log.cache.lock().expect("log cache");
        let already = cache.leaves.len() - known;
        if already < new.len() {
            cache
                .leaves
                .extend(new[already..].iter().map(Entry::leaf_hash));
        }
        Ok(Tree {
            leaves: cache.leaves.clone(),
        })
    }

    /// The current checkpoint signed by the log key, with the witness cosignatures stored for it.
    async fn checkpoint(&self) -> Result<Note, Reply> {
        let tree = self.tree().await?;
        let cached = self
            .log
            .cache
            .lock()
            .expect("log cache")
            .signed
            .clone()
            .filter(|(cp, _)| cp.size == tree.size());
        let (checkpoint, mut note) = match cached {
            Some(signed) => signed,
            None => {
                let checkpoint = Checkpoint {
                    origin: self.log.key.origin().to_string(),
                    size: tree.size(),
                    root: root(&tree.leaves),
                };
                let note = self.log.key.sign(&self.log.signer, &checkpoint);
                let signed = (checkpoint, note);
                self.log.cache.lock().expect("log cache").signed = Some(signed.clone());
                signed
            }
        };
        let cosignatures: Vec<String> = sqlx::query_scalar(
            "SELECT signature FROM log_cosignatures WHERE size = $1 AND root = $2 ORDER BY witness",
        )
        .bind(i64::try_from(checkpoint.size).map_err(internal)?)
        .bind(checkpoint.root.to_string())
        .fetch_all(&self.db)
        .await
        .map_err(internal)?;
        for line in cosignatures {
            note.signatures
                .push(open_pact_core::NoteSignature::parse(&line).map_err(internal)?);
        }
        Ok(note)
    }

    async fn conn(&self) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, Reply> {
        self.db.acquire().await.map_err(internal)
    }
}

async fn healthz(State(app): State<App>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&app.db).await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "db unavailable"),
    }
}

async fn manifest(State(app): State<App>) -> Json<Value> {
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

async fn log_key_text(State(app): State<App>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{}\n", app.log.key.vkey()),
    )
}

async fn log_checkpoint(State(app): State<App>) -> Result<impl IntoResponse, Reply> {
    let note = app.checkpoint().await?;
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        note.to_string(),
    ))
}

async fn log_entries(
    State(app): State<App>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Value>, Reply> {
    let size = app.tree().await?.size();
    let (from, to) = entries_range(q.from, q.to, size).map_err(bad_request)?;
    let entries = translog::range(&mut *app.conn().await?, from, to)
        .await
        .map_err(internal)?;
    Ok(Json(json!({ "entries": entries })))
}

/// `to` defaults to one full page or the end of the log.
fn entries_range(from: Option<u64>, to: Option<u64>, size: u64) -> Result<(u64, u64), String> {
    let from = from.unwrap_or(0);
    let to = to.unwrap_or_else(|| size.min(from.saturating_add(MAX_ENTRIES)));
    if from > to || to > size || to - from > MAX_ENTRIES {
        return Err(format!(
            "need from <= to <= {size} and at most {MAX_ENTRIES} entries, got from={from} to={to}"
        ));
    }
    Ok((from, to))
}

async fn inclusion(
    State(app): State<App>,
    Query(q): Query<InclusionQuery>,
) -> Result<Json<Value>, Reply> {
    let tree = app.tree().await?;
    let size = q.size.unwrap_or(tree.size());
    if size > tree.size() {
        return Err(bad_request(format!("the log has {} entries", tree.size())));
    }
    let proof = inclusion_proof(tree.prefix(size), q.index).map_err(bad_request)?;
    Ok(Json(
        json!({"index": q.index, "size": size, "proof": proof}),
    ))
}

async fn consistency(
    State(app): State<App>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Value>, Reply> {
    let tree = app.tree().await?;
    let (Some(from), to) = (q.from, q.to.unwrap_or(tree.size())) else {
        return Err(bad_request("from is required"));
    };
    if to > tree.size() {
        return Err(bad_request(format!("the log has {} entries", tree.size())));
    }
    let proof = consistency_proof(tree.prefix(to), from).map_err(bad_request)?;
    Ok(Json(json!({"from": from, "to": to, "proof": proof})))
}

/// Takes a checkpoint signed by this log with witness cosignature lines appended, as a
/// c2sp.org/tlog-witness add-checkpoint response would carry them, and stores the valid ones.
async fn witness(State(app): State<App>, body: String) -> Result<Json<Value>, Reply> {
    let reject =
        |code, reason: String| (code, Json(json!({"status": "denied", "reasons": [reason]})));
    let note = Note::parse(&body).map_err(bad_request)?;
    let checkpoint = app
        .log
        .key
        .verify(&note)
        .map_err(|e| reject(StatusCode::FORBIDDEN, e.to_string()))?;
    let tree = app.tree().await?;
    let mut conn = app.conn().await?;
    if checkpoint.size == 0
        || checkpoint.size > tree.size()
        || root(tree.prefix(checkpoint.size)) != checkpoint.root
    {
        return Err(reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "checkpoint of size {} does not match this log",
                checkpoint.size
            ),
        ));
    }
    let mut accepted = vec![];
    for sig in &note.signatures {
        for w in &app.log.witnesses {
            match w.verify(&checkpoint, sig) {
                None => {}
                Some(Err(e)) => {
                    return Err(reject(StatusCode::FORBIDDEN, format!("{}: {e}", w.name())));
                }
                Some(Ok(_)) => accepted.push((w.name(), sig.to_string())),
            }
        }
    }
    if accepted.is_empty() {
        return Err(reject(
            StatusCode::FORBIDDEN,
            "no cosignature from a key in WITNESS_KEYS".into(),
        ));
    }
    for (name, line) in &accepted {
        sqlx::query(
            "INSERT INTO log_cosignatures (size, root, witness, signature) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (size, root, witness) DO UPDATE SET signature = EXCLUDED.signature, received_at = now()",
        )
        .bind(i64::try_from(checkpoint.size).map_err(internal)?)
        .bind(checkpoint.root.to_string())
        .bind(name)
        .bind(line.trim_end())
        .execute(&mut *conn)
        .await
        .map_err(internal)?;
    }
    let names: Vec<&str> = accepted.iter().map(|(n, _)| *n).collect();
    Ok(Json(
        json!({"status": "stored", "size": checkpoint.size, "witnesses": names}),
    ))
}

fn too_many(reason: &str) -> Reply {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"status": "denied", "reasons": [reason]})),
    )
}

async fn nonce(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Json<Value>, Reply> {
    let now = Instant::now();
    if app.nonce_limiter.blocked(peer.ip(), now) {
        return Err(too_many(
            "too many nonces requested from this address; try again later",
        ));
    }
    app.nonce_limiter.record(peer.ip(), now);
    match nonces::issue(&app.db, app.max_nonces)
        .await
        .map_err(internal)?
    {
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
async fn enforce_retention(db: PgPool, retention: Span) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        match claims::purge(&db, &retention, chrono::Utc::now()).await {
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
    State(app): State<App>,
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

    let mut tx = app.db.begin().await.map_err(internal)?;
    translog::lock(&mut tx).await.map_err(internal)?;
    let existing: Option<(Value, String, String, Option<String>)> = sqlx::query_as(
        "SELECT owner_key, salt, state, invitation FROM devices WHERE pseudonym = $1 AND manifest_hash = $2 FOR UPDATE",
    )
    .bind(device.as_str())
    .bind(app.manifest.hash().as_str())
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
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
                translog::append(&mut tx, EntryKind::DeviceApproved, committed)
                    .await
                    .map_err(internal)?;
            }
            (salt, state, entry.index)
        }
    };
    tx.commit().await.map_err(internal)?;
    let manifest_index: i64 = sqlx::query_scalar(
        "SELECT idx FROM log_entries WHERE kind = 'manifest_published' AND data->>'manifest' = $1",
    )
    .bind(app.manifest.hash().as_str())
    .fetch_one(&app.db)
    .await
    .map_err(internal)?;
    let checkpoint = app.checkpoint().await?;
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

async fn claim(
    State(app): State<App>,
    body: Result<Json<ClaimRequest>, JsonRejection>,
) -> Result<Json<Value>, Reply> {
    let Ok(Json(ClaimRequest { jws })) = body else {
        return Err(denied(vec![
            "body must be {\"jws\": \"<compact JWS>\"}".into(),
        ]));
    };
    let verified = verify_claim(&jws).map_err(|e| denied(vec![e.to_string()]))?;
    let claim = verified.claim();
    let live: Option<bool> =
        sqlx::query_scalar("DELETE FROM nonces WHERE nonce = $1 RETURNING expires_at > now()")
            .bind(&claim.nonce)
            .fetch_optional(&app.db)
            .await
            .map_err(internal)?;
    match live {
        None => return Err(denied(vec!["unknown or used nonce".into()])),
        Some(false) => return Err(denied(vec!["expired nonce".into()])),
        Some(true) => {}
    }
    let manifest_hash = app.manifest.hash().as_str();
    let now = chrono::Utc::now();
    let mut tx = app.db.begin().await.map_err(internal)?;
    let state = devices::state(&mut tx, &claim.device, manifest_hash)
        .await
        .map_err(internal)?;
    let enrolled = state.is_some();
    let first_failures = if enrolled {
        grace::load(&mut tx, &claim.device, manifest_hash)
            .await
            .map_err(internal)?
    } else {
        FirstFailures::new()
    };

    let Evaluation {
        decision,
        first_failures,
    } = evaluate(&app.manifest, claim, now, &first_failures);
    let oversharing = matches!(&decision, Decision::Deny { reasons } if reasons.iter().any(Reason::breaks_disclosure_contract));
    let strings = |rs: &[Reason]| rs.iter().map(ToString::to_string).collect::<Vec<_>>();
    let (warnings, mut reasons) = match &decision {
        Decision::Allow { warnings } => (strings(warnings), vec![]),
        Decision::Deny { reasons } => (vec![], strings(reasons)),
    };
    match state.map(DeviceState::denial) {
        None => reasons.insert(0, "device not enrolled".into()),
        Some(Some(why)) => reasons.insert(0, why.into()),
        Some(None) => {}
    }
    let mut certificate_pem = None;
    if let (true, Some(csr)) = (reasons.is_empty(), &claim.csr_pem) {
        let validity = app
            .manifest
            .body()
            .claim_max_age
            .min_duration()
            .map_or(time::Duration::DAY, |max| {
                time::Duration::seconds(max.num_seconds()).min(time::Duration::DAY)
            });
        let cn = claim.device.as_str().trim_start_matches("pseudonym:");
        match app.keys.ca.issue(csr, cn, validity) {
            Ok(pem) => certificate_pem = Some(pem),
            Err(e) => reasons.push(e),
        }
    }

    if enrolled {
        grace::save(&mut tx, &claim.device, manifest_hash, &first_failures)
            .await
            .map_err(internal)?;
    }
    if enrolled && !oversharing {
        let payload = serde_json::to_value(claim).map_err(internal)?;
        claims::store(
            &mut tx,
            &app.kek,
            now,
            &claim.device,
            &payload,
            verified.jws(),
            reasons.is_empty(),
        )
        .await
        .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    if !reasons.is_empty() {
        return Err(denied(reasons));
    }
    let checkpoint = app.checkpoint().await?;
    Ok(Json(json!({
        "status": "accepted",
        "warnings": warnings,
        "certificate_pem": certificate_pem,
        "ca_pem": app.keys.ca.cert_pem,
        "log_checkpoint": checkpoint.to_string(),
    })))
}

async fn index(State(app): State<App>) -> Result<Html<String>, Reply> {
    let devices: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM devices WHERE manifest_hash = $1 AND state = 'approved'",
    )
    .bind(app.manifest.hash().as_str())
    .fetch_one(&app.db)
    .await
    .map_err(internal)?;
    let (allowed, denied): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE allowed), count(*) FILTER (WHERE NOT allowed) \
         FROM claims WHERE received_at > now() - interval '24 hours'",
    )
    .fetch_one(&app.db)
    .await
    .map_err(internal)?;
    let tree = app.tree().await?;
    Ok(Html(format!(
        include_str!("index.html"),
        devices = devices,
        allowed = allowed,
        denied = denied,
        manifest = app.manifest.hash(),
        company = app.company.key.fingerprint(),
        log_size = tree.size(),
        log_root = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(root(&tree.leaves).0)
        },
        log_witnesses = app.log.witnesses.len(),
        ca = app.keys.ca.fingerprint,
    )))
}

async fn publish_manifest(db: &PgPool, manifest: &Manifest) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    translog::lock(&mut tx).await?;
    let published: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM log_entries WHERE kind = 'manifest_published' AND data->>'manifest' = $1)",
    )
    .bind(manifest.hash().as_str())
    .fetch_one(&mut *tx)
    .await?;
    if !published {
        let entry = translog::append(
            &mut tx,
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
    tx.commit().await?;
    Ok(())
}

async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match PgPoolOptions::new().max_connections(10).connect(url).await {
            Ok(db) => return Ok(db),
            Err(e) if tokio::time::Instant::now() < deadline => {
                eprintln!("database not ready, retrying: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn witness_keys() -> anyhow::Result<Vec<WitnessKey>> {
    std::env::var("WITNESS_KEYS")
        .unwrap_or_default()
        .split([',', ' ', '\n'])
        .filter(|k| !k.is_empty())
        .map(|k| WitnessKey::parse(k).map_err(|e| anyhow::anyhow!("WITNESS_KEYS: {e}")))
        .collect()
}

fn log_origin() -> anyhow::Result<String> {
    let origin = std::env::var("LOG_ORIGIN").unwrap_or_else(|_| "pact.example.com/log".into());
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

async fn invite(db: &PgPool, url: &str, ttl: &str, note: &str) -> anyhow::Result<()> {
    let ttl = invitations::parse_ttl(ttl)?;
    let parsed = url.parse::<axum::http::Uri>()?;
    if !matches!(parsed.scheme_str(), Some("https" | "http")) || parsed.host().is_none() {
        anyhow::bail!("--url must be an http(s) URL, got {url:?}");
    }
    let keys = Keys::load_or_create(db, &SealingKey::kek_from_env()?).await?;
    let (code, expires) = invitations::create(db, ttl, note).await?;
    let invitation = Invitation::new(
        url,
        &PublicKey::from(&keys.manifest),
        &log_key(&keys)?,
        code,
    );
    eprint!(
        "One-time invitation, valid until {}{}\n{}",
        expires.format("%Y-%m-%dT%H:%M:%SZ"),
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
    println!("{}", invitation.encode());
    Ok(())
}

async fn admin_devices(db: &PgPool, command: DevicesCommand) -> anyhow::Result<()> {
    let (device, action) = match command {
        DevicesCommand::List => {
            print!("{}", devices::list(db).await?);
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
    for (manifest, state) in devices::apply(db, &device, action).await? {
        println!("{} {device} for {manifest}", state.as_str());
    }
    Ok(())
}

fn router(app: App) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/v1/manifest", get(self::manifest))
        .route("/v1/enroll", post(enroll))
        .route("/v1/log", get(legacy_log))
        .route("/v1/log/key", get(self::log_key_text))
        .route("/v1/log/checkpoint", get(log_checkpoint))
        .route("/v1/log/entries", get(log_entries))
        .route("/v1/log/proof/inclusion", get(inclusion))
        .route("/v1/log/proof/consistency", get(consistency))
        .route("/v1/log/witness", post(witness))
        .route("/v1/nonce", post(nonce))
        .route("/v1/claim", post(claim))
        .with_state(app)
}

async fn serve(db: PgPool) -> anyhow::Result<()> {
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let manifest_path =
        std::env::var("MANIFEST_PATH").unwrap_or_else(|_| "examples/manifest.toml".into());
    let toml = std::fs::read_to_string(&manifest_path)?;
    let manifest = Manifest::parse(toml.as_bytes())?;
    eprintln!("enforcing {manifest_path} {}", manifest.hash());
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
    let log = Log {
        key: log_key(&keys)?,
        signer: keys.log.clone(),
        witnesses: witness_keys()?,
        cache: Mutex::default(),
    };
    eprintln!("log key {}", log.key.vkey());
    for w in &log.witnesses {
        eprintln!("witness {}", w.vkey());
    }
    publish_manifest(&db, &manifest).await?;
    let company = Endorsement::sign(&keys.manifest, manifest.hash());
    eprintln!("company key {}", company.key.fingerprint());
    eprintln!("CA {}", keys.ca.fingerprint);
    if auto_approve {
        eprintln!("AUTO_APPROVE=true: enrolled devices are approved without IT");
    }
    let sealed = claims::seal_plaintext(&db, &kek).await?;
    if sealed > 0 {
        eprintln!("sealed {sealed} plaintext claims from an earlier version");
    }
    tokio::spawn(delete_expired_nonces(db.clone()));
    tokio::spawn(enforce_retention(
        db.clone(),
        manifest.body().claim_retention.clone(),
    ));
    let app = router(App {
        db,
        manifest: Arc::new(manifest),
        toml: toml.into(),
        company,
        keys: Arc::new(keys),
        log: Arc::new(log),
        auto_approve,
        limiter: Arc::new(limiter),
        nonce_limiter: Arc::new(nonce_limiter),
        max_nonces,
        kek: Arc::new(kek),
    });
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let db = connect(&std::env::var("DATABASE_URL")?).await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(db).await,
        Command::Invite { ttl, note, url } => invite(&db, &url, &ttl, note.trim()).await,
        Command::Devices { command } => admin_devices(&db, command).await,
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

    async fn test_app(enrol_limit: u32, nonce_limit: u32) -> Router {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&[5; 32]);
        let keys = Keys::load_or_create(&db, &kek).await.unwrap();
        let toml = include_str!("../../../examples/manifest.toml");
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        let log = Log {
            key: LogKey::new("log.example.org/test", &PublicKey::from(&keys.log)),
            signer: keys.log.clone(),
            witnesses: vec![],
            cache: Mutex::default(),
        };
        let minute = Duration::from_secs(60);
        router(App {
            db,
            company: Endorsement::sign(&keys.manifest, manifest.hash()),
            manifest: Arc::new(manifest),
            toml: toml.into(),
            keys: Arc::new(keys),
            log: Arc::new(log),
            auto_approve: false,
            limiter: Arc::new(Limiter::new(enrol_limit, minute, 100)),
            nonce_limiter: Arc::new(Limiter::new(nonce_limit, minute, 100)),
            max_nonces: 10_000,
            kek: Arc::new(kek),
        })
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

    #[test]
    fn entries_are_served_in_pages_of_at_most_256() {
        assert_eq!(entries_range(None, None, 1000), Ok((0, 256)));
        assert_eq!(entries_range(Some(900), None, 1000), Ok((900, 1000)));
        assert_eq!(entries_range(Some(10), Some(266), 1000), Ok((10, 266)));
        assert!(entries_range(Some(10), Some(267), 1000).is_err());
        assert!(entries_range(Some(5), Some(4), 1000).is_err());
        assert!(entries_range(Some(0), Some(1001), 1000).is_err());
        assert_eq!(entries_range(None, None, 0), Ok((0, 0)));
    }
}
