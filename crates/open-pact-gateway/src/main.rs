mod claims;
use open_pact_core::{
    AcceptRequest, DeviceAuthPurpose, EntryWithProof, MyEntries, MyEntriesRequest, evaluate_under,
};
mod devices;
mod grace;
mod invitations;
mod keys;
mod nonces;
mod ratelimit;
mod seal;
mod siem;
#[cfg(test)]
mod testdb;
mod translog;
mod witness;

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
    Checkpoint, Claim, CsrHash, Decision, Endorsement, EnrolRequest, Entry, EntryKind, Evaluation,
    FirstFailures, Invitation, LogCheckpoint, LogHash, LogKey, Manifest, Note, NoteSignature,
    Pseudonym, PublicKey, Reason, SigningKey, Span, consistency_proof, inclusion_proof, root,
    verified_trust_level, verify_claim,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

use devices::{Action, State as DeviceState, commitment};
use keys::Keys;
use ratelimit::Limiter;
use seal::SealingKey;
use witness::Witnesses;

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
        #[arg(long, default_value = "72h", value_parser = invitations::parse_ttl)]
        ttl: chrono::Duration,
        /// Who the invitation is for. Stays in the gateway database, never in the log
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
    siem: Option<siem::Exporter>,
}

struct Log {
    signer: SigningKey,
    key: LogKey,
    witnesses: Witnesses,
    cache: Mutex<LogCache>,
}

/// Rows are append-only, so leaf hashes are read from the database once, and the checkpoint is
/// signed once per tree size.
#[derive(Default)]
struct LogCache {
    leaves: Vec<LogHash>,
    signed: Option<(Checkpoint, Note)>,
}

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

    /// The checkpoint of `tree` signed by the log key, and whether it was signed just now.
    fn signed(&self, tree: &Tree) -> (Checkpoint, Note, bool) {
        let mut cache = self.log.cache.lock().expect("log cache");
        if let Some((cp, note)) = cache
            .signed
            .clone()
            .filter(|(cp, _)| cp.size == tree.size())
        {
            return (cp, note, false);
        }
        let checkpoint = Checkpoint {
            origin: self.log.key.origin().to_string(),
            size: tree.size(),
            root: root(&tree.leaves),
        };
        let note = self.log.key.sign(&self.log.signer, &checkpoint);
        cache.signed = Some((checkpoint.clone(), note.clone()));
        (checkpoint, note, true)
    }

    /// The current checkpoint signed by the log key, with the witness cosignatures stored for it.
    /// A new checkpoint goes to the witnesses before any client sees it.
    async fn checkpoint(&self) -> Result<Note, Reply> {
        let tree = self.tree().await?;
        let (checkpoint, mut note, fresh) = self.signed(&tree);
        let mut cosignatures = self.cosignatures(&checkpoint).await?;
        let short = cosignatures.len() < self.log.witnesses.quorum;
        if fresh || (short && self.log.witnesses.retry_due()) {
            self.witness(&checkpoint, &note, &tree).await?;
            cosignatures = self.cosignatures(&checkpoint).await?;
        } else if short {
            // Another request may be pushing this checkpoint right now.
            self.log.witnesses.settled().await;
            cosignatures = self.cosignatures(&checkpoint).await?;
        }
        note.signatures.extend(cosignatures);
        Ok(note)
    }

    async fn cosignatures(&self, checkpoint: &Checkpoint) -> Result<Vec<NoteSignature>, Reply> {
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

    /// Asks the witnesses to cosign and stores what they return, newest per witness.
    async fn witness(
        &self,
        checkpoint: &Checkpoint,
        note: &Note,
        tree: &Tree,
    ) -> Result<(), Reply> {
        let cosigned = self
            .log
            .witnesses
            .cosign(note, checkpoint, tree.prefix(checkpoint.size))
            .await;
        for (name, sig) in cosigned {
            sqlx::query(
                "INSERT INTO log_cosignatures (size, root, witness, signature) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (size, root, witness) DO UPDATE SET signature = EXCLUDED.signature, received_at = now()",
            )
            .bind(i64::try_from(checkpoint.size).map_err(internal)?)
            .bind(checkpoint.root.to_string())
            .bind(name)
            .bind(sig.to_string().trim_end())
            .execute(&self.db)
            .await
            .map_err(internal)?;
        }
        Ok(())
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

fn device_denied() -> Reply {
    denied(vec!["device access denied".into()])
}

async fn consume_nonce(app: &App, nonce: &str) -> Result<(), Reply> {
    let live: Option<bool> =
        sqlx::query_scalar("DELETE FROM nonces WHERE nonce = $1 RETURNING expires_at > now()")
            .bind(nonce)
            .fetch_optional(&app.db)
            .await
            .map_err(internal)?;
    match live {
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
    State(app): State<App>,
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
/// signed the acceptance. The state, salt and grace clocks stay. A repeat answers the same.
async fn accept_manifest(
    State(app): State<App>,
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
    let mut tx = app.db.begin().await.map_err(internal)?;
    translog::lock(&mut tx).await.map_err(internal)?;
    let rows: Vec<(String, Value, String, String)> = sqlx::query_as(
        "SELECT manifest_hash, owner_key, state, salt FROM devices \
         WHERE pseudonym = $1 AND manifest_hash = ANY($2) FOR UPDATE",
    )
    .bind(req.pseudonym.as_str())
    .bind(vec![current.to_string(), req.previous.to_string()])
    .fetch_all(&mut *tx)
    .await
    .map_err(internal)?;
    let row = |hash: &str| rows.iter().find(|r| r.0 == hash);
    let (manifest, stored_owner, state, salt) = row(current.as_str())
        .or_else(|| row(req.previous.as_str()))
        .ok_or_else(device_denied)?;
    if *stored_owner != owner_key {
        return Err(denied(vec![
            "the owner key differs from the one that enrolled this device".into(),
        ]));
    }
    if manifest != current.as_str() {
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
        .bind(manifest)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
        translog::append(
            &mut tx,
            EntryKind::ManifestAccepted,
            json!({
                "commitment": commitment(salt, req.pseudonym.as_str()).map_err(internal)?,
                "manifest": current,
            }),
        )
        .await
        .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    Ok(Json(
        json!({"status": "accepted", "state": state, "manifest": current}),
    ))
}

async fn log_mine(
    State(app): State<App>,
    body: Result<Json<MyEntriesRequest>, JsonRejection>,
) -> Result<Json<MyEntries>, Reply> {
    let Json(request) = body.map_err(|_| device_denied())?;
    authenticate_device(&app, &request, DeviceAuthPurpose::LogMine).await?;
    let checkpoint = app.checkpoint().await?;
    let cp = Checkpoint::parse(&checkpoint.text).map_err(internal)?;
    let tree = app.tree().await?;
    let mut conn = app.conn().await?;
    let enrolment = devices::bound(&mut conn, &request.pseudonym, app.manifest.hash().as_str())
        .await
        .map_err(internal)?
        .filter(|e| e.state == DeviceState::Approved)
        .ok_or_else(device_denied)?;
    let commitment =
        devices::commitment(&enrolment.salt, request.pseudonym.as_str()).map_err(internal)?;
    let entries = translog::mine(&mut conn, cp.size, &enrolment.manifest, &commitment)
        .await
        .map_err(internal)?;
    let with_proof = |entry: Entry| -> Result<EntryWithProof, Reply> {
        let proof = inclusion_proof(tree.prefix(cp.size), entry.index).map_err(internal)?;
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
    Ok(Json(MyEntries {
        checkpoint: checkpoint.to_string(),
        manifest: manifest.ok_or_else(|| internal("manifest log entry missing"))?,
        device,
    }))
}

async fn claim(
    State(app): State<App>,
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
    let verified = verify_claim(&jws).map_err(|e| denied(vec![e.to_string()]))?;
    let claim = verified.claim();
    consume_nonce(&app, &claim.nonce).await?;
    let foreign = match &claim.log_checkpoint {
        Some(cp) => foreign_checkpoint(&app.tree().await?, cp),
        None => None,
    };
    let manifest_hash = claim.manifest.as_str();
    let mut tx = app.db.begin().await.map_err(internal)?;
    let state = devices::lock(&mut tx, &claim.device, manifest_hash)
        .await
        .map_err(internal)?;
    let consented = if state.is_some() && &claim.manifest != app.manifest.hash() {
        Arc::new(
            consented_manifest(&app.manifest, &claim.manifest, manifest_toml.as_deref())
                .map_err(|reason| denied(vec![reason]))?,
        )
    } else {
        app.manifest.clone()
    };
    let now = chrono::Utc::now();
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
    } = evaluate_under(&consented, &app.manifest, claim, now, &first_failures);
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
    if let (true, Some(csr)) = (reasons.is_empty(), csr) {
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
        let payload = stored_claim(claim, certificate_pem.as_deref()).map_err(internal)?;
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
    tx.commit().await.map_err(internal)?;
    if enrolled
        && !oversharing
        && let Some(exporter) = &app.siem
    {
        exporter.submit(siem::event(&consented, claim, &reasons, &warnings));
    }
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
    let manifest = Manifest::parse(toml.as_bytes()).map_err(|e| format!("manifest_toml: {e}"))?;
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
fn stored_claim(claim: &Claim, certificate_pem: Option<&str>) -> anyhow::Result<Value> {
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
    Ok(payload)
}

async fn index(State(app): State<App>) -> Result<Html<String>, Reply> {
    let tree = app.tree().await?;
    Ok(Html(format!(
        include_str!("index.html"),
        manifest = app.manifest.hash(),
        company = app.company.key.fingerprint(),
        log_size = tree.size(),
        log_root = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(root(&tree.leaves).0)
        },
        log_witnesses = app.log.witnesses.keys().len(),
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
async fn refresh_cosignatures(app: App, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        let Ok(tree) = app.tree().await else {
            continue;
        };
        let (checkpoint, note, _) = app.signed(&tree);
        let _ = app.witness(&checkpoint, &note, &tree).await;
    }
}

/// Denies a claim whose checkpoint is not a state of this gateway's log.
fn foreign_checkpoint(tree: &Tree, cp: &LogCheckpoint) -> Option<String> {
    let known = cp.size > 0 && cp.size <= tree.size() && root(tree.prefix(cp.size)) == cp.root;
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

async fn invite(db: &PgPool, url: &str, ttl: chrono::Duration, note: &str) -> anyhow::Result<()> {
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
        .route("/v1/log/proof/consistency", get(consistency))
        .route("/v1/nonce", post(nonce))
        .route("/v1/claim", post(claim))
        .route("/v1/log/mine", post(log_mine))
        .route("/v1/device/status", post(device_status))
        .route("/v1/device/accept", post(accept_manifest))
        .with_state(app)
}

async fn serve(db: PgPool) -> anyhow::Result<()> {
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let manifest_path =
        std::env::var("MANIFEST_PATH").unwrap_or_else(|_| "examples/manifest.toml".into());
    let toml = std::fs::read_to_string(&manifest_path)?;
    let manifest = Manifest::parse(toml.as_bytes())?;
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
    let log = Log {
        key: log_key(&keys)?,
        signer: keys.log.clone(),
        witnesses: Witnesses::new(witness_urls(), policy)?,
        cache: Mutex::default(),
    };
    eprintln!("log key {}", log.key.vkey());
    for w in log.witnesses.keys() {
        eprintln!("manifest witness {}", w.vkey());
    }
    for url in log.witnesses.urls() {
        eprintln!("pushing checkpoints to {url}");
    }
    if log.witnesses.urls().len() < log.witnesses.quorum {
        eprintln!(
            "WARNING: the manifest requires {} witness cosignatures but WITNESS_URLS lists {} witnesses; clients will raise a log alarm",
            log.witnesses.quorum,
            log.witnesses.urls().len()
        );
    }
    let refresh = match policy.and_then(|p| p.checkpoint_max_age.min_duration()) {
        Some(age) if !log.witnesses.urls().is_empty() => {
            let quarter = u64::try_from(age.num_seconds() / 4).unwrap_or(600);
            Some(Duration::from_secs(env_number(
                "WITNESS_REFRESH_SECS",
                quarter.clamp(10, 600),
            )?))
        }
        _ => None,
    };
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
    tokio::spawn(enforce_retention(
        db.clone(),
        manifest.body().claim_retention.clone(),
    ));
    let siem = siem::from_env(&manifest);
    let app = App {
        siem,
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
    };
    if let Some(every) = refresh {
        tokio::spawn(refresh_cosignatures(app.clone(), every));
    }
    let app = router(app);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
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
    let cli = Cli::parse();
    let db = connect(&std::env::var("DATABASE_URL")?).await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(db).await,
        Command::Invite { ttl, note, url } => invite(&db, &url, ttl, note.trim()).await,
        Command::Devices { command } => admin_devices(&db, command).await,
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
        let db = testdb::fresh_with_max_connections(max_connections).await;
        let kek = SealingKey::new(&TEST_KEK);
        let keys = Keys::load_or_create(&db, &kek).await.unwrap();
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        let log = Log {
            key: LogKey::new("log.example.org/test", &PublicKey::from(&keys.log)),
            signer: keys.log.clone(),
            witnesses: Witnesses::new(vec![], manifest.body().log.as_ref()).unwrap(),
            cache: Mutex::default(),
        };
        let minute = Duration::from_secs(60);
        let app = router(App {
            siem: None,
            db: db.clone(),
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
        });
        (app, db)
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
            time: chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap(),
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
            let (code, _) = invitations::create(&db, chrono::Duration::hours(1), note)
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
        let (received, delete_after): (
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ) = sqlx::query_as("SELECT received_at, delete_after FROM claims")
            .fetch_one(&db)
            .await
            .unwrap();
        let kept = (delete_after - received).num_days();
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
        assert!(!texts.contains("csr_pem") && !texts.contains("CERTIFICATE REQUEST"));
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
        let tree = Tree {
            leaves: (0u8..5).map(|i| open_pact_core::leaf_hash(&[i])).collect(),
        };
        let at = |size: u64| LogCheckpoint {
            size,
            root: root(tree.prefix(size)),
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
}
