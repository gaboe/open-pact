mod keys;
mod translog;

use std::fmt::Display;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{Query, State, rejection::JsonRejection},
    http::{StatusCode, header},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use open_pact_core::{
    Checkpoint, Decision, Endorsement, Entry, EntryKind, LogHash, LogKey, Manifest, Note,
    Pseudonym, PublicKey, Reason, SignedManifest, SigningKey, WitnessKey, consistency_proof,
    evaluate, inclusion_proof, root, verify_claim,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};

use keys::Keys;

type Reply = (StatusCode, Json<Value>);

#[derive(Clone)]
struct App {
    db: PgPool,
    manifest: Arc<Manifest>,
    toml: Arc<str>,
    company: Endorsement,
    keys: Arc<Keys>,
    log: Arc<Log>,
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
#[serde(deny_unknown_fields)]
struct EnrollRequest {
    signed_manifest: SignedManifest,
    device_key: PublicKey,
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

fn commitment(salt_hex: &str, device: &Pseudonym) -> Result<String, Reply> {
    let mut commitment = Sha256::new();
    commitment.update(hex::decode(salt_hex).map_err(internal)?);
    commitment.update(device.as_str());
    Ok(format!("sha256:{}", hex::encode(commitment.finalize())))
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

async fn log_key(State(app): State<App>) -> impl IntoResponse {
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

async fn nonce(State(app): State<App>) -> Result<Json<Value>, Reply> {
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    sqlx::query("INSERT INTO nonces (nonce, expires_at) VALUES ($1, now() + interval '5 minutes')")
        .bind(&nonce)
        .execute(&app.db)
        .await
        .map_err(internal)?;
    Ok(Json(json!({ "nonce": nonce })))
}

async fn enroll(
    State(app): State<App>,
    body: Result<Json<EnrollRequest>, JsonRejection>,
) -> Result<Json<Value>, Reply> {
    let Json(req) = body.map_err(|e| denied(vec![e.body_text()]))?;
    let signed = &req.signed_manifest;
    let manifest = signed.verify().map_err(|e| denied(vec![e.to_string()]))?;
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
    let owner_key = serde_json::to_value(&signed.owner.key).map_err(internal)?;
    let fresh_salt = hex::encode(rand::random::<[u8; 32]>());

    let mut tx = app.db.begin().await.map_err(internal)?;
    translog::lock(&mut tx).await.map_err(internal)?;
    let inserted: Option<String> = sqlx::query_scalar(
        "INSERT INTO devices (pseudonym, manifest_hash, owner_key, owner_signature, salt) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING RETURNING salt",
    )
    .bind(device.as_str())
    .bind(app.manifest.hash().as_str())
    .bind(&owner_key)
    .bind(String::from(signed.owner.signature.clone()))
    .bind(&fresh_salt)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    let (salt, log_index) = match inserted {
        Some(salt) => {
            let entry = translog::append(
                &mut tx,
                EntryKind::DeviceEnrolled,
                json!({ "commitment": commitment(&salt, &device)? }),
            )
            .await
            .map_err(internal)?;
            (salt, entry.index)
        }
        None => {
            let (existing_owner, salt): (Value, String) = sqlx::query_as(
                "SELECT owner_key, salt FROM devices WHERE pseudonym = $1 AND manifest_hash = $2",
            )
            .bind(device.as_str())
            .bind(app.manifest.hash().as_str())
            .fetch_one(&mut *tx)
            .await
            .map_err(internal)?;
            if existing_owner != owner_key {
                return Err((
                    StatusCode::CONFLICT,
                    Json(
                        json!({"status": "denied", "reasons": ["device is enrolled by another owner key"]}),
                    ),
                ));
            }
            let index: i64 = sqlx::query_scalar(
                "SELECT idx FROM log_entries WHERE kind = 'device_enrolled' AND data->>'commitment' = $1",
            )
            .bind(commitment(&salt, &device)?)
            .fetch_one(&mut *tx)
            .await
            .map_err(internal)?;
            (salt, u64::try_from(index).map_err(internal)?)
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
    let enrolled: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM devices WHERE pseudonym = $1 AND manifest_hash = $2)",
    )
    .bind(claim.device.as_str())
    .bind(app.manifest.hash().as_str())
    .fetch_one(&app.db)
    .await
    .map_err(internal)?;

    let decision = evaluate(&app.manifest, claim, chrono::Utc::now());
    let oversharing = matches!(&decision, Decision::Deny { reasons } if reasons.iter().any(Reason::breaks_disclosure_contract));
    let strings = |rs: &[Reason]| rs.iter().map(ToString::to_string).collect::<Vec<_>>();
    let (warnings, mut reasons) = match &decision {
        Decision::Allow { warnings } => (strings(warnings), vec![]),
        Decision::Deny { reasons } => (vec![], strings(reasons)),
    };
    if !enrolled {
        reasons.insert(0, "device not enrolled".into());
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

    if enrolled && !oversharing {
        let payload = serde_json::to_value(claim).map_err(internal)?;
        sqlx::query("INSERT INTO claims (device, claim, jws, allowed) VALUES ($1, $2, $3, $4)")
            .bind(claim.device.as_str())
            .bind(&payload)
            .bind(verified.jws())
            .bind(reasons.is_empty())
            .execute(&app.db)
            .await
            .map_err(internal)?;
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

async fn index(State(app): State<App>) -> Result<Html<String>, Reply> {
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE manifest_hash = $1")
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL")?;
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let manifest_path =
        std::env::var("MANIFEST_PATH").unwrap_or_else(|_| "examples/manifest.toml".into());
    let toml = std::fs::read_to_string(&manifest_path)?;
    let manifest = Manifest::parse(toml.as_bytes())?;
    eprintln!("enforcing {manifest_path} {}", manifest.hash());
    let db = connect(&url).await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    let keys = Keys::load_or_create(&db).await?;
    let log = Log {
        key: LogKey::new(&log_origin()?, &PublicKey::from(&keys.log)),
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
    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/v1/manifest", get(self::manifest))
        .route("/v1/enroll", post(enroll))
        .route("/v1/log", get(legacy_log))
        .route("/v1/log/key", get(log_key))
        .route("/v1/log/checkpoint", get(log_checkpoint))
        .route("/v1/log/entries", get(log_entries))
        .route("/v1/log/proof/inclusion", get(inclusion))
        .route("/v1/log/proof/consistency", get(consistency))
        .route("/v1/log/witness", post(witness))
        .route("/v1/nonce", post(nonce))
        .route("/v1/claim", post(claim))
        .with_state(App {
            db,
            manifest: Arc::new(manifest),
            toml: toml.into(),
            company,
            keys: Arc::new(keys),
            log: Arc::new(log),
        });
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
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
    use super::*;

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
