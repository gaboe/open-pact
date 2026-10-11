mod keys;
mod translog;

use std::fmt::Display;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State, rejection::JsonRejection},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use open_pact_core::{
    Decision, Endorsement, EntryKind, Head, Manifest, Pseudonym, PublicKey, Reason, SignedManifest,
    evaluate, verify_claim,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, postgres::PgPoolOptions};

use keys::Keys;

type Reply = (StatusCode, Json<Value>);

#[derive(Clone)]
struct App {
    db: PgPool,
    manifest: Arc<Manifest>,
    toml: Arc<str>,
    company: Endorsement,
    keys: Arc<Keys>,
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
struct LogQuery {
    from: Option<u64>,
}

fn internal(e: impl Display) -> Reply {
    eprintln!("internal error: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"status": "error"})),
    )
}

fn denied(reasons: Vec<String>) -> Reply {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"status": "denied", "reasons": reasons})),
    )
}

impl App {
    async fn head(&self, conn: &mut PgConnection) -> Result<Head, Reply> {
        let last = translog::last(conn)
            .await
            .map_err(internal)?
            .ok_or_else(|| internal("transparency log is empty"))?;
        Ok(Head::sign(&self.keys.log, &last))
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

async fn log(State(app): State<App>, Query(q): Query<LogQuery>) -> Result<Json<Value>, Reply> {
    let mut tx = app.db.begin().await.map_err(internal)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let entries = translog::since(&mut tx, q.from.unwrap_or(0))
        .await
        .map_err(internal)?;
    let head = app.head(&mut tx).await?;
    tx.commit().await.map_err(internal)?;
    Ok(Json(json!({"entries": entries, "head": head})))
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
    let salt = match inserted {
        Some(salt) => {
            let mut commitment = Sha256::new();
            commitment.update(hex::decode(&salt).map_err(internal)?);
            commitment.update(device.as_str());
            let commitment = format!("sha256:{}", hex::encode(commitment.finalize()));
            translog::append(
                &mut tx,
                EntryKind::DeviceEnrolled,
                json!({ "commitment": commitment }),
            )
            .await
            .map_err(internal)?;
            salt
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
            salt
        }
    };
    let head = app.head(&mut tx).await?;
    tx.commit().await.map_err(internal)?;
    Ok(Json(json!({
        "status": "enrolled",
        "device": device,
        "salt": salt,
        "log_head": head,
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
    let head = app.head(&mut *app.conn().await?).await?;
    Ok(Json(json!({
        "status": "accepted",
        "warnings": warnings,
        "certificate_pem": certificate_pem,
        "ca_pem": app.keys.ca.cert_pem,
        "log_head": head,
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
    let head = app.head(&mut *app.conn().await?).await?;
    Ok(Html(format!(
        include_str!("index.html"),
        devices = devices,
        allowed = allowed,
        denied = denied,
        manifest = app.manifest.hash(),
        company = app.company.key.fingerprint(),
        log_index = head.index,
        log_hash = head.hash,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL")?;
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let manifest_path =
        std::env::var("MANIFEST_PATH").unwrap_or_else(|_| "examples/manifest.toml".into());
    let toml = std::fs::read_to_string(&manifest_path)?;
    let manifest = Manifest::parse(toml.as_bytes())?;
    eprintln!("enforcing {manifest_path} {}", manifest.hash());
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    let keys = Keys::load_or_create(&db).await?;
    publish_manifest(&db, &manifest).await?;
    let company = Endorsement::sign(&keys.manifest, manifest.hash());
    eprintln!("company key {}", company.key.fingerprint());
    eprintln!("CA {}", keys.ca.fingerprint);
    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/v1/manifest", get(self::manifest))
        .route("/v1/enroll", post(enroll))
        .route("/v1/log", get(log))
        .route("/v1/nonce", post(nonce))
        .route("/v1/claim", post(claim))
        .with_state(App {
            db,
            manifest: Arc::new(manifest),
            toml: toml.into(),
            company,
            keys: Arc::new(keys),
        });
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
