use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use open_pact_core::{Decision, Manifest, Reason, evaluate, verify_claim};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

type Reply = (StatusCode, Json<Value>);

#[derive(Clone)]
struct App {
    db: PgPool,
    manifest: Arc<Manifest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    jws: String,
}

fn internal(e: sqlx::Error) -> Reply {
    eprintln!("db error: {e}");
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

async fn healthz(State(app): State<App>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&app.db).await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "db unavailable"),
    }
}

async fn nonce(State(app): State<App>) -> Result<Json<Value>, Reply> {
    let nonce: String = (0..32)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();
    sqlx::query("INSERT INTO nonces (nonce, expires_at) VALUES ($1, now() + interval '5 minutes')")
        .bind(&nonce)
        .execute(&app.db)
        .await
        .map_err(internal)?;
    Ok(Json(json!({ "nonce": nonce })))
}

async fn claim(
    State(app): State<App>,
    body: Result<Json<ClaimRequest>, axum::extract::rejection::JsonRejection>,
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
    let decision = evaluate(&app.manifest, claim, chrono::Utc::now());
    let oversharing = matches!(&decision, Decision::Deny { reasons } if reasons.iter().any(Reason::breaks_disclosure_contract));
    if !oversharing {
        let payload = serde_json::to_value(claim).expect("claim serializes");
        sqlx::query("INSERT INTO claims (device, claim, jws, allowed) VALUES ($1, $2, $3, $4)")
            .bind(claim.device.as_str())
            .bind(&payload)
            .bind(verified.jws())
            .bind(matches!(decision, Decision::Allow { .. }))
            .execute(&app.db)
            .await
            .map_err(internal)?;
    }
    match decision {
        Decision::Allow { warnings } => {
            let warnings: Vec<String> = warnings.iter().map(ToString::to_string).collect();
            Ok(Json(json!({"status": "accepted", "warnings": warnings})))
        }
        Decision::Deny { reasons } => {
            Err(denied(reasons.iter().map(ToString::to_string).collect()))
        }
    }
}

async fn index(State(app): State<App>) -> Result<Html<String>, Reply> {
    let (claims, devices): (i64, i64) =
        sqlx::query_as("SELECT count(*), count(DISTINCT device) FROM claims")
            .fetch_one(&app.db)
            .await
            .map_err(internal)?;
    Ok(Html(format!(
        "<!doctype html><title>open-pact gateway</title><h1>open-pact gateway</h1>\
         <p>Manifest: <code>{}</code></p><p>Claims stored: {claims}</p><p>Distinct devices: {devices}</p>",
        app.manifest.hash()
    )))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL")?;
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let manifest_path =
        std::env::var("MANIFEST_PATH").unwrap_or_else(|_| "examples/manifest.toml".into());
    let manifest = Manifest::parse(&std::fs::read(&manifest_path)?)?;
    eprintln!("enforcing {manifest_path} {}", manifest.hash());
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/v1/nonce", post(nonce))
        .route("/v1/claim", post(claim))
        .with_state(App {
            db,
            manifest: Arc::new(manifest),
        });
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
