use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use open_pact_core::Claim;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

type Reply = (StatusCode, Json<Value>);

fn internal(e: sqlx::Error) -> Reply {
    eprintln!("db error: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"status": "error"})))
}

fn denied(reason: &str) -> Reply {
    (StatusCode::FORBIDDEN, Json(json!({"status": "denied", "reason": reason})))
}

async fn healthz(State(db): State<PgPool>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&db).await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "db unavailable"),
    }
}

async fn nonce(State(db): State<PgPool>) -> Result<Json<Value>, Reply> {
    let nonce: String = (0..32).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
    sqlx::query("INSERT INTO nonces (nonce, expires_at) VALUES ($1, now() + interval '5 minutes')")
        .bind(&nonce)
        .execute(&db)
        .await
        .map_err(internal)?;
    Ok(Json(json!({ "nonce": nonce })))
}

async fn claim(State(db): State<PgPool>, Json(raw): Json<Value>) -> Result<Json<Value>, Reply> {
    let Ok(claim) = serde_json::from_value::<Claim>(raw.clone()) else {
        return Err(denied("malformed claim"));
    };
    let live: Option<bool> =
        sqlx::query_scalar("DELETE FROM nonces WHERE nonce = $1 RETURNING expires_at > now()")
            .bind(&claim.nonce)
            .fetch_optional(&db)
            .await
            .map_err(internal)?;
    match live {
        None => return Err(denied("unknown or used nonce")),
        Some(false) => return Err(denied("expired nonce")),
        Some(true) => {}
    }
    sqlx::query("INSERT INTO claims (device, claim) VALUES ($1, $2)")
        .bind(&claim.device)
        .bind(&raw)
        .execute(&db)
        .await
        .map_err(internal)?;
    Ok(Json(json!({"status": "accepted"})))
}

async fn index(State(db): State<PgPool>) -> Result<Html<String>, Reply> {
    let (claims, devices): (i64, i64) =
        sqlx::query_as("SELECT count(*), count(DISTINCT device) FROM claims")
            .fetch_one(&db)
            .await
            .map_err(internal)?;
    Ok(Html(format!(
        "<!doctype html><title>open-pact gateway</title><h1>open-pact gateway</h1>\
         <p>Claims stored: {claims}</p><p>Distinct devices: {devices}</p>"
    )))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL")?;
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let db = PgPoolOptions::new().max_connections(10).connect(&url).await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/v1/nonce", post(nonce))
        .route("/v1/claim", post(claim))
        .with_state(db);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
