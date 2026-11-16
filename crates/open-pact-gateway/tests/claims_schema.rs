//! The real binary on the claims read commands against a database with no schema: they fail with
//! a hint and write nothing, so reading results never migrates the database.

use std::process::{Command, Output};

use base64::Engine;
use sqlx::PgPool;

async fn empty_database() -> String {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");
    let admin = PgPool::connect(&url).await.unwrap();
    let name = format!(
        "open_pact_claims_{}",
        hex::encode(rand::random::<[u8; 8]>())
    );
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let (base, _) = url.rsplit_once('/').unwrap();
    format!("{base}/{name}")
}

fn run(args: &[&str], database_url: &str) -> Output {
    let kek = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    Command::new(env!("CARGO_BIN_EXE_open-pact-gateway"))
        .args(args)
        .env("DATABASE_URL", database_url)
        .env("GATEWAY_KEK", kek)
        .output()
        .unwrap()
}

#[tokio::test]
#[ignore = "needs TEST_DATABASE_URL"]
async fn claims_reads_refuse_a_database_without_the_schema_and_write_nothing() {
    let url = empty_database().await;
    for args in [
        &["claims", "list", "--json"][..],
        &["claims", "show", "987654", "--json"],
    ] {
        let output = run(args, &url);

        assert_eq!(output.status.code(), Some(1), "{args:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("the database schema is older than this gateway"),
            "{args:?} printed {stdout:?}"
        );
    }
    let db = PgPool::connect(&url).await.unwrap();
    let tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(tables, 0);
}
