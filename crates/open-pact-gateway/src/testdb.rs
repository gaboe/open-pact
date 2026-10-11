//! A fresh, migrated database per test. The tests that use it are `#[ignore]`d; run them with
//! `TEST_DATABASE_URL=postgres://... cargo test -p open-pact-gateway -- --ignored`.

use sqlx::PgPool;
use sqlx::postgres::PgConnectOptions;

pub async fn fresh() -> PgPool {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");
    let admin = PgPool::connect(&url)
        .await
        .expect("connect TEST_DATABASE_URL");
    let name = format!("open_pact_test_{}", hex::encode(rand::random::<[u8; 8]>()));
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .expect("create test database");
    let options: PgConnectOptions = url.parse().expect("TEST_DATABASE_URL");
    let db = PgPool::connect_with(options.database(&name))
        .await
        .expect("connect test database");
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("migrate");
    db
}

pub async fn enrolled_device(db: &PgPool, pseudonym: &str, manifest: &str) {
    sqlx::query(
        "INSERT INTO devices (pseudonym, manifest_hash, owner_key, owner_signature, salt, state) \
         VALUES ($1, $2, '{}', '', '00', 'approved')",
    )
    .bind(pseudonym)
    .bind(manifest)
    .execute(db)
    .await
    .expect("insert device");
}
