//! Durability contract. Issuing a nonce commits with `synchronous_commit = off`, so the advisory
//! lock below is held for no WAL flush. A database crash can lose an issued, unused nonce (the
//! last 0.6 s of commits at most, three times `wal_writer_delay`). The client then gets
//! "unknown or used nonce" and asks for a new one. Consuming a nonce always commits with
//! `synchronous_commit = on`: a consumed nonce never comes back after a crash, and that flush
//! also covers every earlier issue. This holds for a single primary with `fsync` on. A promoted
//! asynchronous replica can lose consumes as well; use synchronous replication where that matters.

use sqlx::{PgConnection, PgPool};

/// A new single-use nonce valid for 5 minutes, or `None` while `cap` unexpired nonces are
/// outstanding.
pub async fn issue(db: &PgPool, cap: i64) -> sqlx::Result<Option<String>> {
    let mut tx = db.begin().await?;
    let nonce = issue_in(&mut tx, cap).await?;
    tx.commit().await?;
    Ok(nonce)
}

/// Issuers take turns on a transaction-scoped advisory lock. A guarded INSERT alone is not enough:
/// its snapshot misses rows that a concurrent transaction has not committed yet. The INSERT runs
/// as a later statement, so its snapshot includes the nonce of the issuer that held the lock.
///
/// Both settings are pinned here, not left to the server defaults. READ COMMITTED gives every
/// statement a new snapshot, which the count needs. `synchronous_commit = off` ends the lock
/// hold at the commit without waiting for a WAL flush; the commit is still visible to the next
/// lock holder before the lock is released. `SET LOCAL` ends with the transaction.
async fn issue_in(tx: &mut PgConnection, cap: i64) -> sqlx::Result<Option<String>> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL synchronous_commit = off")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('open-pact nonces'))")
        .execute(&mut *tx)
        .await?;
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    let inserted = sqlx::query(
        "INSERT INTO nonces (nonce, expires_at) SELECT $1, now() + interval '5 minutes' \
         WHERE (SELECT count(*) FROM nonces WHERE expires_at > now()) < $2",
    )
    .bind(&nonce)
    .bind(cap)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    Ok((inserted == 1).then_some(nonce))
}

/// Removes a nonce. `Some(true)`: it was live and is consumed. `Some(false)`: it had expired.
/// `None`: unknown or already used. The commit is durable whatever the server or session default.
pub async fn consume(db: &PgPool, nonce: &str) -> sqlx::Result<Option<bool>> {
    let mut tx = db.begin().await?;
    let live = consume_in(&mut tx, nonce).await?;
    tx.commit().await?;
    Ok(live)
}

async fn consume_in(tx: &mut PgConnection, nonce: &str) -> sqlx::Result<Option<bool>> {
    sqlx::query("SET LOCAL synchronous_commit = on")
        .execute(&mut *tx)
        .await?;
    sqlx::query_scalar("DELETE FROM nonces WHERE nonce = $1 RETURNING expires_at > now()")
        .bind(nonce)
        .fetch_optional(&mut *tx)
        .await
}

pub async fn delete_expired(db: &PgPool) -> sqlx::Result<u64> {
    Ok(sqlx::query("DELETE FROM nonces WHERE expires_at <= now()")
        .execute(db)
        .await?
        .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdb;
    use sqlx::Connection;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    async fn count(db: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM nonces")
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn stops_at_the_cap_of_outstanding_nonces_and_expired_ones_do_not_count() {
        let db = testdb::fresh().await;
        for _ in 0..3 {
            assert!(issue(&db, 3).await.unwrap().is_some());
        }
        assert_eq!(issue(&db, 3).await.unwrap(), None);
        assert_eq!(count(&db).await, 3);

        sqlx::query("UPDATE nonces SET expires_at = now() - interval '1 second'")
            .execute(&db)
            .await
            .unwrap();
        assert!(issue(&db, 3).await.unwrap().is_some());
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn an_issuer_waits_for_an_uncommitted_one_and_counts_its_nonce() {
        let db = testdb::fresh().await;
        let mut first = db.begin().await.unwrap();
        assert!(issue_in(&mut first, 1).await.unwrap().is_some());
        let second = tokio::spawn({
            let db = db.clone();
            async move { issue(&db, 1).await.unwrap() }
        });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!second.is_finished(), "the second issuer did not wait");
        first.commit().await.unwrap();
        assert_eq!(second.await.unwrap(), None);
        assert_eq!(count(&db).await, 1);
    }

    async fn show(conn: &mut PgConnection, setting: &str) -> String {
        sqlx::query_scalar(&format!("SHOW {setting}"))
            .fetch_one(conn)
            .await
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn the_commit_settings_end_with_their_transaction_on_the_same_connection() {
        let db = testdb::fresh().await;
        let mut conn = db.acquire().await.unwrap();
        sqlx::query("SET synchronous_commit = local")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("SET default_transaction_isolation = 'serializable'")
            .execute(&mut *conn)
            .await
            .unwrap();

        let mut tx = conn.begin().await.unwrap();
        let nonce = issue_in(&mut tx, 3).await.unwrap().unwrap();
        assert_eq!(show(&mut tx, "synchronous_commit").await, "off");
        assert_eq!(
            show(&mut tx, "transaction_isolation").await,
            "read committed"
        );
        tx.commit().await.unwrap();
        assert_eq!(show(&mut conn, "synchronous_commit").await, "local");
        assert_eq!(
            show(&mut conn, "transaction_isolation").await,
            "serializable"
        );

        let mut tx = conn.begin().await.unwrap();
        assert_eq!(consume_in(&mut tx, &nonce).await.unwrap(), Some(true));
        assert_eq!(show(&mut tx, "synchronous_commit").await, "on");
        tx.commit().await.unwrap();
        assert_eq!(show(&mut conn, "synchronous_commit").await, "local");
    }

    /// The consume commit has to reach disk at its own commit, not at a later write. The pool has
    /// an asynchronous session default, checked first. `marker` is read inside the transaction,
    /// before its commit record, so a synchronous commit has flushed at least up to it. Without
    /// the override in `consume_in` the flush trails by up to the WAL writer delay.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn a_consume_is_flushed_at_its_own_commit_under_an_async_session_default() {
        let db = testdb::fresh_with_session_settings(&[("synchronous_commit", "off")]).await;
        let mut conn = db.acquire().await.unwrap();
        assert_eq!(show(&mut conn, "synchronous_commit").await, "off");
        drop(conn);
        for round in 0..10 {
            let nonce = issue(&db, 10).await.unwrap().unwrap();
            let mut tx = db.begin().await.unwrap();
            assert_eq!(consume_in(&mut tx, &nonce).await.unwrap(), Some(true));
            let marker: String = sqlx::query_scalar("SELECT pg_current_wal_insert_lsn()::text")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let flushed: bool =
                sqlx::query_scalar("SELECT pg_current_wal_flush_lsn() >= $1::pg_lsn")
                    .bind(&marker)
                    .fetch_one(&db)
                    .await
                    .unwrap();
            assert!(
                flushed,
                "round {round}: the consume commit was not flushed at its commit"
            );
            assert_eq!(consume(&db, &nonce).await.unwrap(), None);
        }
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn a_nonce_is_consumed_once_and_an_expired_one_is_reported_as_expired() {
        let db = testdb::fresh().await;
        let nonce = issue(&db, 10).await.unwrap().unwrap();
        assert_eq!(consume(&db, &nonce).await.unwrap(), Some(true));
        assert_eq!(consume(&db, &nonce).await.unwrap(), None);

        let nonce = issue(&db, 10).await.unwrap().unwrap();
        sqlx::query("UPDATE nonces SET expires_at = now() - interval '1 second'")
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(consume(&db, &nonce).await.unwrap(), Some(false));
        assert_eq!(count(&db).await, 0);
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn concurrent_issuers_never_pass_the_cap() {
        let db = testdb::fresh().await;
        let issuers: Vec<_> = (0..40)
            .map(|_| {
                let db = db.clone();
                tokio::spawn(async move { issue(&db, 15).await.unwrap() })
            })
            .collect();
        let mut issued = 0;
        for issuer in issuers {
            issued += i64::from(issuer.await.unwrap().is_some());
        }
        assert_eq!(issued, 15);
        assert_eq!(count(&db).await, 15);
    }

    /// Driven by `scripts/check-nonce-durability.sh` against its own PostgreSQL instance; it does
    /// nothing without `NONCE_PROBE`. The WAL sync counter is cluster wide, so it cannot be
    /// asserted next to other tests.
    #[tokio::test]
    #[ignore = "run by scripts/check-nonce-durability.sh"]
    async fn durability_probe() {
        let Ok(phase) = std::env::var("NONCE_PROBE") else {
            return;
        };
        let url = std::env::var("NONCE_PROBE_URL").expect("NONCE_PROBE_URL");
        let file = std::env::var("NONCE_PROBE_FILE").expect("NONCE_PROBE_FILE");
        match phase.as_str() {
            "wal-sync" => probe_wal_sync(&url).await,
            "before-crash" => probe_before_crash(&url, &file).await,
            "after-restart" => probe_after_restart(&url, &file).await,
            other => panic!("unknown NONCE_PROBE {other:?}"),
        }
    }

    async fn probe_pool(url: &str, settings: &[(&str, &str)]) -> PgPool {
        let options: PgConnectOptions = url.parse().expect("NONCE_PROBE_URL");
        PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options.options(settings.iter().copied()))
            .await
            .expect("connect probe database")
    }

    /// Backends flush their statistics when they exit, so each sample closes its pool first.
    async fn wal_syncs(url: &str) -> i64 {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let pool = probe_pool(url, &[]).await;
        let syncs = sqlx::query_scalar("SELECT wal_sync FROM pg_stat_wal")
            .fetch_one(&pool)
            .await
            .unwrap();
        pool.close().await;
        syncs
    }

    async fn probe_wal_sync(url: &str) {
        let pool = probe_pool(url, &[]).await;
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        assert_eq!(show(&mut conn, "synchronous_commit").await, "on");
        drop(conn);
        issue(&pool, 100_000).await.unwrap().unwrap();
        pool.close().await;
        let before = wal_syncs(url).await;
        let pool = probe_pool(url, &[]).await;
        for _ in 0..100 {
            issue(&pool, 100_000).await.unwrap().unwrap();
        }
        pool.close().await;
        let delta = wal_syncs(url).await - before;
        println!("wal_sync delta for 100 sequential issues: {delta}");
        assert!(
            delta < 50,
            "issuing waits for a WAL flush: {delta} syncs for 100 issues"
        );
    }

    async fn probe_before_crash(url: &str, file: &str) {
        let pool = probe_pool(url, &[]).await;
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query("TRUNCATE nonces").execute(&pool).await.unwrap();
        pool.close().await;

        let pool = probe_pool(url, &[("synchronous_commit", "off")]).await;
        let mut conn = pool.acquire().await.unwrap();
        assert_eq!(show(&mut conn, "synchronous_commit").await, "off");
        drop(conn);
        let mut issued = Vec::new();
        for _ in 0..5 {
            issued.push(issue(&pool, 5).await.unwrap().unwrap());
        }
        assert_eq!(issue(&pool, 5).await.unwrap(), None, "the cap of 5 held");
        assert_eq!(consume(&pool, &issued[0]).await.unwrap(), Some(true));
        let late = issue(&pool, 5).await.unwrap().unwrap();
        let mut lines = vec![format!("consumed={}", issued[0]), format!("late={late}")];
        lines.extend(issued[1..].iter().map(|n| format!("kept={n}")));
        std::fs::write(file, lines.join("\n")).unwrap();
        println!("READY: kill the database now");
    }

    async fn probe_after_restart(url: &str, file: &str) {
        let text = std::fs::read_to_string(file).unwrap();
        let named = |key: &str| -> Vec<String> {
            text.lines()
                .filter_map(|l| l.strip_prefix(&format!("{key}=")))
                .map(String::from)
                .collect()
        };
        let pool = probe_pool(url, &[]).await;
        let present: Vec<String> = sqlx::query_scalar("SELECT nonce FROM nonces")
            .fetch_all(&pool)
            .await
            .unwrap();
        let consumed = &named("consumed")[0];
        assert!(
            !present.contains(consumed),
            "the consumed nonce came back after the crash"
        );
        for kept in named("kept") {
            assert!(present.contains(&kept), "an earlier issued nonce was lost");
        }
        assert!(
            present.len() <= 5,
            "more live nonces than the cap: {}",
            present.len()
        );
        let late = &named("late")[0];
        println!(
            "after the crash: {} nonces live, consumed nonce gone, issued after the last consume: {}",
            present.len(),
            if present.contains(late) {
                "kept"
            } else {
                "lost"
            }
        );
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn deletes_only_expired_nonces() {
        let db = testdb::fresh().await;
        for _ in 0..4 {
            issue(&db, 10).await.unwrap();
        }
        sqlx::query(
            "UPDATE nonces SET expires_at = now() - interval '1 second' \
             WHERE nonce IN (SELECT nonce FROM nonces LIMIT 3)",
        )
        .execute(&db)
        .await
        .unwrap();
        assert_eq!(delete_expired(&db).await.unwrap(), 3);
        assert_eq!(count(&db).await, 1);
    }
}
