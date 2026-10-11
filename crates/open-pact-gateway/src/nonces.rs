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
async fn issue_in(tx: &mut PgConnection, cap: i64) -> sqlx::Result<Option<String>> {
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
