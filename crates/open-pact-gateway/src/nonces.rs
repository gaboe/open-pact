use sqlx::PgPool;

/// A new single-use nonce valid for 5 minutes, or `None` while `cap` unexpired nonces are
/// outstanding. The count and the insert are one statement, so concurrent requests cannot both
/// pass a check made before either inserted.
pub async fn issue(db: &PgPool, cap: i64) -> sqlx::Result<Option<String>> {
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    let inserted = sqlx::query(
        "INSERT INTO nonces (nonce, expires_at) SELECT $1, now() + interval '5 minutes' \
         WHERE (SELECT count(*) FROM nonces WHERE expires_at > now()) < $2",
    )
    .bind(&nonce)
    .bind(cap)
    .execute(db)
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
