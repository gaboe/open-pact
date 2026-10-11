use chrono::{DateTime, Utc};
use open_pact_core::{FirstFailures, Pseudonym};
use sqlx::PgConnection;

pub async fn load(
    conn: &mut PgConnection,
    device: &Pseudonym,
    manifest: &str,
) -> sqlx::Result<FirstFailures> {
    let rows: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT control, first_failed_at FROM control_failures WHERE pseudonym = $1 AND manifest_hash = $2",
    )
    .bind(device.as_str())
    .bind(manifest)
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().collect())
}

/// Two claims of one device racing converge: an insert keeps the earlier start.
pub async fn save(
    conn: &mut PgConnection,
    device: &Pseudonym,
    manifest: &str,
    failures: &FirstFailures,
) -> sqlx::Result<()> {
    let (controls, starts): (Vec<String>, Vec<DateTime<Utc>>) =
        failures.iter().map(|(c, t)| (c.clone(), *t)).unzip();
    sqlx::query(
        "DELETE FROM control_failures WHERE pseudonym = $1 AND manifest_hash = $2 AND NOT (control = ANY($3))",
    )
    .bind(device.as_str())
    .bind(manifest)
    .bind(&controls)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO control_failures (pseudonym, manifest_hash, control, first_failed_at) \
         SELECT $1, $2, * FROM unnest($3::text[], $4::timestamptz[]) ON CONFLICT DO NOTHING",
    )
    .bind(device.as_str())
    .bind(manifest)
    .bind(&controls)
    .bind(&starts)
    .execute(conn)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use open_pact_core::{PublicKey, dev_key};

    use super::*;
    use crate::testdb;

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn stores_clears_and_keeps_the_earliest_start() {
        let db = testdb::fresh().await;
        let device = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        testdb::enrolled_device(&db, device.as_str(), "m").await;
        let mut conn = db.acquire().await.unwrap();
        let t0: DateTime<Utc> = "2026-10-12T09:00:00Z".parse().unwrap();

        let both = FirstFailures::from([("firewall".into(), t0), ("screen_lock".into(), t0)]);
        save(&mut conn, &device, "m", &both).await.unwrap();
        assert_eq!(load(&mut conn, &device, "m").await.unwrap(), both);
        assert!(load(&mut conn, &device, "other").await.unwrap().is_empty());

        let later = FirstFailures::from([("firewall".into(), t0 + TimeDelta::hours(1))]);
        save(&mut conn, &device, "m", &later).await.unwrap();
        assert_eq!(
            load(&mut conn, &device, "m").await.unwrap(),
            FirstFailures::from([("firewall".into(), t0)]),
            "a racing claim cannot move the start later, and the passing control is cleared"
        );

        save(&mut conn, &device, "m", &FirstFailures::new())
            .await
            .unwrap();
        assert!(load(&mut conn, &device, "m").await.unwrap().is_empty());
    }

    /// R2-M4: claim A reads the empty state and saves it unchanged (an invalid envelope). Claim
    /// B of the same device starts a failure meanwhile. A's stale save must not erase B's clock.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn a_stale_concurrent_claim_cannot_erase_a_committed_failure() {
        let db = testdb::fresh().await;
        let device = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        testdb::enrolled_device(&db, device.as_str(), "m").await;
        let t0: DateTime<Utc> = "2026-10-12T09:00:00Z".parse().unwrap();

        let mut a = db.begin().await.unwrap();
        crate::devices::lock(&mut a, &device, "m").await.unwrap();
        let stale = load(&mut a, &device, "m").await.unwrap();
        assert!(stale.is_empty());

        let mut b_conn = db.acquire().await.unwrap();
        let b_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *b_conn)
            .await
            .unwrap();
        let b_device = device.clone();
        let b = tokio::spawn(async move {
            let mut b = sqlx::Connection::begin(&mut *b_conn).await.unwrap();
            crate::devices::lock(&mut b, &b_device, "m").await.unwrap();
            let mut failures = load(&mut b, &b_device, "m").await.unwrap();
            failures.entry("firewall".into()).or_insert(t0);
            save(&mut b, &b_device, "m", &failures).await.unwrap();
            b.commit().await.unwrap();
        });
        let waits_or_done = async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock')",
                )
                .bind(b_pid)
                .fetch_one(&db)
                .await
                .unwrap();
                if waiting || b.is_finished() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), waits_or_done)
            .await
            .expect("claim B neither waits nor finishes");

        save(&mut a, &device, "m", &stale).await.unwrap();
        a.commit().await.unwrap();
        b.await.unwrap();
        let mut conn = db.acquire().await.unwrap();
        assert_eq!(
            load(&mut conn, &device, "m").await.unwrap(),
            FirstFailures::from([("firewall".into(), t0)]),
            "the failure clock B started survives A's stale save"
        );
    }
}
