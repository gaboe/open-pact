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
}
