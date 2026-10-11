//! Claims at rest (PAPER 4.4, 4.8). Each claim, with its device pseudonym and JWS, is sealed
//! under the key of its calendar month (UTC). Period keys are sealed under the KEK. Retention
//! deletes claims older than `claim_retention` and then the key of every month that has ended
//! before that cutoff, which leaves its claims unreadable in every backup.

use anyhow::Context;
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use open_pact_core::{EntryKind, Pseudonym, Span};
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};

use crate::seal::SealingKey;
use crate::translog;

fn period_of(t: DateTime<Utc>) -> NaiveDate {
    t.date_naive().with_day(1).expect("day 1 exists")
}

fn key_name(period: NaiveDate) -> String {
    format!("claim_key:{}", period.format("%Y-%m"))
}

fn row_name(period: NaiveDate) -> String {
    format!("claim:{}", period.format("%Y-%m"))
}

async fn period_key(
    conn: &mut PgConnection,
    kek: &SealingKey,
    period: NaiveDate,
) -> anyhow::Result<SealingKey> {
    let name = key_name(period);
    sqlx::query(
        "INSERT INTO claim_keys (period, wrapped_key) VALUES ($1, $2) ON CONFLICT (period) DO NOTHING",
    )
    .bind(period)
    .bind(kek.seal(&name, &rand::random::<[u8; 32]>()))
    .execute(&mut *conn)
    .await?;
    let wrapped: String =
        sqlx::query_scalar("SELECT wrapped_key FROM claim_keys WHERE period = $1")
            .bind(period)
            .fetch_one(conn)
            .await?;
    let key: [u8; 32] = kek
        .open(&name, &wrapped)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} is not 32 bytes"))?;
    Ok(SealingKey::new(&key))
}

fn sealed_body(device: &str, claim: &Value, jws: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&json!({"device": device, "claim": claim, "jws": jws}))
        .expect("JSON values serialize")
}

/// `received_at` and the period come from the same `now`, so a claim at a month boundary is
/// sealed under the key of the month its timestamp names.
pub async fn store(
    conn: &mut PgConnection,
    kek: &SealingKey,
    now: DateTime<Utc>,
    device: &Pseudonym,
    claim: &Value,
    jws: &str,
    allowed: bool,
) -> anyhow::Result<()> {
    let period = period_of(now);
    let key = period_key(conn, kek, period).await?;
    sqlx::query(
        "INSERT INTO claims (received_at, period, sealed, allowed) VALUES ($1, $2, $3, $4)",
    )
    .bind(now)
    .bind(period)
    .bind(key.seal(
        &row_name(period),
        &sealed_body(device.as_str(), claim, Some(jws)),
    ))
    .bind(allowed)
    .execute(conn)
    .await?;
    Ok(())
}

/// Seals claims stored in plaintext by earlier versions, each under the key of its
/// `received_at` month. Old plaintext can remain in dead tuples, the WAL and earlier backups.
pub async fn seal_plaintext(db: &PgPool, kek: &SealingKey) -> anyhow::Result<u64> {
    type Plain = (i64, String, Value, Option<String>, DateTime<Utc>);
    let rows: Vec<Plain> = sqlx::query_as(
        "SELECT id, device, claim, jws, received_at FROM claims WHERE sealed IS NULL ORDER BY id",
    )
    .fetch_all(db)
    .await?;
    let mut sealed = 0;
    for (id, device, claim, jws, received_at) in rows {
        let mut tx = db.begin().await?;
        let period = period_of(received_at);
        let key = period_key(&mut tx, kek, period).await?;
        sealed += sqlx::query(
            "UPDATE claims SET period = $1, sealed = $2, device = NULL, claim = NULL, jws = NULL \
             WHERE id = $3 AND sealed IS NULL",
        )
        .bind(period)
        .bind(key.seal(
            &row_name(period),
            &sealed_body(&device, &claim, jws.as_deref()),
        ))
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
    }
    Ok(sealed)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Purged {
    pub claims: u64,
    pub period_keys: u64,
}

/// Deletes claims received before `now - retention` and the keys of months that ended before
/// that cutoff, in one transaction with a `retention_purge` log entry that holds only the counts.
/// Appends nothing when nothing was deleted.
pub async fn purge(db: &PgPool, retention: &Span, now: DateTime<Utc>) -> anyhow::Result<Purged> {
    let cutoff = retention
        .before(now)
        .context("claim_retention reaches before the calendar")?;
    let mut tx = db.begin().await?;
    translog::lock(&mut tx).await?;
    let claims = sqlx::query("DELETE FROM claims WHERE received_at < $1 OR period < $2")
        .bind(cutoff)
        .bind(period_of(cutoff))
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let period_keys = sqlx::query("DELETE FROM claim_keys WHERE period < $1")
        .bind(period_of(cutoff))
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let purged = Purged {
        claims,
        period_keys,
    };
    if claims > 0 || period_keys > 0 {
        translog::append(
            &mut tx,
            EntryKind::RetentionPurge,
            json!({"claims": claims, "period_keys": period_keys}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(purged)
}

#[cfg(test)]
pub async fn open_all(db: &PgPool, kek: &SealingKey) -> anyhow::Result<Vec<Value>> {
    let rows: Vec<(NaiveDate, String)> =
        sqlx::query_as("SELECT period, sealed FROM claims ORDER BY id")
            .fetch_all(db)
            .await?;
    let mut out = vec![];
    for (period, sealed) in rows {
        let key = period_key(&mut *db.acquire().await?, kek, period).await?;
        out.push(serde_json::from_slice(
            &key.open(&row_name(period), &sealed)?,
        )?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use open_pact_core::{PublicKey, dev_key};

    use super::*;
    use crate::testdb;

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    async fn count(db: &PgPool, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(db).await.unwrap()
    }

    #[test]
    fn a_claim_belongs_to_the_utc_month_it_was_received_in() {
        assert_eq!(
            period_of(at("2026-10-31T23:59:59Z")).to_string(),
            "2026-10-01"
        );
        assert_eq!(
            period_of(at("2026-11-01T00:00:00Z")).to_string(),
            "2026-11-01"
        );
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn seals_claims_and_shreds_a_month_once_all_its_claims_are_past_retention() {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&[3; 32]);
        let device = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        let mut conn = db.acquire().await.unwrap();
        for t in [
            "2026-09-10T08:00:00Z",
            "2026-10-15T08:30:00Z",
            "2026-10-15T09:30:00Z",
        ] {
            let claim = json!({"results": {"firewall": "on"}, "time": t});
            store(&mut conn, &kek, at(t), &device, &claim, "jws", true)
                .await
                .unwrap();
        }
        let raw: Vec<String> = sqlx::query_scalar("SELECT sealed FROM claims")
            .fetch_all(&db)
            .await
            .unwrap();
        assert!(raw.iter().all(|r| !r.contains("firewall")
            && !r.contains(device.as_str().trim_start_matches("pseudonym:"))));
        let opened = open_all(&db, &kek).await.unwrap();
        assert_eq!(opened[0]["device"], device.as_str());
        assert_eq!(opened[0]["claim"]["results"]["firewall"], "on");
        assert_eq!(opened[0]["jws"], "jws");
        assert_eq!(count(&db, "SELECT count(*) FROM claim_keys").await, 2);

        let short: Span = "1h".to_string().try_into().unwrap();
        let purged = purge(&db, &short, at("2026-10-15T10:00:00Z"))
            .await
            .unwrap();
        assert_eq!(
            purged,
            Purged {
                claims: 2,
                period_keys: 1
            }
        );
        let left: Vec<NaiveDate> = sqlx::query_scalar("SELECT period FROM claim_keys")
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(left, [NaiveDate::from_ymd_opt(2026, 10, 1).unwrap()]);
        assert_eq!(count(&db, "SELECT count(*) FROM claims").await, 1);
        let entries = translog::since(&mut conn, 0).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, EntryKind::RetentionPurge);
        assert_eq!(entries[0].data, json!({"claims": 2, "period_keys": 1}));

        let again = purge(&db, &short, at("2026-10-15T10:00:00Z"))
            .await
            .unwrap();
        assert_eq!(
            again,
            Purged {
                claims: 0,
                period_keys: 0
            }
        );
        assert_eq!(translog::since(&mut conn, 0).await.unwrap().len(), 1);

        let purged = purge(&db, &short, at("2026-11-01T10:30:00Z"))
            .await
            .unwrap();
        assert_eq!(
            purged,
            Purged {
                claims: 1,
                period_keys: 1
            }
        );
        assert_eq!(count(&db, "SELECT count(*) FROM claim_keys").await, 0);
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn seals_plaintext_claims_from_earlier_versions_in_place() {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&[4; 32]);
        sqlx::query(
            "INSERT INTO claims (device, claim, jws, allowed, received_at) VALUES \
             ('pseudonym:aa', '{\"results\": {\"firewall\": \"on\"}}', 'jws-a', true, '2026-08-05T12:00:00Z'), \
             ('pseudonym:bb', '{\"v\": 0}', NULL, NULL, '2026-10-02T12:00:00Z')",
        )
        .execute(&db)
        .await
        .unwrap();
        assert_eq!(seal_plaintext(&db, &kek).await.unwrap(), 2);
        assert_eq!(seal_plaintext(&db, &kek).await.unwrap(), 0);
        assert_eq!(
            count(
                &db,
                "SELECT count(*) FROM claims WHERE device IS NOT NULL OR claim IS NOT NULL OR jws IS NOT NULL"
            )
            .await,
            0
        );
        let opened = open_all(&db, &kek).await.unwrap();
        assert_eq!(
            opened[0],
            json!({"device": "pseudonym:aa", "claim": {"results": {"firewall": "on"}}, "jws": "jws-a"})
        );
        assert_eq!(opened[1]["jws"], Value::Null);
        let periods: Vec<NaiveDate> = sqlx::query_scalar("SELECT period FROM claims ORDER BY id")
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(
            periods,
            [
                NaiveDate::from_ymd_opt(2026, 8, 1).unwrap(),
                NaiveDate::from_ymd_opt(2026, 10, 1).unwrap()
            ]
        );
    }
}
