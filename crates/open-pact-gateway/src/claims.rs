//! Claims at rest (PAPER 4.4, 4.8). Each claim gets a deletion deadline from the `claim_retention`
//! it was accepted under and, with its device pseudonym and JWS, is sealed under the key of its
//! deadline's calendar month (UTC). Period keys are sealed under the KEK. Retention deletes claims
//! past their deadline, then the keys of ended months that no claim uses. A database backup made
//! before a key was deleted still holds it, so the claims stay readable from that backup with the
//! KEK until the backup expires (R2-M2).

use std::collections::HashMap;

use anyhow::Context;
use open_pact_core::{EntryKind, ManifestHash, Pseudonym, Span};
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};
use time::{Date, OffsetDateTime};

use crate::seal::SealingKey;
use crate::translog;

fn period_of(t: OffsetDateTime) -> Date {
    t.date().replace_day(1).expect("day 1 exists")
}

fn key_name(period: Date) -> String {
    format!(
        "claim_key:{}",
        open_pact_core::timestamp::year_month(period)
    )
}

fn row_name(period: Date) -> String {
    format!("claim:{}", open_pact_core::timestamp::year_month(period))
}

async fn period_key(
    conn: &mut PgConnection,
    kek: &SealingKey,
    period: Date,
) -> anyhow::Result<SealingKey> {
    sqlx::query(
        "INSERT INTO claim_keys (period, wrapped_key) VALUES ($1, $2) ON CONFLICT (period) DO NOTHING",
    )
    .bind(period)
    .bind(kek.seal(&key_name(period), &rand::random::<[u8; 32]>()))
    .execute(&mut *conn)
    .await?;
    open_period_key(conn, kek, period).await
}

async fn open_period_key(
    conn: &mut PgConnection,
    kek: &SealingKey,
    period: Date,
) -> anyhow::Result<SealingKey> {
    let name = key_name(period);
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

fn deadline(retention: &Span, received_at: OffsetDateTime) -> anyhow::Result<OffsetDateTime> {
    retention
        .after(received_at)
        .context("claim_retention reaches past the calendar")
}

/// The deadline of a claim stored before deadlines were recorded (R3-M2). Only the current
/// manifest's body is known, so a claim made under it keeps `received_at + retention`. A claim
/// made under any other manifest, or with no manifest, had an unknown `claim_retention`. The
/// shortest one a manifest allows is zero, so that claim is due at once and the next purge
/// deletes it. A later manifest never extends the retention a device owner accepted.
fn legacy_deadline(
    current: &ManifestHash,
    retention: &Span,
    claim: &Value,
    received_at: OffsetDateTime,
) -> anyhow::Result<OffsetDateTime> {
    if claim.get("manifest").and_then(Value::as_str) == Some(current.as_str()) {
        deadline(retention, received_at)
    } else {
        Ok(received_at)
    }
}

/// The claim is deleted at `now + retention` and sealed under the key of that deadline's month,
/// so claims kept for different spans never share a key.
#[allow(clippy::too_many_arguments)]
pub async fn store(
    conn: &mut PgConnection,
    kek: &SealingKey,
    retention: &Span,
    now: OffsetDateTime,
    device: &Pseudonym,
    claim: &Value,
    jws: &str,
    allowed: bool,
) -> anyhow::Result<()> {
    let delete_after = deadline(retention, now)?;
    let period = period_of(delete_after);
    let key = period_key(conn, kek, period).await?;
    sqlx::query(
        "INSERT INTO claims (received_at, delete_after, period, sealed, allowed) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(now)
    .bind(delete_after)
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

/// Seals claims stored in plaintext by earlier versions, each with its [`legacy_deadline`] and
/// under the key of its month. Old plaintext can remain in dead tuples, the WAL and earlier backups.
pub async fn seal_plaintext(
    db: &PgPool,
    kek: &SealingKey,
    current: &ManifestHash,
    retention: &Span,
) -> anyhow::Result<u64> {
    type Plain = (i64, String, Value, Option<String>, OffsetDateTime);
    let rows: Vec<Plain> = sqlx::query_as(
        "SELECT id, device, claim, jws, received_at FROM claims WHERE sealed IS NULL ORDER BY id",
    )
    .fetch_all(db)
    .await?;
    let mut sealed = 0;
    for (id, device, claim, jws, received_at) in rows {
        let mut tx = db.begin().await?;
        let delete_after = legacy_deadline(current, retention, &claim, received_at)?;
        let period = period_of(delete_after);
        let key = period_key(&mut tx, kek, period).await?;
        sealed += sqlx::query(
            "UPDATE claims SET delete_after = $1, period = $2, sealed = $3, device = NULL, \
             claim = NULL, jws = NULL WHERE id = $4 AND sealed IS NULL",
        )
        .bind(delete_after)
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

/// Gives claims sealed before deadlines existed their [`legacy_deadline`].
pub async fn set_missing_deadlines(
    db: &PgPool,
    kek: &SealingKey,
    current: &ManifestHash,
    retention: &Span,
) -> anyhow::Result<u64> {
    let rows: Vec<(i64, OffsetDateTime, Date, String)> = sqlx::query_as(
        "SELECT id, received_at, period, sealed FROM claims WHERE delete_after IS NULL",
    )
    .fetch_all(db)
    .await?;
    let mut conn = db.acquire().await?;
    let (mut ids, mut deadlines) = (vec![], vec![]);
    for (id, received_at, period, sealed) in rows {
        let key = open_period_key(&mut conn, kek, period).await?;
        let body: Value = serde_json::from_slice(&key.open(&row_name(period), &sealed)?)?;
        ids.push(id);
        deadlines.push(legacy_deadline(
            current,
            retention,
            &body["claim"],
            received_at,
        )?);
    }
    Ok(sqlx::query(
        "UPDATE claims SET delete_after = d.at FROM unnest($1::bigint[], $2::timestamptz[]) AS d(id, at) \
         WHERE claims.id = d.id AND claims.delete_after IS NULL",
    )
    .bind(&ids)
    .bind(&deadlines)
    .execute(db)
    .await?
    .rows_affected())
}

/// A claim as the gateway stored it, opened: the device and the claim JSON as `stored_claim` wrote
/// them. The JWS stays sealed; reading results never needs it.
pub struct Stored {
    pub id: i64,
    pub received_at: OffsetDateTime,
    pub allowed: Option<bool>,
    pub device: String,
    pub claim: Value,
}

/// The columns `SELECT_STORED` returns.
pub type StoredRow = (
    i64,
    OffsetDateTime,
    Option<bool>,
    Option<Date>,
    Option<String>,
    Option<String>,
    Option<Value>,
);

pub const SELECT_STORED: &str =
    "SELECT id, received_at, allowed, period, sealed, device, claim FROM claims";

/// Opens stored claims for reading. It reads each month key once. A month whose key retention
/// deleted has no key, and its claims stay sealed for good.
pub struct Opener<'a> {
    db: &'a PgPool,
    kek: &'a SealingKey,
    keys: HashMap<Date, Option<SealingKey>>,
}

impl<'a> Opener<'a> {
    pub fn new(db: &'a PgPool, kek: &'a SealingKey) -> Self {
        Opener {
            db,
            kek,
            keys: HashMap::new(),
        }
    }

    /// `None` when the claim's month key is gone. A claim not sealed yet (an earlier version
    /// stored it, and `serve` has not run since) is read from its plain columns.
    pub async fn open(&mut self, row: StoredRow) -> anyhow::Result<Option<Stored>> {
        let (id, received_at, allowed, period, sealed, device, claim) = row;
        let (device, claim) = match (period, sealed) {
            (Some(period), Some(sealed)) => {
                if !self.keys.contains_key(&period) {
                    let wrapped: Option<String> =
                        sqlx::query_scalar("SELECT wrapped_key FROM claim_keys WHERE period = $1")
                            .bind(period)
                            .fetch_optional(self.db)
                            .await?;
                    let key = match wrapped {
                        Some(wrapped) => {
                            let name = key_name(period);
                            let bytes: [u8; 32] = self
                                .kek
                                .open(&name, &wrapped)?
                                .try_into()
                                .map_err(|_| anyhow::anyhow!("{name} is not 32 bytes"))?;
                            Some(SealingKey::new(&bytes))
                        }
                        None => None,
                    };
                    self.keys.insert(period, key);
                }
                let Some(key) = &self.keys[&period] else {
                    return Ok(None);
                };
                let mut body: Value =
                    serde_json::from_slice(&key.open(&row_name(period), &sealed)?)?;
                let device = match body["device"].take() {
                    Value::String(device) => device,
                    _ => anyhow::bail!("claim {id} has no device"),
                };
                (device, body["claim"].take())
            }
            _ => match (device, claim) {
                (Some(device), Some(claim)) => (device, claim),
                _ => anyhow::bail!("claim {id} is neither sealed nor stored in plain columns"),
            },
        };
        Ok(Some(Stored {
            id,
            received_at,
            allowed,
            device,
            claim,
        }))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Purged {
    pub claims: u64,
    pub period_keys: u64,
}

/// Deletes claims past their own deadline, and claims received before `now - retention` when the
/// current retention is shorter. Then deletes the key of every month that has ended and no
/// remaining claim uses. Store never creates the key of an ended month, so a claim in flight keeps
/// its key. One transaction with a `retention_purge` log entry that holds only the counts; appends
/// nothing when nothing was deleted.
pub async fn purge(db: &PgPool, retention: &Span, now: OffsetDateTime) -> anyhow::Result<Purged> {
    let cutoff = retention
        .before(now)
        .context("claim_retention reaches before the calendar")?;
    let mut tx = db.begin().await?;
    translog::lock(&mut tx).await?;
    let claims = sqlx::query("DELETE FROM claims WHERE delete_after <= $1 OR received_at < $2")
        .bind(now)
        .bind(cutoff)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let period_keys = sqlx::query(
        "DELETE FROM claim_keys k WHERE period < $1 \
         AND NOT EXISTS (SELECT 1 FROM claims c WHERE c.period = k.period)",
    )
    .bind(period_of(now))
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
    let rows: Vec<(Date, String)> = sqlx::query_as("SELECT period, sealed FROM claims ORDER BY id")
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

    fn at(s: &str) -> OffsetDateTime {
        open_pact_core::timestamp::parse_rfc3339(s).unwrap()
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
        let short: Span = "1h".to_string().try_into().unwrap();
        for t in [
            "2026-09-10T08:00:00Z",
            "2026-10-15T08:30:00Z",
            "2026-10-15T09:30:00Z",
        ] {
            let claim = json!({"results": {"firewall": "on"}, "time": t});
            store(&mut conn, &kek, &short, at(t), &device, &claim, "jws", true)
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
        let left: Vec<Date> = sqlx::query_scalar("SELECT period FROM claim_keys")
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(left, [open_pact_core::timestamp::ymd(2026, 10, 1).unwrap()]);
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

    /// R2-M3: the owner consented to the retention of the manifest a claim was accepted under.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn a_later_manifest_cannot_extend_a_claims_retention_but_can_shorten_it() {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&[5; 32]);
        let device = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        let mut conn = db.acquire().await.unwrap();
        let hour: Span = "1h".to_string().try_into().unwrap();
        let year: Span = "12mo".to_string().try_into().unwrap();
        let t = at("2026-10-15T08:00:00Z");
        store(
            &mut conn,
            &kek,
            &hour,
            t,
            &device,
            &json!({"v": "short"}),
            "jws",
            true,
        )
        .await
        .unwrap();
        store(
            &mut conn,
            &kek,
            &year,
            t,
            &device,
            &json!({"v": "long"}),
            "jws",
            true,
        )
        .await
        .unwrap();

        let purged = purge(&db, &year, at("2026-10-15T10:00:00Z")).await.unwrap();
        assert_eq!(
            purged.claims, 1,
            "the 1h claim goes although 12mo is current"
        );
        assert_eq!(open_all(&db, &kek).await.unwrap()[0]["claim"]["v"], "long");
        assert_eq!(
            purge(&db, &year, at("2026-11-01T00:00:00Z")).await.unwrap(),
            Purged {
                claims: 0,
                period_keys: 1
            },
            "the key of the 1h claim goes once its deadline month has ended"
        );

        let purged = purge(&db, &hour, at("2026-11-01T01:00:00Z")).await.unwrap();
        assert_eq!(
            purged.claims, 1,
            "a shorter current retention deletes the 12mo claim"
        );
        assert_eq!(count(&db, "SELECT count(*) FROM claims").await, 0);
    }

    /// R3-M2: a claim from before deadlines existed was accepted under a policy the gateway did
    /// not record, so a longer current retention must not keep it.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn migration_does_not_extend_a_legacy_claim_to_a_longer_current_retention() {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&[7; 32]);
        let device = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        let mut conn = db.acquire().await.unwrap();
        let hour: Span = "1h".to_string().try_into().unwrap();
        let year: Span = "12mo".to_string().try_into().unwrap();
        let earlier = ManifestHash::of(b"fictional earlier manifest");
        let current = ManifestHash::of(b"fictional current manifest");
        let received = at("2026-10-15T08:00:00Z");
        let now = at("2026-10-15T10:00:00Z");
        for manifest in [&earlier, &current] {
            let claim = json!({"manifest": manifest});
            store(
                &mut conn, &kek, &hour, received, &device, &claim, "jws", true,
            )
            .await
            .unwrap();
        }
        sqlx::query("UPDATE claims SET delete_after = NULL")
            .execute(&db)
            .await
            .unwrap();
        for claim in [json!({"manifest": earlier}), json!({"manifest": current})] {
            sqlx::query(
                "INSERT INTO claims (device, claim, jws, allowed, received_at) VALUES \
                 ('pseudonym:aa', $1, 'jws-a', true, $2)",
            )
            .bind(claim)
            .bind(received)
            .execute(&db)
            .await
            .unwrap();
        }

        seal_plaintext(&db, &kek, &current, &year).await.unwrap();
        set_missing_deadlines(&db, &kek, &current, &year)
            .await
            .unwrap();
        assert_eq!(
            purge(&db, &year, now).await.unwrap().claims,
            2,
            "neither legacy claim may outlive the unknown policy it was accepted under"
        );
        let kept: Vec<OffsetDateTime> =
            sqlx::query_scalar("SELECT delete_after FROM claims ORDER BY id")
                .fetch_all(&db)
                .await
                .unwrap();
        assert_eq!(
            kept,
            [at("2027-10-15T08:00:00Z"), at("2027-10-15T08:00:00Z")],
            "claims made under the current manifest keep its retention"
        );
        for opened in open_all(&db, &kek).await.unwrap() {
            assert_eq!(opened["claim"]["manifest"], current.as_str());
        }
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn seals_plaintext_claims_from_earlier_versions_in_place() {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&[4; 32]);
        let current = ManifestHash::of(b"fictional current manifest");
        let first = json!({"manifest": current, "results": {"firewall": "on"}});
        sqlx::query(
            "INSERT INTO claims (device, claim, jws, allowed, received_at) VALUES \
             ('pseudonym:aa', $1, 'jws-a', true, '2026-08-05T12:00:00Z'), \
             ('pseudonym:bb', '{\"v\": 0}', NULL, NULL, '2026-10-02T12:00:00Z')",
        )
        .bind(&first)
        .execute(&db)
        .await
        .unwrap();
        let day: Span = "1d".to_string().try_into().unwrap();
        assert_eq!(seal_plaintext(&db, &kek, &current, &day).await.unwrap(), 2);
        assert_eq!(seal_plaintext(&db, &kek, &current, &day).await.unwrap(), 0);
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
            json!({"device": "pseudonym:aa", "claim": first, "jws": "jws-a"})
        );
        assert_eq!(opened[1]["jws"], Value::Null);
        let periods: Vec<Date> = sqlx::query_scalar("SELECT period FROM claims ORDER BY id")
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(
            periods,
            [
                open_pact_core::timestamp::ymd(2026, 8, 1).unwrap(),
                open_pact_core::timestamp::ymd(2026, 10, 1).unwrap()
            ]
        );
        let deadlines: Vec<OffsetDateTime> =
            sqlx::query_scalar("SELECT delete_after FROM claims ORDER BY id")
                .fetch_all(&db)
                .await
                .unwrap();
        assert_eq!(
            deadlines,
            [at("2026-08-06T12:00:00Z"), at("2026-10-02T12:00:00Z")],
            "a claim with no manifest had an unknown retention and is due at once"
        );
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn claims_sealed_under_the_current_manifest_get_its_retention_as_a_deadline() {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&[6; 32]);
        let device = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        let mut conn = db.acquire().await.unwrap();
        let hour: Span = "1h".to_string().try_into().unwrap();
        let t = at("2026-01-31T08:00:00Z");
        let current = ManifestHash::of(b"fictional current manifest");
        let claim = json!({"manifest": current});
        store(&mut conn, &kek, &hour, t, &device, &claim, "jws", true)
            .await
            .unwrap();
        sqlx::query("UPDATE claims SET delete_after = NULL")
            .execute(&db)
            .await
            .unwrap();
        let month: Span = "1mo".to_string().try_into().unwrap();
        let dated = set_missing_deadlines(&db, &kek, &current, &month);
        assert_eq!(dated.await.unwrap(), 1);
        let again = set_missing_deadlines(&db, &kek, &current, &month);
        assert_eq!(again.await.unwrap(), 0);
        let deadline: OffsetDateTime = sqlx::query_scalar("SELECT delete_after FROM claims")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(deadline, at("2026-02-28T08:00:00Z"));

        assert_eq!(
            purge(&db, &month, at("2026-02-15T00:00:00Z"))
                .await
                .unwrap(),
            Purged {
                claims: 0,
                period_keys: 0
            },
            "an ended month's key stays while a claim sealed under it is live"
        );
        assert_eq!(open_all(&db, &kek).await.unwrap().len(), 1);
        assert_eq!(
            purge(&db, &month, at("2026-03-01T00:00:00Z"))
                .await
                .unwrap(),
            Purged {
                claims: 1,
                period_keys: 1
            }
        );
    }
}

#[cfg(test)]
mod timestamp_pins {
    use super::*;

    fn at(s: &str) -> OffsetDateTime {
        open_pact_core::timestamp::parse_rfc3339(s).unwrap()
    }

    #[test]
    fn period_names_use_the_utc_month() {
        let period = period_of(at("2026-10-12T23:59:59.9Z"));
        assert_eq!(key_name(period), "claim_key:2026-10");
        assert_eq!(row_name(period), "claim:2026-10");
        assert_eq!(
            key_name(period_of(at("2026-10-01T00:00:00Z"))),
            "claim_key:2026-10"
        );
        assert_eq!(
            key_name(period_of(at("2026-09-30T23:30:00-02:00"))),
            "claim_key:2026-10"
        );
    }

    #[test]
    fn deadlines_clamp_the_month_and_keep_fractions() {
        let span = Span::try_from("1mo".to_string()).unwrap();
        assert_eq!(
            open_pact_core::timestamp::rfc3339_auto(
                deadline(&span, at("2026-01-31T10:00:00.5Z")).unwrap()
            ),
            "2026-02-28T10:00:00.500Z"
        );
    }
}
