use anyhow::bail;
use chrono::{DateTime, Duration, Utc};
use open_pact_core::{InvitationCode, InvitationHash, Pseudonym};
use sqlx::{PgConnection, PgPool};

pub const MAX_TTL: Duration = Duration::days(30);
const MAX_NOTE: usize = 200;

/// `30m`, `72h` or `7d`, at most 30 days.
pub fn parse_ttl(text: &str) -> anyhow::Result<Duration> {
    let (n, unit) = text.split_at(text.len().saturating_sub(1));
    let n: i64 =
        n.parse().ok().filter(|n| *n > 0).ok_or_else(|| {
            anyhow::anyhow!("TTL must be a positive number with m, h or d: {text:?}")
        })?;
    let ttl = match unit {
        "m" => Duration::minutes(n),
        "h" => Duration::hours(n),
        "d" => Duration::days(n),
        _ => bail!("TTL must end in m, h or d: {text:?}"),
    };
    if ttl > MAX_TTL {
        bail!("TTL {text} is longer than 30 days");
    }
    Ok(ttl)
}

pub async fn create(
    db: &PgPool,
    ttl: Duration,
    note: &str,
) -> anyhow::Result<(InvitationCode, DateTime<Utc>)> {
    if note.chars().count() > MAX_NOTE {
        bail!("note is longer than {MAX_NOTE} characters");
    }
    let code = InvitationCode::from_bytes(rand::random());
    let expires: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO invitations (hash, note, expires_at) VALUES ($1, $2, now() + $3) RETURNING expires_at",
    )
    .bind(code.hash().as_str())
    .bind(note)
    .bind(ttl)
    .fetch_one(db)
    .await?;
    Ok((code, expires))
}

/// Marks the invitation used by `device` if it exists, is unused and has not expired. One UPDATE,
/// so two enrolments racing for the same code cannot both see it unused.
pub async fn consume(
    conn: &mut PgConnection,
    hash: &InvitationHash,
    device: &Pseudonym,
) -> anyhow::Result<bool> {
    let consumed = sqlx::query(
        "UPDATE invitations SET used_at = now(), used_by = $2 \
         WHERE hash = $1 AND used_at IS NULL AND expires_at > now()",
    )
    .bind(hash.as_str())
    .bind(device.as_str())
    .execute(conn)
    .await?;
    Ok(consumed.rows_affected() == 1)
}

/// True if `device` itself consumed this invitation, so its owner may run `join` again with it.
pub async fn used_by(
    conn: &mut PgConnection,
    hash: &InvitationHash,
    device: &Pseudonym,
) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM invitations WHERE hash = $1 AND used_by = $2)",
    )
    .bind(hash.as_str())
    .bind(device.as_str())
    .fetch_one(conn)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_accepts_minutes_hours_days_up_to_30_days() {
        assert_eq!(parse_ttl("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_ttl("72h").unwrap(), Duration::hours(72));
        assert_eq!(parse_ttl("30d").unwrap(), MAX_TTL);
        for bad in ["31d", "0h", "-1h", "h", "", "12", "1w", "1.5h"] {
            assert!(parse_ttl(bad).is_err(), "{bad:?}");
        }
    }

    /// Run with `cargo test -- --ignored` and TEST_DATABASE_URL set, for example to a throwaway
    /// `docker run -p 55432:5432 -e POSTGRES_PASSWORD=pact postgres:17`.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn concurrent_enrolments_consume_one_invitation_once() {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(20)
            .connect(&url)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        let (code, _) = create(&db, Duration::hours(1), "race").await.unwrap();
        let stored: Vec<String> = sqlx::query_scalar(
            "SELECT concat_ws(' ', hash, note, used_by) FROM invitations WHERE note = 'race' AND hash = $1",
        )
        .bind(code.hash().as_str())
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(stored, [format!("{} race", code.hash())]);
        assert!(!stored[0].contains(&String::from(code.clone())));
        let attempts = (0..16u8).map(|i| {
            let (db, hash) = (db.clone(), code.hash());
            tokio::spawn(async move {
                let device =
                    Pseudonym::try_from(format!("pseudonym:{}", hex::encode([i; 32]))).unwrap();
                let mut tx = db.begin().await.unwrap();
                let won = consume(&mut tx, &hash, &device).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                tx.commit().await.unwrap();
                won
            })
        });
        let mut wins = 0;
        for a in attempts {
            wins += usize::from(a.await.unwrap());
        }
        assert_eq!(wins, 1);

        let (expired, _) = create(&db, Duration::minutes(1), "expired").await.unwrap();
        sqlx::query(
            "UPDATE invitations SET expires_at = now() - interval '1 second' WHERE hash = $1",
        )
        .bind(expired.hash().as_str())
        .execute(&db)
        .await
        .unwrap();
        let device = Pseudonym::try_from(format!("pseudonym:{}", "cd".repeat(32))).unwrap();
        let mut conn = db.acquire().await.unwrap();
        assert!(!consume(&mut conn, &expired.hash(), &device).await.unwrap());
        let unknown = InvitationCode::from_bytes([9; 32]).hash();
        assert!(!consume(&mut conn, &unknown, &device).await.unwrap());
    }
}
