use anyhow::Context;
use open_pact_core::{Entry, EntryKind};
use serde_json::Value;
use sqlx::PgConnection;

type Row = (i64, String, Value);

fn entry((idx, kind, data): Row) -> anyhow::Result<Entry> {
    Ok(Entry {
        index: u64::try_from(idx)?,
        kind: serde_json::from_value(Value::String(kind)).context("log kind")?,
        data,
    })
}

pub async fn lock(conn: &mut PgConnection) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('open-pact log_entries'))")
        .execute(conn)
        .await
        .map(drop)
}

/// Entries `from..to` in index order; fails if the table has a gap there.
pub async fn range(conn: &mut PgConnection, from: u64, to: u64) -> anyhow::Result<Vec<Entry>> {
    let entries = sqlx::query_as::<_, Row>(
        "SELECT idx, kind, data FROM log_entries WHERE idx >= $1 AND idx < $2 ORDER BY idx",
    )
    .bind(i64::try_from(from)?)
    .bind(i64::try_from(to).unwrap_or(i64::MAX))
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(entry)
    .collect::<anyhow::Result<Vec<_>>>()?;
    if let Some((i, e)) = entries
        .iter()
        .enumerate()
        .find(|(i, e)| e.index != from + *i as u64)
    {
        anyhow::bail!(
            "log_entries has a gap: index {} at position {}",
            e.index,
            from + i as u64
        );
    }
    Ok(entries)
}

/// Every committed entry from `from` on.
pub async fn since(conn: &mut PgConnection, from: u64) -> anyhow::Result<Vec<Entry>> {
    range(conn, from, u64::MAX).await
}

pub async fn append(
    conn: &mut PgConnection,
    kind: EntryKind,
    data: Value,
) -> anyhow::Result<Entry> {
    lock(conn).await?;
    let next: i64 = sqlx::query_scalar("SELECT count(*) FROM log_entries")
        .fetch_one(&mut *conn)
        .await?;
    let entry = Entry {
        index: u64::try_from(next)?,
        kind,
        data,
    };
    sqlx::query("INSERT INTO log_entries (idx, kind, data) VALUES ($1, $2, $3)")
        .bind(next)
        .bind(entry.kind.as_str())
        .bind(&entry.data)
        .execute(conn)
        .await?;
    Ok(entry)
}
