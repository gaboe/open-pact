use anyhow::Context;
use open_pact_core::{Entry, EntryKind, LogHash};
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

/// Every entry in index order. The log is small, so proofs are computed from all leaves.
pub async fn all(conn: &mut PgConnection) -> anyhow::Result<Vec<Entry>> {
    let entries = sqlx::query_as::<_, Row>("SELECT idx, kind, data FROM log_entries ORDER BY idx")
        .fetch_all(conn)
        .await?
        .into_iter()
        .map(entry)
        .collect::<anyhow::Result<Vec<_>>>()?;
    if let Some((i, e)) = entries
        .iter()
        .enumerate()
        .find(|(i, e)| e.index != *i as u64)
    {
        anyhow::bail!("log_entries has a gap: index {} at position {i}", e.index);
    }
    Ok(entries)
}

pub fn leaf_hashes(entries: &[Entry]) -> Vec<LogHash> {
    entries.iter().map(Entry::leaf_hash).collect()
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
