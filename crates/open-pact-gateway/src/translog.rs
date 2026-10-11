use anyhow::Context;
use open_pact_core::{Entry, EntryKind, LogHash};
use serde_json::Value;
use sqlx::PgConnection;

type Row = (i64, String, Value, String, String);

const COLUMNS: &str = "SELECT idx, kind, data, prev_hash, hash FROM log_entries";

fn entry((idx, kind, data, prev_hash, hash): Row) -> anyhow::Result<Entry> {
    Ok(Entry {
        index: u64::try_from(idx)?,
        kind: serde_json::from_value(Value::String(kind)).context("log kind")?,
        data,
        prev_hash: LogHash::try_from(prev_hash).map_err(anyhow::Error::msg)?,
        hash: LogHash::try_from(hash).map_err(anyhow::Error::msg)?,
    })
}

pub async fn lock(conn: &mut PgConnection) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('open-pact log_entries'))")
        .execute(conn)
        .await
        .map(drop)
}

pub async fn last(conn: &mut PgConnection) -> anyhow::Result<Option<Entry>> {
    sqlx::query_as::<_, Row>(&format!("{COLUMNS} ORDER BY idx DESC LIMIT 1"))
        .fetch_optional(conn)
        .await?
        .map(entry)
        .transpose()
}

pub async fn since(conn: &mut PgConnection, from: u64) -> anyhow::Result<Vec<Entry>> {
    sqlx::query_as::<_, Row>(&format!("{COLUMNS} WHERE idx >= $1 ORDER BY idx"))
        .bind(i64::try_from(from).unwrap_or(i64::MAX))
        .fetch_all(conn)
        .await?
        .into_iter()
        .map(entry)
        .collect()
}

pub async fn append(
    conn: &mut PgConnection,
    kind: EntryKind,
    data: Value,
) -> anyhow::Result<Entry> {
    lock(conn).await?;
    let entry = match last(conn).await? {
        Some(prev) => prev.next(kind, data),
        None => Entry::first(kind, data),
    };
    sqlx::query(
        "INSERT INTO log_entries (idx, kind, data, prev_hash, hash) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(i64::try_from(entry.index)?)
    .bind(entry.kind.as_str())
    .bind(&entry.data)
    .bind(entry.prev_hash.to_string())
    .bind(entry.hash.to_string())
    .execute(conn)
    .await?;
    Ok(entry)
}
