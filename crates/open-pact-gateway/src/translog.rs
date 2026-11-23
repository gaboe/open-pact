use std::sync::Arc;

use anyhow::Context;
use futures_util::TryStreamExt;
use open_pact_core::{Entry, EntryKind};
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row as _};

use crate::hooks::Hooks;

type Row = (i64, String, Value);

/// Raw rows of one SQL statement. Dropping them frees them on the blocking pool, so a large batch
/// never costs an async worker its time. The batch owns every row from the first one it receives.
pub struct RowBatch {
    rows: Vec<PgRow>,
    /// Closed after the rows are freed, so a waiter knows the memory is gone.
    freed: Option<tokio::sync::oneshot::Sender<()>>,
    hooks: Arc<Hooks>,
}

impl RowBatch {
    pub fn new(freed: Option<tokio::sync::oneshot::Sender<()>>, hooks: Arc<Hooks>) -> RowBatch {
        RowBatch {
            rows: Vec::new(),
            freed,
            hooks,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn push(&mut self, row: PgRow) {
        self.rows.push(row);
    }

    pub fn rows(&self) -> &[PgRow] {
        &self.rows
    }

    /// Hands the rows and the `freed` signal to a closure that already runs on the blocking pool.
    pub fn into_parts(mut self) -> (Vec<PgRow>, Option<tokio::sync::oneshot::Sender<()>>) {
        (std::mem::take(&mut self.rows), self.freed.take())
    }
}

impl Drop for RowBatch {
    fn drop(&mut self) {
        let rows = std::mem::take(&mut self.rows);
        let freed = self.freed.take();
        if rows.is_empty() {
            return;
        }
        let hooks = self.hooks.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn_blocking(move || {
                    hooks.block("row_batch_drop");
                    hooks.add("freed_rows", rows.len());
                    drop(rows);
                    drop(freed);
                });
            }
            // At shutdown no runtime is left to ask.
            Err(_) => drop(rows),
        }
    }
}

fn decode_row(row: &PgRow) -> anyhow::Result<Entry> {
    entry((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?))
}

/// Decodes rows that start at `from`; fails if they have a gap. CPU work: run it off the async
/// workers when the batch is large.
pub fn decode(rows: &[PgRow], from: u64) -> anyhow::Result<Vec<Entry>> {
    let entries = rows
        .iter()
        .map(decode_row)
        .collect::<anyhow::Result<Vec<_>>>()?;
    check_gap(&entries, from)?;
    Ok(entries)
}

fn check_gap(entries: &[Entry], from: u64) -> anyhow::Result<()> {
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
    Ok(())
}

/// Every committed entry from `from` on.
#[cfg(test)]
pub async fn since(conn: &mut PgConnection, from: u64) -> anyhow::Result<Vec<Entry>> {
    range(conn, from, u64::MAX).await
}

/// Every committed row from `from` on, undecoded, streamed into `batch` from the first row.
pub async fn since_raw(
    conn: &mut PgConnection,
    from: u64,
    mut batch: RowBatch,
) -> anyhow::Result<RowBatch> {
    let mut rows =
        sqlx::query("SELECT idx, kind, data FROM log_entries WHERE idx >= $1 ORDER BY idx")
            .bind(i64::try_from(from)?)
            .fetch(conn);
    while let Some(row) = rows.try_next().await? {
        batch.push(row);
    }
    drop(rows);
    Ok(batch)
}

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

/// Begins the transaction that reads one device's proof entries. Its first statement sets REPEATABLE
/// READ, so the first read in it (the approval read) takes the snapshot that the entry read also
/// uses: a revocation committed after that snapshot cannot pass, and one committed before it stops
/// the proof at the approval read.
pub async fn begin_proof(
    db: &sqlx::PgPool,
) -> anyhow::Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = db.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// The partial indexes `log_entries_manifest` and `log_entries_commitment` (migration 0013) serve
/// this query. Each `kind` list here must equal the `kind` predicate of its index in that migration.
pub async fn mine(
    conn: &mut PgConnection,
    size: u64,
    manifest: &str,
    commitment: &str,
) -> anyhow::Result<Vec<Entry>> {
    sqlx::query_as::<_, Row>(
        "SELECT idx, kind, data FROM log_entries WHERE idx < $1 AND \
         ((kind = 'manifest_published' AND data->>'manifest' = $2) OR \
         (kind IN ('device_enrolled', 'device_approved', 'device_revoked', 'manifest_accepted') \
         AND data->>'commitment' = $3)) ORDER BY idx",
    )
    .bind(i64::try_from(size)?)
    .bind(manifest)
    .bind(commitment)
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(entry)
    .collect()
}

/// Entries `from..to` in index order; fails if the table has a gap there.
pub async fn range(conn: &mut PgConnection, from: u64, to: u64) -> anyhow::Result<Vec<Entry>> {
    let rows = sqlx::query(
        "SELECT idx, kind, data FROM log_entries WHERE idx >= $1 AND idx < $2 ORDER BY idx",
    )
    .bind(i64::try_from(from)?)
    .bind(i64::try_from(to).unwrap_or(i64::MAX))
    .fetch_all(conn)
    .await?;
    decode(&rows, from)
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
