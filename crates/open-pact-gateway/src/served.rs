//! The read routes. A checkpoint note that the client accepts under its policy, or a 503 within
//! the deadline plus one candidate. The work is the request's own: the tree step, the owners and
//! the store run in their own tasks, and a request only waits for them until its deadline.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::http::StatusCode;
use base64::Engine;
use futures_util::TryStreamExt;
use open_pact_core::{
    CLOCK_SKEW_SECS, Checkpoint, LogHash, LogKey, LogPolicy, Note, NoteSignature,
    cosign_time_usable, root,
};
use serde_json::json;
use sqlx::Row as _;

use crate::hooks::Hooks;
use crate::translog::RowBatch;
use crate::witness::db_step;
use crate::{App, Reply, Tree, TreeSql, tree_step};

/// A gateway note counts only while it keeps this much of the age the client allows: 60 s for a
/// client clock ahead of the gateway and 240 s from the gateway's choice to the client's check.
pub const AGE_MARGIN_SECS: u64 = 300;

pub const UNAVAILABLE: &str = "witness cosignatures are not available yet; retry";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    NotYet,
    Exhausted,
    Database,
}

pub enum Answer {
    Witnessed { note: Note, tree: Tree },
    Unavailable(Why),
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn invalid_policy() -> Reply {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"status": "error", "reason": "invalid policy"})),
    )
}

/// The policy a client sends in `?policy=<base64url JSON>`, validated as a signed manifest's is.
/// No parameter is no policy (the request gets the policy of the manifest the gateway enforces);
/// two parameters or any failed step is 400. The gateway uses the policy only to choose a stored
/// size and how long to wait, and never contacts an address from it.
pub fn request_policy(query: Option<&str>) -> Result<Option<LogPolicy>, Reply> {
    let mut found = None;
    for pair in query.unwrap_or_default().split('&') {
        if let Some(value) = pair.strip_prefix("policy=")
            && found.replace(value).is_some()
        {
            return Err(invalid_policy());
        }
    }
    let Some(value) = found else { return Ok(None) };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_policy())?;
    let policy: LogPolicy = serde_json::from_slice(&bytes).map_err(|_| invalid_policy())?;
    policy.validate().map_err(|_| invalid_policy())?;
    Ok(Some(policy))
}

/// A witness line that the policy's key verified, with the cosign time its verification returned.
pub struct Kept {
    pub line: NoteSignature,
    pub time: u64,
}

fn log_key_id(key: &LogKey) -> Option<String> {
    key.vkey().rsplit('+').nth(1).map(str::to_string)
}

/// The log-signed note extended with one witness line per policy key, and the number of distinct
/// keys. A key keeps the newest line that passes the future test, else its newest line; a line
/// under the log's own name and key ID is dropped, because the client rejects the whole note for it.
/// Each line is verified once, here.
pub fn assemble(
    log_key: &LogKey,
    policy: Option<&LogPolicy>,
    cp: &Checkpoint,
    mut note: Note,
    lines: &[NoteSignature],
    now: u64,
    hooks: &Hooks,
) -> (Note, usize, Vec<Kept>) {
    let log_id = log_key_id(log_key);
    let mut kept = vec![];
    for witness in policy.map(|p| p.witnesses.as_slice()).unwrap_or_default() {
        let mut best: Option<Kept> = None;
        for line in lines {
            if line.name == log_key.origin()
                && log_id.as_deref() == line.payload.get(..4).map(hex::encode).as_deref()
            {
                continue;
            }
            let checked = witness.key.verify(cp, line);
            if checked.is_some() {
                hooks.bump("verify_ed25519");
            }
            let Some(Ok(time)) = checked else {
                continue;
            };
            let timely = |t: u64| t <= now.saturating_add(CLOCK_SKEW_SECS);
            let better = match &best {
                None => true,
                Some(old) => match (timely(time), timely(old.time)) {
                    (true, false) => true,
                    (false, true) => false,
                    _ => time > old.time,
                },
            };
            if better {
                best = Some(Kept {
                    line: line.clone(),
                    time,
                });
            }
        }
        kept.extend(best);
    }
    let count = kept.len();
    note.signatures.extend(kept.iter().map(|k| k.line.clone()));
    (note, count, kept)
}

/// At least a quorum of distinct keys whose cosign times pass the age test with the gateway's
/// margin, and a log signature that verifies: the checks the client runs before it installs.
pub fn usable(
    log_key: &LogKey,
    policy: Option<&LogPolicy>,
    note: &Note,
    kept: &[Kept],
    now: u64,
    hooks: &Hooks,
) -> bool {
    let Some(policy) = policy else {
        hooks.bump("verify_p256");
        return log_key.verify(note).is_ok();
    };
    kept.iter()
        .filter(|k| cosign_time_usable(policy, k.time, now, AGE_MARGIN_SECS))
        .count()
        >= policy.witness_quorum
        && {
            hooks.bump("verify_p256");
            log_key.verify(note).is_ok()
        }
}

/// The pure bound of the uncached-size query: never above the captured tree, and none when the
/// window already covers `floor`.
pub fn uncached_bound(floor: u64, tree_size: u64, oldest: u64) -> Option<u64> {
    (floor < oldest).then(|| tree_size.min(oldest - 1))
}

/// How many sizes the rows of a batch hold (they arrive ordered by size).
fn groups_in(batch: &RowBatch) -> usize {
    let mut groups = 0;
    let mut last = None;
    for row in batch.rows() {
        let size: i64 = row.get(0);
        if last != Some(size) {
            groups += 1;
            last = Some(size);
        }
    }
    groups
}

enum Stop {
    NotYet,
    Database,
}

struct Rows {
    batch: RowBatch,
    known: HashMap<u64, LogHash>,
}

impl App {
    fn timeout_at(deadline: Instant) -> tokio::time::Instant {
        tokio::time::Instant::from_std(deadline)
    }

    /// The tree of this request's snapshot, or none when the step failed or the deadline passed.
    async fn tree_until(&self, deadline: Instant) -> Option<Tree> {
        self.owners.hooks().bump("served_tree_reads");
        let step = tree_step(
            self.db.clone(),
            self.enforced.clone(),
            TreeSql::Step,
            self.owners.hooks(),
        );
        match tokio::time::timeout_at(Self::timeout_at(deadline), step).await {
            Ok(Ok(Ok(tree))) => {
                if let Some(metrics) = self.metrics() {
                    metrics.log_size(tree.size());
                }
                Some(tree)
            }
            Ok(Ok(Err(error))) => {
                eprintln!("checkpoint read: the tree step failed: {error:#}");
                None
            }
            _ => None,
        }
    }

    fn sign_tree(&self, tree: &Tree) -> Note {
        self.owners.hooks().bump("served_signatures");
        let cp = Checkpoint {
            origin: self.log.key.origin().to_string(),
            size: tree.size(),
            root: tree.root(),
        };
        self.log.key.sign(&self.log.signer, &cp)
    }

    /// A note of a size from `floor` to the tree's that `policy` accepts, or why not. Never errs.
    pub async fn served(&self, policy: Option<&LogPolicy>, deadline: Instant) -> Answer {
        let past = || Instant::now() >= deadline;
        let hooks = self.owners.hooks();
        let mut rx = self.owners.subscribe();
        let Some(mut tree) = self.tree_until(deadline).await else {
            return Answer::Unavailable(Why::Database);
        };
        hooks.hit("served_tree_returned").await;
        let Some(policy) = policy.filter(|p| !p.witnesses.is_empty()) else {
            if past() {
                return Answer::Unavailable(Why::NotYet);
            }
            return Answer::Witnessed {
                note: self.sign_tree(&tree),
                tree,
            };
        };
        let floor = tree.size();
        let mut uncached: Option<(u64, LogHash)> = None;
        loop {
            if past() {
                return Answer::Unavailable(Why::NotYet);
            }
            match self
                .read_once(policy, &tree, floor, deadline, &mut uncached)
                .await
            {
                Ok(Some(note)) => return Answer::Witnessed { note, tree },
                Ok(None) => {}
                Err(Stop::Database) => return Answer::Unavailable(Why::Database),
                Err(Stop::NotYet) => return Answer::Unavailable(Why::NotYet),
            }
            if past() {
                return Answer::Unavailable(Why::NotYet);
            }
            hooks.bump("kick_calls");
            self.owners.kick(tree.size());
            if past() {
                return Answer::Unavailable(Why::NotYet);
            }
            let exhausted = self
                .owners
                .views()
                .iter()
                .all(|v| v.idle && (v.cooling || (v.tried >= tree.size() && v.failures == 0)));
            if exhausted {
                return match self
                    .final_read(policy, &tree, floor, deadline, &mut uncached)
                    .await
                {
                    Some(note) => Answer::Witnessed { note, tree },
                    None => Answer::Unavailable(Why::Exhausted),
                };
            }
            hooks.hit("reader_waiting").await;
            let final_at = deadline
                .checked_sub(Duration::from_millis(200))
                .unwrap_or(deadline);
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() || past() {
                        return Answer::Unavailable(Why::NotYet);
                    }
                    match self.tree_until(deadline).await {
                        Some(next) => tree = next,
                        None => return Answer::Unavailable(Why::Database),
                    }
                }
                () = tokio::time::sleep_until(Self::timeout_at(final_at)) => {
                    return match self.final_read(policy, &tree, floor, deadline, &mut uncached).await {
                        Some(note) => Answer::Witnessed { note, tree },
                        None => Answer::Unavailable(Why::NotYet),
                    };
                }
            }
        }
    }

    async fn final_read(
        &self,
        policy: &LogPolicy,
        tree: &Tree,
        floor: u64,
        deadline: Instant,
        uncached: &mut Option<(u64, LogHash)>,
    ) -> Option<Note> {
        if Instant::now() >= deadline {
            return None;
        }
        self.read_once(policy, tree, floor, deadline, uncached)
            .await
            .ok()
            .flatten()
    }

    async fn read_once(
        &self,
        policy: &LogPolicy,
        tree: &Tree,
        floor: u64,
        deadline: Instant,
        uncached: &mut Option<(u64, LogHash)>,
    ) -> Result<Option<Note>, Stop> {
        let rows = self.read(policy, tree, floor, deadline, uncached).await?;
        let note = self.select(policy, &rows, deadline);
        Ok(note)
    }

    /// The stored lines of every candidate size from `floor`, largest size first, that the SQL
    /// leaves: only rows of the candidate root whose column is one of the policy's keys.
    async fn read(
        &self,
        policy: &LogPolicy,
        tree: &Tree,
        floor: u64,
        deadline: Instant,
        uncached: &mut Option<(u64, LogHash)>,
    ) -> Result<Rows, Stop> {
        let past = || Instant::now() >= deadline;
        let hooks = self.owners.hooks();
        hooks.bump("read_calls");
        let cols: Vec<String> = policy
            .witnesses
            .iter()
            .flat_map(|w| [w.key.vkey(), w.key.name().to_string()])
            .collect();
        let view = &tree.view;
        let oldest = view.roots.front().map_or(tree.size(), |(s, _)| *s);
        let mut known: HashMap<u64, LogHash> = HashMap::new();
        for s in floor.max(oldest)..=tree.size() {
            if s == tree.size() {
                known.insert(s, tree.root());
            } else if let Some((_, hash)) = usize::try_from(s - oldest)
                .ok()
                .and_then(|i| view.roots.get(i))
            {
                known.insert(s, *hash);
            }
        }
        if let Some(hi) = uncached_bound(floor, tree.size(), oldest) {
            if past() {
                return Err(Stop::NotYet);
            }
            let (low, high, wanted) = (
                i64::try_from(floor).unwrap_or(i64::MAX),
                i64::try_from(hi).unwrap_or(i64::MAX),
                cols.clone(),
            );
            let step = db_step(self.db.clone(), move |conn| {
                Box::pin(async move {
                    let top: Option<i64> = sqlx::query_scalar(
                        "SELECT max(size) FROM log_cosignatures \
                         WHERE size BETWEEN $1 AND $2 AND witness = ANY($3)",
                    )
                    .bind(low)
                    .bind(high)
                    .bind(wanted)
                    .fetch_one(conn)
                    .await?;
                    Ok(top)
                })
            });
            let top = match tokio::time::timeout_at(Self::timeout_at(deadline), step).await {
                Ok(Ok(Ok(top))) => top,
                Ok(Ok(Err(error))) => {
                    eprintln!("checkpoint read: the uncached size query failed: {error:#}");
                    return Err(Stop::Database);
                }
                _ => return Err(Stop::Database),
            };
            if let Some(size) = top.and_then(|s| u64::try_from(s).ok()) {
                if size == tree.size() {
                    known.insert(size, tree.root());
                } else {
                    if uncached.is_none() && !past() {
                        hooks.bump("uncached_root");
                        *uncached = Some((size, root(tree.prefix(size))));
                    }
                    if let Some((u, hash)) = uncached.as_ref().filter(|(u, _)| *u == size) {
                        known.insert(*u, *hash);
                    }
                }
            }
        }
        if past() {
            return Err(Stop::NotYet);
        }
        let mut sizes = vec![];
        let mut roots = vec![];
        for (size, hash) in &known {
            sizes.push(i64::try_from(*size).unwrap_or(i64::MAX));
            roots.push(hash.to_string());
        }
        if sizes.is_empty() {
            return Ok(Rows {
                batch: RowBatch::new(None, hooks),
                known,
            });
        }
        let step_hooks = hooks.clone();
        let step = db_step(self.db.clone(), move |conn| {
            Box::pin(async move {
                let hooks = step_hooks;
                let mut batch = RowBatch::new(None, hooks.clone());
                hooks.hit("row_step_start").await;
                let mut rows = sqlx::query(
                    "SELECT size, witness, signature FROM log_cosignatures \
                     WHERE (size, root) IN (SELECT * FROM unnest($1::bigint[], $2::text[])) \
                     AND witness = ANY($3) ORDER BY size DESC, received_at DESC",
                )
                .bind(sizes)
                .bind(roots)
                .bind(cols)
                .fetch(conn);
                while let Some(row) = rows.try_next().await? {
                    batch.push(row);
                }
                drop(rows);
                hooks.add("row_groups", groups_in(&batch));
                hooks.hit("row_step_returned").await;
                Ok(batch)
            })
        });
        match tokio::time::timeout_at(Self::timeout_at(deadline), step).await {
            Ok(Ok(Ok(batch))) => Ok(Rows { batch, known }),
            Ok(Ok(Err(error))) => {
                eprintln!("checkpoint read: the row query failed: {error:#}");
                Err(Stop::Database)
            }
            Ok(Err(_)) => Err(Stop::Database),
            Err(_) => Err(Stop::NotYet),
        }
    }

    /// Walks the row groups, largest size first, and returns the first note the policy accepts. The
    /// deadline is checked before each group, never inside one: one candidate can end after it.
    fn select(&self, policy: &LogPolicy, rows: &Rows, deadline: Instant) -> Option<Note> {
        let batch = rows.batch.rows();
        let mut start = 0;
        while start < batch.len() {
            let size: i64 = batch[start].get(0);
            let end = batch[start..]
                .iter()
                .position(|r| r.get::<i64, _>(0) != size)
                .map_or(batch.len(), |n| start + n);
            if Instant::now() >= deadline {
                return None;
            }
            let hooks = self.owners.hooks();
            hooks.hold_until_after("candidate_started", deadline);
            let size = u64::try_from(size).ok()?;
            if let Some(hash) = rows.known.get(&size) {
                hooks.add("candidate_rows", end - start);
                hooks.bump("served_signatures");
                let cp = Checkpoint {
                    origin: self.log.key.origin().to_string(),
                    size,
                    root: *hash,
                };
                let note = self.log.key.sign(&self.log.signer, &cp);
                let lines: Vec<NoteSignature> = batch[start..end]
                    .iter()
                    .filter_map(|r| NoteSignature::parse(&r.get::<String, _>(2)).ok())
                    .collect();
                let now = now_secs();
                let (note, _, kept) =
                    assemble(&self.log.key, Some(policy), &cp, note, &lines, now, &hooks);
                if usable(&self.log.key, Some(policy), &note, &kept, now, &hooks) {
                    return Some(note);
                }
            }
            start = end;
        }
        None
    }
}
