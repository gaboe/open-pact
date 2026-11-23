use anyhow::{Context, bail};
use open_pact_core::{EntryKind, Pseudonym};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

use crate::translog;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pending,
    Approved,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Approve,
    Revoke,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Approved => "approved",
            State::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> anyhow::Result<State> {
        match s {
            "pending" => Ok(State::Pending),
            "approved" => Ok(State::Approved),
            "revoked" => Ok(State::Revoked),
            other => bail!("unknown device state {other:?}"),
        }
    }

    /// Why `/v1/claim` refuses a device in this state.
    pub fn denial(self) -> Option<&'static str> {
        match self {
            State::Pending => Some("device awaiting IT approval"),
            State::Approved => None,
            State::Revoked => Some("device revoked"),
        }
    }

    /// The new state, `None` when the action changes nothing. Revoked is final: a revoked device
    /// enrols again only with a new device key.
    pub fn after(self, action: Action) -> Result<Option<State>, &'static str> {
        match (self, action) {
            (State::Pending, Action::Approve) => Ok(Some(State::Approved)),
            (State::Approved, Action::Approve) | (State::Revoked, Action::Revoke) => Ok(None),
            (State::Revoked, Action::Approve) => {
                Err("a revoked device stays revoked; the owner joins again with a new device key")
            }
            (State::Pending | State::Approved, Action::Revoke) => Ok(Some(State::Revoked)),
        }
    }
}

impl Action {
    fn entry_kind(self) -> EntryKind {
        match self {
            Action::Approve => EntryKind::DeviceApproved,
            Action::Revoke => EntryKind::DeviceRevoked,
        }
    }
}

/// `sha256(salt || pseudonym)`, the only form of a device the public log holds.
pub fn commitment(salt_hex: &str, device: &str) -> anyhow::Result<String> {
    let mut h = Sha256::new();
    h.update(hex::decode(salt_hex).context("device salt")?);
    h.update(device);
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
}

/// The state of `device` under `manifest`, with its row locked until the transaction ends. Claims
/// of one device then load, evaluate and save their grace state one after another (R2-M4).
pub async fn lock(
    conn: &mut PgConnection,
    device: &Pseudonym,
    manifest: &str,
) -> anyhow::Result<Option<State>> {
    let state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM devices WHERE pseudonym = $1 AND manifest_hash = $2 FOR UPDATE",
    )
    .bind(device.as_str())
    .bind(manifest)
    .fetch_optional(conn)
    .await?;
    state.as_deref().map(State::parse).transpose()
}

/// An enrolment of one device: the manifest its owner signed, its state, its salt and its owner.
pub struct Enrolment {
    pub manifest: String,
    pub state: State,
    pub salt: String,
    pub owner_key: Value,
}

/// The enrolment `device` uses: the one under `current` if it has one, else its newest. A device
/// enrolled under an earlier manifest keeps that enrolment until its owner accepts `current`.
const BOUND: &str = "SELECT manifest_hash, state, salt, owner_key FROM devices WHERE pseudonym = $1 \
     ORDER BY manifest_hash = $2 DESC, enrolled_at DESC LIMIT 1";

fn enrolment(row: (String, String, String, Value)) -> anyhow::Result<Enrolment> {
    let (manifest, state, salt, owner_key) = row;
    Ok(Enrolment {
        manifest,
        state: State::parse(&state)?,
        salt,
        owner_key,
    })
}

pub async fn bound(
    conn: &mut PgConnection,
    device: &Pseudonym,
    current: &str,
) -> anyhow::Result<Option<Enrolment>> {
    let row = sqlx::query_as(BOUND)
        .bind(device.as_str())
        .bind(current)
        .fetch_optional(conn)
        .await?;
    row.map(enrolment).transpose()
}

/// `bound`, with its row locked until the transaction ends. A claim or an acceptance decides on
/// the enrolment it locked, so two requests for one device cannot both pass.
pub async fn lock_bound(
    conn: &mut PgConnection,
    device: &Pseudonym,
    current: &str,
) -> anyhow::Result<Option<Enrolment>> {
    let row = sqlx::query_as(&format!("{BOUND} FOR UPDATE"))
        .bind(device.as_str())
        .bind(current)
        .fetch_optional(conn)
        .await?;
    row.map(enrolment).transpose()
}

pub async fn revoked_anywhere(conn: &mut PgConnection, device: &Pseudonym) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM devices WHERE pseudonym = $1 AND state = 'revoked')",
    )
    .bind(device.as_str())
    .fetch_one(conn)
    .await?)
}

/// The first log entry that an action wrote. `at` is the time the transaction was about to commit:
/// no table keeps the time of a state change, so the gateway takes it right before the commit.
#[derive(Debug, Clone)]
pub struct Change {
    pub manifest: String,
    pub state: State,
    pub log_index: u64,
    pub at: OffsetDateTime,
}

/// What `apply` left: the state of each enrolment, and the first change when at least one
/// enrolment changed. `None` means the action changed nothing.
#[derive(Debug)]
pub struct Applied {
    pub states: Vec<(String, State)>,
    pub change: Option<Change>,
}

/// Applies `action` to every enrolment of `device` and logs each change.
pub async fn apply(db: &PgPool, device: &str, action: Action) -> anyhow::Result<Applied> {
    let mut tx = db.begin().await?;
    translog::lock(&mut tx).await?;
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT manifest_hash, state, salt FROM devices WHERE pseudonym = $1 ORDER BY enrolled_at FOR UPDATE",
    )
    .bind(device)
    .fetch_all(&mut *tx)
    .await?;
    if rows.is_empty() {
        bail!("no device {device}");
    }
    let mut result = vec![];
    let mut first = None;
    for (manifest, state, salt) in rows {
        let state = State::parse(&state)?;
        let Some(next) = state.after(action).map_err(anyhow::Error::msg)? else {
            result.push((manifest, state));
            continue;
        };
        sqlx::query("UPDATE devices SET state = $1 WHERE pseudonym = $2 AND manifest_hash = $3")
            .bind(next.as_str())
            .bind(device)
            .bind(&manifest)
            .execute(&mut *tx)
            .await?;
        let entry = translog::append(
            &mut tx,
            action.entry_kind(),
            json!({ "commitment": commitment(&salt, device)? }),
        )
        .await?;
        eprintln!("log entry {}: {}", entry.index, entry.kind.as_str());
        first.get_or_insert_with(|| (manifest.clone(), next, entry.index));
        result.push((manifest, next));
    }
    let at = OffsetDateTime::now_utc();
    tx.commit().await?;
    Ok(Applied {
        states: result,
        change: first.map(|(manifest, state, log_index)| Change {
            manifest,
            state,
            log_index,
            at,
        }),
    })
}

/// The start of a pseudonym the owner or IT reads out: at least 8 lowercase hex digits, with or
/// without `pseudonym:`. Returns it with the prefix.
pub fn pseudonym_prefix(prefix: &str) -> anyhow::Result<String> {
    const MIN: usize = 8;
    let hex = prefix.strip_prefix("pseudonym:").unwrap_or(prefix);
    if hex.len() < MIN || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        bail!("give at least {MIN} lowercase hex digits of the pseudonym, got {prefix:?}");
    }
    Ok(format!("pseudonym:{hex}"))
}

/// The one pending pseudonym that starts with `prefix`. The owner reads the prefix out to IT.
pub async fn pending_by_prefix(db: &PgPool, prefix: &str) -> anyhow::Result<String> {
    let prefix = pseudonym_prefix(prefix)?;
    let found: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT pseudonym FROM devices WHERE state = 'pending' AND starts_with(pseudonym, $1) ORDER BY pseudonym",
    )
    .bind(&prefix)
    .fetch_all(db)
    .await?;
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => bail!("no pending device starts with {prefix}"),
        many => bail!(
            "{} pending devices start with {prefix}; give more digits:\n{}",
            many.len(),
            many.join("\n")
        ),
    }
}

pub fn full_pseudonym(text: &str) -> anyhow::Result<String> {
    let full = if text.starts_with("pseudonym:") {
        text.to_string()
    } else {
        format!("pseudonym:{text}")
    };
    Pseudonym::try_from(full.clone()).map_err(anyhow::Error::msg)?;
    Ok(full)
}

/// How the gateway decided the last claim of an enrolment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimResult {
    Accepted,
    AcceptedWithWarnings,
    Denied,
}

impl ClaimResult {
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimResult::Accepted => "accepted",
            ClaimResult::AcceptedWithWarnings => "accepted_with_warnings",
            ClaimResult::Denied => "denied",
        }
    }
}

/// What a claim decision leaves on the device row: the result, and the warnings or reasons that
/// went with it. A claim that carried data the manifest does not allow is not stored, and its
/// reasons can quote that data, so they are not stored here either: one fixed line takes their place.
pub fn claim_outcome(
    warnings: &[String],
    reasons: &[String],
    oversharing: bool,
) -> (ClaimResult, Vec<String>) {
    if oversharing {
        (
            ClaimResult::Denied,
            vec!["the claim disclosed more than the manifest allows".to_owned()],
        )
    } else if !reasons.is_empty() {
        (ClaimResult::Denied, reasons.to_vec())
    } else if !warnings.is_empty() {
        (ClaimResult::AcceptedWithWarnings, warnings.to_vec())
    } else {
        (ClaimResult::Accepted, vec![])
    }
}

/// Records the last claim decision of the enrolment `device` holds under `manifest`, in the
/// transaction that decides the claim. `access_until` is the end of the certificate the claim got.
/// An accepted claim that got none ended its access at `at`, so it stores `at`. The column stays
/// null after a denial and for a row the gateway wrote before it kept the end, which reads as an
/// unknown standing until the next claim.
pub async fn record_claim(
    conn: &mut PgConnection,
    device: &Pseudonym,
    manifest: &str,
    at: OffsetDateTime,
    result: ClaimResult,
    access_until: Option<OffsetDateTime>,
    reasons: &[String],
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE devices SET last_claim_at = $3, last_result = $4, last_reasons = $5, \
         last_access_until = $6 WHERE pseudonym = $1 AND manifest_hash = $2",
    )
    .bind(device.as_str())
    .bind(manifest)
    .bind(at)
    .bind(result.as_str())
    .bind(reasons)
    .bind(match result {
        ClaimResult::Denied => None,
        _ => Some(access_until.unwrap_or(at)),
    })
    .execute(conn)
    .await?;
    Ok(())
}

/// The note of the invitation this device enrolled with under `manifest_hash`; empty when it has
/// none.
pub async fn note(
    conn: &mut PgConnection,
    device: &Pseudonym,
    manifest_hash: &str,
) -> anyhow::Result<String> {
    let note: Option<Option<String>> = sqlx::query_scalar(
        "SELECT i.note FROM devices d LEFT JOIN invitations i ON i.hash = d.invitation \
         WHERE d.pseudonym = $1 AND d.manifest_hash = $2 ORDER BY d.enrolled_at DESC LIMIT 1",
    )
    .bind(device.as_str())
    .bind(manifest_hash)
    .fetch_optional(conn)
    .await?;
    Ok(note.flatten().unwrap_or_default())
}

/// One enrolment as `devices list --json` prints it. The last three fields are the gateway's last
/// claim decision for this enrolment: null and empty until the device sends a claim.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct DeviceRow {
    pub pseudonym: String,
    /// The first 12 hex digits of the pseudonym: what the owner reads out to IT.
    pub code: String,
    pub state: String,
    /// The note of the invitation the device enrolled with; empty when it has none.
    pub note: String,
    pub enrolled_at: String,
    pub manifest_hash: String,
    /// When the gateway decided the last claim of this enrolment, as `enrolled_at` is written.
    pub last_claim_at: Option<String>,
    /// `accepted`, `accepted_with_warnings` or `denied`.
    pub last_result: Option<String>,
    /// The warnings of an accepted claim, or the reasons of a denied one.
    pub last_reasons: Vec<String>,
}

/// The columns of an enrolment as `rows` selects them.
type RawRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Vec<String>>,
);

impl DeviceRow {
    fn new(
        state: String,
        pseudonym: String,
        manifest_hash: String,
        enrolled_at: String,
        note: Option<String>,
    ) -> Self {
        DeviceRow {
            code: pseudonym
                .strip_prefix("pseudonym:")
                .unwrap_or(&pseudonym)
                .chars()
                .take(12)
                .collect(),
            pseudonym,
            state,
            note: note.unwrap_or_default(),
            enrolled_at,
            manifest_hash,
            last_claim_at: None,
            last_result: None,
            last_reasons: vec![],
        }
    }

    fn with_last_claim(
        mut self,
        at: Option<String>,
        result: Option<String>,
        reasons: Option<Vec<String>>,
    ) -> Self {
        self.last_claim_at = at;
        self.last_result = result;
        self.last_reasons = reasons.unwrap_or_default();
        self
    }
}

/// Every enrolment, oldest first.
pub async fn rows(db: &PgPool) -> anyhow::Result<Vec<DeviceRow>> {
    let rows: Vec<RawRow> = sqlx::query_as(
        "SELECT d.state, d.pseudonym, d.manifest_hash, \
                to_char(d.enrolled_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), i.note, \
                to_char(d.last_claim_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                d.last_result, d.last_reasons \
         FROM devices d LEFT JOIN invitations i ON i.hash = d.invitation \
         ORDER BY d.enrolled_at",
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(state, pseudonym, manifest, enrolled, note, last_at, last_result, last_reasons)| {
                DeviceRow::new(state, pseudonym, manifest, enrolled, note).with_last_claim(
                    last_at,
                    last_result,
                    last_reasons,
                )
            },
        )
        .collect())
}

/// The lines of `devices list`.
pub fn render(rows: &[DeviceRow]) -> String {
    let mut out = String::new();
    for row in rows {
        let manifest = row.manifest_hash.get(..19).unwrap_or(&row.manifest_hash);
        out.push_str(&format!(
            "{:<9} {}  {manifest}  {}  {}\n",
            row.state, row.pseudonym, row.enrolled_at, row.note
        ));
    }
    out
}

pub async fn list(db: &PgPool) -> anyhow::Result<String> {
    Ok(render(&rows(db).await?))
}

/// `devices list --json`: an array with one object per enrolment.
pub async fn list_json(db: &PgPool) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(&rows(db).await?)? + "\n")
}

/// How many devices are in each state. A device with several enrolments counts once per state.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct StateCounts {
    pub pending: u64,
    pub approved: u64,
    pub revoked: u64,
}

pub async fn counts(db: &PgPool) -> anyhow::Result<StateCounts> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT state, count(DISTINCT pseudonym) FROM devices GROUP BY state")
            .fetch_all(db)
            .await?;
    let mut counts = StateCounts::default();
    for (state, number) in rows {
        let number = u64::try_from(number)?;
        match State::parse(&state)? {
            State::Pending => counts.pending = number,
            State::Approved => counts.approved = number,
            State::Revoked => counts.revoked = number,
        }
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_carries_the_code_the_owner_reads_out() {
        let hex = "0123456789abcdef".repeat(4);
        let row = DeviceRow::new(
            "pending".into(),
            format!("pseudonym:{hex}"),
            format!("sha256:{}", "ab".repeat(32)),
            "2026-11-02T10:00:00Z".into(),
            None,
        );
        assert_eq!(row.code, "0123456789ab");
        assert_eq!(row.note, "");
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(
            json,
            json!({
                "pseudonym": format!("pseudonym:{hex}"),
                "code": "0123456789ab",
                "state": "pending",
                "note": "",
                "enrolled_at": "2026-11-02T10:00:00Z",
                "manifest_hash": format!("sha256:{}", "ab".repeat(32)),
                "last_claim_at": null,
                "last_result": null,
                "last_reasons": [],
            })
        );
    }

    #[test]
    fn a_decision_becomes_a_result_with_its_warnings_or_reasons() {
        let words = |text: &[&str]| text.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(
            claim_outcome(&[], &[], false),
            (ClaimResult::Accepted, vec![])
        );
        let warnings = words(&["firewall = unknown, access ends in 23h"]);
        assert_eq!(
            claim_outcome(&warnings, &[], false),
            (ClaimResult::AcceptedWithWarnings, warnings.clone())
        );
        let reasons = words(&["device revoked"]);
        assert_eq!(
            claim_outcome(&[], &reasons, false),
            (ClaimResult::Denied, reasons.clone())
        );
        let leaking =
            words(&["fictional_control = secret value is not an output the manifest allows"]);
        let (result, stored) = claim_outcome(&[], &leaking, true);
        assert_eq!(result, ClaimResult::Denied);
        assert_eq!(stored.len(), 1);
        assert!(!stored[0].contains("secret"), "{stored:?}");
    }

    #[test]
    fn the_text_list_keeps_its_columns() {
        let row = DeviceRow::new(
            "approved".into(),
            "pseudonym:aa".into(),
            format!("sha256:{}", "cd".repeat(32)),
            "2026-11-02T10:00:00Z".into(),
            Some("MacBook of K. Example".into()),
        );
        assert_eq!(
            render(&[row]),
            "approved  pseudonym:aa  sha256:cdcdcdcdcdcd  2026-11-02T10:00:00Z  MacBook of K. Example\n"
        );
    }

    #[test]
    fn approval_moves_only_pending_devices() {
        assert_eq!(
            State::Pending.after(Action::Approve),
            Ok(Some(State::Approved))
        );
        assert_eq!(State::Approved.after(Action::Approve), Ok(None));
        assert!(State::Revoked.after(Action::Approve).is_err());
    }

    #[test]
    fn revocation_is_final_and_repeats_change_nothing() {
        assert_eq!(
            State::Pending.after(Action::Revoke),
            Ok(Some(State::Revoked))
        );
        assert_eq!(
            State::Approved.after(Action::Revoke),
            Ok(Some(State::Revoked))
        );
        assert_eq!(State::Revoked.after(Action::Revoke), Ok(None));
    }

    #[test]
    fn only_approved_devices_may_claim() {
        assert_eq!(State::Pending.denial(), Some("device awaiting IT approval"));
        assert_eq!(State::Revoked.denial(), Some("device revoked"));
        assert_eq!(State::Approved.denial(), None);
        for s in [State::Pending, State::Approved, State::Revoked] {
            assert_eq!(State::parse(s.as_str()).unwrap(), s);
        }
    }

    #[test]
    fn full_pseudonym_accepts_bare_hex_and_rejects_prefixes() {
        let hex = "ab".repeat(32);
        assert_eq!(full_pseudonym(&hex).unwrap(), format!("pseudonym:{hex}"));
        assert!(full_pseudonym("abcd1234").is_err());
    }

    /// Run with TEST_DATABASE_URL set, as the other database tests.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn the_json_list_and_the_counts_follow_the_database() {
        let db = crate::testdb::fresh().await;
        let manifest = format!("sha256:{}", "ab".repeat(32));
        for (n, state) in [
            (1u8, "pending"),
            (2, "approved"),
            (3, "approved"),
            (4, "revoked"),
        ] {
            let pseudonym = format!("pseudonym:{}", hex::encode([n; 32]));
            crate::testdb::enrolled_device(&db, &pseudonym, &manifest).await;
            sqlx::query("UPDATE devices SET state = $1 WHERE pseudonym = $2")
                .bind(state)
                .bind(&pseudonym)
                .execute(&db)
                .await
                .unwrap();
        }
        let listed: Value = serde_json::from_str(&list_json(&db).await.unwrap()).unwrap();
        let listed = listed.as_array().unwrap();
        assert_eq!(listed.len(), 4);
        assert_eq!(listed[0]["code"], "010101010101");
        assert_eq!(listed[0]["state"], "pending");
        assert_eq!(listed[0]["manifest_hash"], manifest);
        assert!(listed[0]["enrolled_at"].as_str().unwrap().ends_with('Z'));
        assert_eq!(listed[0]["note"], "");
        assert_eq!(list(&db).await.unwrap().lines().count(), 4);
        assert_eq!(
            counts(&db).await.unwrap(),
            StateCounts {
                pending: 1,
                approved: 2,
                revoked: 1
            }
        );
    }

    /// Run with TEST_DATABASE_URL set, as the other database tests.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn a_proof_reads_approval_and_entries_from_one_snapshot() {
        let db = crate::testdb::fresh().await;
        let manifest = format!("sha256:{}", "ab".repeat(32));
        let device = format!("pseudonym:{}", hex::encode([7u8; 32]));
        crate::testdb::enrolled_device(&db, &device, &manifest).await;
        let commitment = commitment("00", &device).unwrap();
        {
            let mut conn = db.acquire().await.unwrap();
            translog::append(
                &mut conn,
                EntryKind::DeviceEnrolled,
                json!({ "commitment": commitment }),
            )
            .await
            .unwrap();
        }
        let pseudonym = Pseudonym::try_from(device.clone()).unwrap();
        let mut tx = translog::begin_proof(&db).await.unwrap();
        let read = bound(&mut tx, &pseudonym, &manifest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.state, State::Approved);
        // Another connection revokes the device and commits while the proof transaction is open.
        apply(&db, &device, Action::Revoke).await.unwrap();
        let again = bound(&mut tx, &pseudonym, &manifest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            again.state,
            State::Approved,
            "the proof transaction saw a revocation that came after its snapshot"
        );
        let entries = translog::mine(&mut tx, 1, &manifest, &commitment)
            .await
            .unwrap();
        assert_eq!(
            entries.len(),
            1,
            "the entries were read from a later snapshot"
        );
        tx.commit().await.unwrap();
        // A proof that starts after the revocation reads it: the handler answers 403 here.
        let mut tx = translog::begin_proof(&db).await.unwrap();
        let later = bound(&mut tx, &pseudonym, &manifest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(later.state, State::Revoked);
        tx.commit().await.unwrap();
    }

    /// Run with TEST_DATABASE_URL set, as the other database tests.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn the_note_comes_from_the_invitation_the_device_used() {
        let db = crate::testdb::fresh().await;
        let manifest = format!("sha256:{}", "ab".repeat(32));
        let named = format!("pseudonym:{}", "01".repeat(32));
        let plain = format!("pseudonym:{}", "02".repeat(32));
        crate::testdb::enrolled_device(&db, &named, &manifest).await;
        crate::testdb::enrolled_device(&db, &plain, &manifest).await;
        let hash = format!("sha256:{}", "cd".repeat(32));
        sqlx::query("INSERT INTO invitations (hash, note, expires_at) VALUES ($1, 'Laptop, Example Person', now() + interval '1 day')")
            .bind(&hash)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("UPDATE devices SET invitation = $1 WHERE pseudonym = $2")
            .bind(&hash)
            .bind(&named)
            .execute(&db)
            .await
            .unwrap();
        let mut conn = db.acquire().await.unwrap();
        let named = Pseudonym::try_from(named).unwrap();
        let plain = Pseudonym::try_from(plain).unwrap();
        assert_eq!(
            note(&mut conn, &named, &manifest).await.unwrap(),
            "Laptop, Example Person"
        );
        assert_eq!(note(&mut conn, &plain, &manifest).await.unwrap(), "");
        let other = format!("sha256:{}", "ef".repeat(32));
        assert_eq!(note(&mut conn, &named, &other).await.unwrap(), "");
    }
}
