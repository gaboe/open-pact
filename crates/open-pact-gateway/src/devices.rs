use anyhow::{Context, bail};
use open_pact_core::{EntryKind, Pseudonym};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};

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

pub async fn state(
    conn: &mut PgConnection,
    device: &Pseudonym,
    manifest: &str,
) -> anyhow::Result<Option<State>> {
    let state: Option<String> =
        sqlx::query_scalar("SELECT state FROM devices WHERE pseudonym = $1 AND manifest_hash = $2")
            .bind(device.as_str())
            .bind(manifest)
            .fetch_optional(conn)
            .await?;
    state.as_deref().map(State::parse).transpose()
}

pub async fn revoked_anywhere(conn: &mut PgConnection, device: &Pseudonym) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM devices WHERE pseudonym = $1 AND state = 'revoked')",
    )
    .bind(device.as_str())
    .fetch_one(conn)
    .await?)
}

/// Applies `action` to every enrolment of `device` and logs each change. Returns the new states.
pub async fn apply(
    db: &PgPool,
    device: &str,
    action: Action,
) -> anyhow::Result<Vec<(String, State)>> {
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
        result.push((manifest, next));
    }
    tx.commit().await?;
    Ok(result)
}

/// The one pending pseudonym that starts with `prefix`. The owner reads the prefix out to IT.
pub async fn pending_by_prefix(db: &PgPool, prefix: &str) -> anyhow::Result<String> {
    const MIN: usize = 8;
    let hex = prefix.strip_prefix("pseudonym:").unwrap_or(prefix);
    if hex.len() < MIN || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        bail!("give at least {MIN} lowercase hex digits of the pseudonym, got {prefix:?}");
    }
    let found: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT pseudonym FROM devices WHERE state = 'pending' AND starts_with(pseudonym, $1) ORDER BY pseudonym",
    )
    .bind(format!("pseudonym:{hex}"))
    .fetch_all(db)
    .await?;
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => bail!("no pending device starts with pseudonym:{hex}"),
        many => bail!(
            "{} pending devices start with pseudonym:{hex}; give more digits:\n{}",
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

pub async fn list(db: &PgPool) -> anyhow::Result<String> {
    let rows: Vec<(String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT d.state, d.pseudonym, d.manifest_hash, \
                to_char(d.enrolled_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), i.note \
         FROM devices d LEFT JOIN invitations i ON i.hash = d.invitation \
         ORDER BY d.enrolled_at",
    )
    .fetch_all(db)
    .await?;
    let mut out = String::new();
    for (state, pseudonym, manifest, enrolled, note) in rows {
        let manifest = manifest.get(..19).unwrap_or(&manifest);
        out.push_str(&format!(
            "{state:<9} {pseudonym}  {manifest}  {enrolled}  {}\n",
            note.unwrap_or_default()
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
