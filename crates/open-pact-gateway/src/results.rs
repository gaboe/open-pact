//! Read results for IT (PAPER 4.4): `claims list` and `claims show`. Both open the sealed claims
//! with the KEK, read-only, and print JSON for an app that runs the command through `kubectl exec`.
//!
//! The gateway stores a claim's decision as one flag, `allowed`. A claim stored as allowed carries
//! a warning exactly when a required control of its manifest does not pass: a failing control
//! inside its grace is the only way an allowed claim has a failing control. So a result is
//! derived from `allowed` and from `control_compliance`, the function that evaluates a claim
//! against its manifest, and no second evaluator exists here.

use std::collections::HashMap;
use std::fmt::Write as _;

use anyhow::{Context, bail};
use clap::{Subcommand, ValueEnum};
use open_pact_core::{
    Claim, ControlValue, Manifest, Os, Pseudonym, TrustLevel, control_compliance,
};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::claims::{Opener, SELECT_STORED, Stored, StoredRow};
use crate::seal::SealingKey;
use crate::{devices, grace};

/// How many rows one query reads while `list` looks for matches.
const BATCH: i64 = 200;

#[derive(Subcommand)]
pub enum Command {
    /// List stored claims, newest first
    List {
        /// Print {"claims": [...], "unreadable": n}. On an error it prints {"error": ...}. Usage errors exit 2, other errors exit 1
        #[arg(long)]
        json: bool,
        /// Only claims of this device: at least 8 hex digits of its pseudonym
        #[arg(long)]
        device: Option<String>,
        /// Only claims with this result
        #[arg(long)]
        result: Option<Outcome>,
        /// Only claims received at or after this time (RFC 3339)
        #[arg(long, value_parser = parse_since)]
        since: Option<OffsetDateTime>,
        /// Stop after this many matches
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
        limit: u32,
    },
    /// Show every check of one claim against the manifest it was made under
    Show {
        id: i64,
        /// Print one JSON document. On an error it prints {"error": ...}. Usage errors exit 2, other errors exit 1
        #[arg(long)]
        json: bool,
    },
}

impl Command {
    pub fn prints_json(&self) -> bool {
        matches!(
            self,
            Command::List { json: true, .. } | Command::Show { json: true, .. }
        )
    }
}

/// How the gateway decided a claim. `accepted_with_warnings` of the device list is `warnings` here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Accepted,
    Warnings,
    Denied,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Accepted => "accepted",
            Outcome::Warnings => "warnings",
            Outcome::Denied => "denied",
        }
    }
}

pub struct Filter {
    pub device: Option<String>,
    pub result: Option<Outcome>,
    pub since: Option<OffsetDateTime>,
    pub limit: usize,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub id: i64,
    pub received_at: String,
    pub device: String,
    pub device_note: String,
    pub manifest_hash: String,
    /// Null for a claim an early version stored with no decision.
    pub result: Option<Outcome>,
    pub failed_controls: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Listing {
    pub claims: Vec<Summary>,
    /// Claims met on the way whose month key retention deleted. They cannot be opened, so no
    /// filter applies to them.
    pub unreadable: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    Unknown,
    NotRequired,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ControlRow {
    pub id: String,
    pub value: Option<ControlValue>,
    /// What the manifest requires on this OS. Null when it requires nothing, and when the
    /// manifest of the claim is not known to the gateway.
    pub required: Option<String>,
    /// `unknown` with `required: null` means the gateway could not evaluate the control.
    pub status: Status,
    /// The grace of a failing control: its own, or `unknown_grace` for an `unknown` value.
    pub grace: Option<String>,
    /// When the control began to fail, as the gateway holds it now.
    pub first_failed_at: Option<String>,
    pub deadline: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Detail {
    pub id: i64,
    pub received_at: String,
    pub device: String,
    pub device_note: String,
    pub manifest_hash: String,
    pub os: Os,
    pub client_version: String,
    pub trust_level: TrustLevel,
    pub result: Option<Outcome>,
    pub controls: Vec<ControlRow>,
}

fn stamp(t: OffsetDateTime) -> String {
    open_pact_core::timestamp::rfc3339_secs(t)
}

fn parse_since(text: &str) -> Result<OffsetDateTime, String> {
    open_pact_core::timestamp::parse_relaxed(text)
        .ok_or_else(|| format!("not an RFC 3339 time: {text}"))
}

/// The claim as the client signed it. `stored_claim` renamed `trust_level` and added two fields.
fn parse_claim(stored: &Value) -> anyhow::Result<Claim> {
    let mut claim = stored.clone();
    let fields = claim
        .as_object_mut()
        .context("the claim is not an object")?;
    fields.remove("verified_trust_level");
    fields.remove("certificate_sha256");
    if let Some(asserted) = fields.remove("asserted_trust_level") {
        fields.insert("trust_level".into(), asserted);
    }
    Ok(serde_json::from_value(claim)?)
}

/// The manifests of claims, read once each: a stored version, or the one the process started with.
struct Manifests<'a> {
    db: &'a PgPool,
    startup: Option<&'a Manifest>,
    found: HashMap<String, Option<Manifest>>,
}

impl<'a> Manifests<'a> {
    fn new(db: &'a PgPool, startup: Option<&'a Manifest>) -> Self {
        Manifests {
            db,
            startup,
            found: HashMap::new(),
        }
    }

    async fn get(&mut self, hash: &str) -> anyhow::Result<Option<&Manifest>> {
        if !self.found.contains_key(hash) {
            let toml: Option<String> = sqlx::query_scalar(
                "SELECT toml FROM manifest_versions WHERE hash = $1 ORDER BY version DESC LIMIT 1",
            )
            .bind(hash)
            .fetch_optional(self.db)
            .await?;
            let manifest = match toml {
                Some(toml) => Some(Manifest::parse(toml.as_bytes())?),
                None => self
                    .startup
                    .filter(|manifest| manifest.hash().as_str() == hash)
                    .cloned(),
            };
            self.found.insert(hash.to_owned(), manifest);
        }
        Ok(self.found[hash].as_ref())
    }
}

/// The invitation note of the device, empty when it has none. A device with several enrolments
/// gets the note of the newest.
async fn device_note(db: &PgPool, device: &str) -> anyhow::Result<String> {
    let note: Option<String> = sqlx::query_scalar(
        "SELECT i.note FROM devices d JOIN invitations i ON i.hash = d.invitation \
         WHERE d.pseudonym = $1 ORDER BY d.enrolled_at DESC LIMIT 1",
    )
    .bind(device)
    .fetch_optional(db)
    .await?;
    Ok(note.unwrap_or_default())
}

/// The ids of the required controls that do not pass.
fn failed_controls(manifest: &Manifest, claim: &Claim) -> Vec<String> {
    control_compliance(manifest, claim.os, &claim.results)
        .into_iter()
        .filter_map(|(id, passes)| (!passes).then_some(id))
        .collect()
}

fn outcome(allowed: Option<bool>, failed: Option<&[String]>) -> Option<Outcome> {
    match (allowed?, failed) {
        (false, _) => Some(Outcome::Denied),
        (true, Some(failed)) if !failed.is_empty() => Some(Outcome::Warnings),
        (true, _) => Some(Outcome::Accepted),
    }
}

/// Matching claims, newest first. It reads batches and stops after `filter.limit` matches.
pub async fn list(
    db: &PgPool,
    kek: &SealingKey,
    startup: Option<&Manifest>,
    filter: &Filter,
) -> anyhow::Result<Listing> {
    let device = filter
        .device
        .as_deref()
        .map(devices::pseudonym_prefix)
        .transpose()?;
    let mut opener = Opener::new(db, kek);
    let mut manifests = Manifests::new(db, startup);
    let mut notes: HashMap<String, String> = HashMap::new();
    let mut listing = Listing {
        claims: vec![],
        unreadable: 0,
    };
    let mut after: Option<(OffsetDateTime, i64)> = None;
    loop {
        let rows: Vec<StoredRow> = sqlx::query_as(&format!(
            "{SELECT_STORED} WHERE ($1::timestamptz IS NULL OR received_at >= $1) \
             AND ($2::timestamptz IS NULL OR (received_at, id) < ($2, $3::bigint)) \
             ORDER BY received_at DESC, id DESC LIMIT $4"
        ))
        .bind(filter.since)
        .bind(after.map(|(at, _)| at))
        .bind(after.map(|(_, id)| id))
        .bind(BATCH)
        .fetch_all(db)
        .await?;
        let Some(last) = rows.last() else {
            return Ok(listing);
        };
        after = Some((last.1, last.0));
        let read_all = (rows.len() as i64) < BATCH;
        for row in rows {
            let Some(stored) = opener.open(row).await? else {
                listing.unreadable += 1;
                continue;
            };
            if device
                .as_deref()
                .is_some_and(|prefix| !stored.device.starts_with(prefix))
            {
                continue;
            }
            let claim = parse_claim(&stored.claim).ok();
            let hash = claim.as_ref().map_or_else(
                || {
                    stored.claim["manifest"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned()
                },
                |claim| claim.manifest.as_str().to_owned(),
            );
            let failed = match (&claim, manifests.get(&hash).await?) {
                (Some(claim), Some(manifest)) => Some(failed_controls(manifest, claim)),
                _ => None,
            };
            let result = outcome(stored.allowed, failed.as_deref());
            if filter.result.is_some() && filter.result != result {
                continue;
            }
            if !notes.contains_key(&stored.device) {
                let note = device_note(db, &stored.device).await?;
                notes.insert(stored.device.clone(), note);
            }
            listing.claims.push(Summary {
                id: stored.id,
                received_at: stamp(stored.received_at),
                device_note: notes[&stored.device].clone(),
                device: stored.device,
                manifest_hash: hash,
                result,
                failed_controls: failed.unwrap_or_default(),
            });
            if listing.claims.len() >= filter.limit {
                return Ok(listing);
            }
        }
        if read_all {
            return Ok(listing);
        }
    }
}

/// One claim with every control of its manifest. Without that manifest the gateway cannot
/// evaluate: the result comes from the stored decision, and each control is `unknown`.
pub async fn show(
    db: &PgPool,
    kek: &SealingKey,
    startup: Option<&Manifest>,
    id: i64,
) -> anyhow::Result<Detail> {
    let row: Option<StoredRow> = sqlx::query_as(&format!("{SELECT_STORED} WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?;
    let Some(row) = row else {
        bail!("no claim with id {id}");
    };
    let Stored {
        received_at,
        allowed,
        device,
        claim: stored_claim,
        ..
    } = Opener::new(db, kek)
        .open(row)
        .await?
        .with_context(|| format!("claim {id} cannot be read: the key of its month was deleted"))?;
    let claim = parse_claim(&stored_claim).with_context(|| format!("claim {id} is not a claim"))?;
    let hash = claim.manifest.as_str().to_owned();
    let trust_level = serde_json::from_value(stored_claim["verified_trust_level"].clone())
        .unwrap_or(claim.trust_level);
    let manifest = Manifests::new(db, startup).get(&hash).await?.cloned();

    let (controls, failed) = match &manifest {
        Some(manifest) => {
            let failures = grace::load(
                &mut *db.acquire().await?,
                &Pseudonym::try_from(device.clone()).map_err(anyhow::Error::msg)?,
                &hash,
            )
            .await?;
            let compliance = control_compliance(manifest, claim.os, &claim.results);
            let body = manifest.body();
            let mut controls = vec![];
            for control in &body.controls {
                let value = claim.results.get(&control.id).cloned();
                let required = control.required.get(&claim.os);
                let (status, span) = match (required, compliance.get(&control.id)) {
                    (Some(_), Some(false)) => match &value {
                        Some(ControlValue::Text(text)) if text == "unknown" => {
                            (Status::Unknown, Some(&body.unknown_grace))
                        }
                        Some(_) => (Status::Fail, Some(&control.grace)),
                        None => (Status::Fail, None),
                    },
                    (Some(_), Some(true)) => (Status::Pass, None),
                    _ => (Status::NotRequired, None),
                };
                let failing = matches!(status, Status::Fail | Status::Unknown);
                let first_failed_at = failing.then(|| failures.get(&control.id)).flatten();
                controls.push(ControlRow {
                    id: control.id.clone(),
                    value,
                    required: required.map(ToString::to_string),
                    status,
                    grace: span.map(ToString::to_string),
                    first_failed_at: first_failed_at.copied().map(stamp),
                    deadline: span
                        .zip(first_failed_at)
                        .and_then(|(span, first)| first.checked_add(span.min_duration()?))
                        .map(stamp),
                });
            }
            (controls, Some(failed_controls(manifest, &claim)))
        }
        None => (
            claim
                .results
                .iter()
                .map(|(id, value)| ControlRow {
                    id: id.clone(),
                    value: Some(value.clone()),
                    required: None,
                    status: Status::Unknown,
                    grace: None,
                    first_failed_at: None,
                    deadline: None,
                })
                .collect(),
            None,
        ),
    };
    Ok(Detail {
        id,
        received_at: stamp(received_at),
        device_note: device_note(db, &device).await?,
        device,
        manifest_hash: hash,
        os: claim.os,
        client_version: claim
            .client
            .strip_prefix("open-pact-client ")
            .unwrap_or(&claim.client)
            .to_owned(),
        trust_level,
        result: outcome(allowed, failed.as_deref()),
        controls,
    })
}

fn code(device: &str) -> &str {
    let hex = device.strip_prefix("pseudonym:").unwrap_or(device);
    hex.get(..12).unwrap_or(hex)
}

fn render_list(listing: &Listing) -> String {
    let mut out = String::new();
    for claim in &listing.claims {
        let _ = writeln!(
            out,
            "{:>6}  {}  {:<8}  {}  {}  {}",
            claim.id,
            claim.received_at,
            claim.result.map_or("unknown", Outcome::as_str),
            code(&claim.device),
            claim.device_note,
            claim.failed_controls.join(","),
        );
    }
    if listing.unreadable > 0 {
        let _ = writeln!(
            out,
            "{} claims cannot be read: their month key was deleted",
            listing.unreadable
        );
    }
    out
}

fn render_detail(detail: &Detail) -> String {
    let status = |status: Status| match status {
        Status::Pass => "pass",
        Status::Fail => "fail",
        Status::Unknown => "unknown",
        Status::NotRequired => "not required",
    };
    let mut out = format!(
        "claim {}  {}  {}\ndevice {}  {}\nmanifest {}\n{}  client {}  trust {:?}\n",
        detail.id,
        detail.received_at,
        detail.result.map_or("unknown", Outcome::as_str),
        detail.device,
        detail.device_note,
        detail.manifest_hash,
        detail.os,
        detail.client_version,
        detail.trust_level,
    );
    for control in &detail.controls {
        let _ = writeln!(
            out,
            "{:<32} {:<12} {:<14} required {}  deadline {}",
            control.id,
            control
                .value
                .as_ref()
                .map_or("-".into(), ToString::to_string),
            status(control.status),
            control.required.as_deref().unwrap_or("-"),
            control.deadline.as_deref().unwrap_or("-"),
        );
    }
    out
}

pub async fn run(
    db: &PgPool,
    kek: &SealingKey,
    startup: Option<&Manifest>,
    command: Command,
) -> anyhow::Result<()> {
    match command {
        Command::List {
            json,
            device,
            result,
            since,
            limit,
        } => {
            let filter = Filter {
                device,
                result,
                since,
                limit: limit as usize,
            };
            let listing = list(db, kek, startup, &filter).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&listing)?);
            } else {
                print!("{}", render_list(&listing));
            }
        }
        Command::Show { id, json } => {
            let detail = show(db, kek, startup, id).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&detail)?);
            } else {
                print!("{}", render_detail(&detail));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use open_pact_core::{ManifestHash, PublicKey, Span, Virtualized, dev_key};
    use serde_json::json;
    use time::Duration;

    use super::*;
    use crate::{claims, testdb};

    const KEK: [u8; 32] = [9; 32];

    fn at(s: &str) -> OffsetDateTime {
        open_pact_core::timestamp::parse_rfc3339(s).unwrap()
    }

    /// The demo manifest's header and `[log]` section around two controls.
    fn manifest_toml() -> String {
        let demo = include_str!("../../../examples/manifest.toml");
        let header = demo.split("[[control]]").next().unwrap();
        let log = demo.split("[log]").nth(1).unwrap();
        format!(
            "{header}{}\n[log]{log}",
            r#"
[[control]]
id = "disk_encryption"
source = "customer_contract"
check = "builtin:disk_encryption@1"
output = ["full", "partial", "none", "unknown"]
required = { macos = "full", linux = "full" }
grace = "0d"

[[control]]
id = "firewall"
source = "company_policy"
check = "builtin:firewall@1"
output = ["on", "off", "unknown"]
required = { linux = "on" }
grace = "1d"
"#
        )
    }

    fn manifest() -> Manifest {
        Manifest::parse(manifest_toml().as_bytes()).unwrap()
    }

    fn claim(
        device: &Pseudonym,
        manifest: &ManifestHash,
        os: Os,
        time: OffsetDateTime,
        results: &[(&str, &str)],
    ) -> Claim {
        Claim {
            manifest: manifest.clone(),
            device: device.clone(),
            device_key: PublicKey::from(&dev_key::generate()),
            nonce: "fictional-nonce".into(),
            time,
            client: "open-pact-client 0.6.0".into(),
            os,
            trust_level: TrustLevel::L0,
            virtualized: Some(Virtualized::No),
            results: results
                .iter()
                .map(|(id, value)| (id.to_string(), (*value).into()))
                .collect::<BTreeMap<_, _>>(),
            csr_sha256: None,
            log_checkpoint: None,
        }
    }

    async fn put(db: &PgPool, retention: &str, claim: &Claim, allowed: bool) -> i64 {
        let retention: Span = retention.to_string().try_into().unwrap();
        let payload = crate::stored_claim(claim, None).unwrap();
        let mut conn = db.acquire().await.unwrap();
        claims::store(
            &mut conn,
            &SealingKey::new(&KEK),
            &retention,
            claim.time,
            &claim.device,
            &payload,
            "jws",
            allowed,
        )
        .await
        .unwrap();
        sqlx::query_scalar("SELECT max(id) FROM claims")
            .fetch_one(db)
            .await
            .unwrap()
    }

    async fn keep_manifest(db: &PgPool, manifest: &Manifest) {
        sqlx::query("INSERT INTO manifest_versions (toml, hash, active) VALUES ($1, $2, false)")
            .bind(manifest_toml())
            .bind(manifest.hash().as_str())
            .execute(db)
            .await
            .unwrap();
    }

    fn filter() -> Filter {
        Filter {
            device: None,
            result: None,
            since: None,
            limit: 100,
        }
    }

    struct World {
        db: PgPool,
        kek: SealingKey,
        manifest: Manifest,
        a: Pseudonym,
        b: Pseudonym,
        /// Claim ids in the order they were received: A accepted, B warns, A denied, B accepted,
        /// A with an unknown firewall.
        ids: [i64; 5],
    }

    async fn world() -> World {
        let db = testdb::fresh().await;
        let manifest = manifest();
        keep_manifest(&db, &manifest).await;
        let hash = manifest.hash();
        let a = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        let b = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        for device in [&a, &b] {
            testdb::enrolled_device(&db, device.as_str(), hash.as_str()).await;
        }
        sqlx::query("INSERT INTO invitations (hash, note, expires_at) VALUES ('h', 'Example laptop', now())")
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("UPDATE devices SET invitation = 'h' WHERE pseudonym = $1")
            .bind(a.as_str())
            .execute(&db)
            .await
            .unwrap();
        let ok = [("disk_encryption", "full"), ("firewall", "on")];
        let ids = [
            put(
                &db,
                "12mo",
                &claim(&a, hash, Os::Linux, at("2026-10-01T08:00:00Z"), &ok),
                true,
            )
            .await,
            put(
                &db,
                "12mo",
                &claim(
                    &b,
                    hash,
                    Os::Linux,
                    at("2026-10-02T08:00:00Z"),
                    &[("disk_encryption", "full"), ("firewall", "off")],
                ),
                true,
            )
            .await,
            put(
                &db,
                "12mo",
                &claim(
                    &a,
                    hash,
                    Os::Linux,
                    at("2026-10-03T08:00:00Z"),
                    &[("disk_encryption", "none"), ("firewall", "on")],
                ),
                false,
            )
            .await,
            put(
                &db,
                "12mo",
                &claim(&b, hash, Os::Linux, at("2026-10-04T08:00:00Z"), &ok),
                true,
            )
            .await,
            put(
                &db,
                "12mo",
                &claim(
                    &a,
                    hash,
                    Os::Macos,
                    at("2026-10-05T08:00:00Z"),
                    &[("disk_encryption", "unknown")],
                ),
                true,
            )
            .await,
        ];
        World {
            db,
            kek: SealingKey::new(&KEK),
            manifest,
            a,
            b,
            ids,
        }
    }

    fn ids(listing: &Listing) -> Vec<i64> {
        listing.claims.iter().map(|c| c.id).collect()
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn lists_the_newest_claim_first_with_its_device_note_result_and_failed_controls() {
        let w = world().await;
        let listing = list(&w.db, &w.kek, None, &filter()).await.unwrap();
        let [c1, c2, c3, c4, c5] = w.ids;
        assert_eq!(ids(&listing), [c5, c4, c3, c2, c1]);
        assert_eq!(listing.unreadable, 0);
        let newest = &listing.claims[0];
        assert_eq!(newest.received_at, "2026-10-05T08:00:00Z");
        assert_eq!(newest.device, w.a.as_str());
        assert_eq!(newest.device_note, "Example laptop");
        assert_eq!(newest.manifest_hash, w.manifest.hash().as_str());
        assert_eq!(newest.result, Some(Outcome::Warnings));
        assert_eq!(newest.failed_controls, ["disk_encryption"]);
        let results: Vec<_> = listing.claims.iter().map(|c| c.result).collect();
        assert_eq!(
            results,
            [
                Some(Outcome::Warnings),
                Some(Outcome::Accepted),
                Some(Outcome::Denied),
                Some(Outcome::Warnings),
                Some(Outcome::Accepted)
            ]
        );
        assert_eq!(listing.claims[2].failed_controls, ["disk_encryption"]);
        assert_eq!(listing.claims[3].failed_controls, ["firewall"]);
        assert_eq!(
            listing.claims[3].device_note, "",
            "device B has no invitation note"
        );
        assert_eq!(
            serde_json::to_value(newest).unwrap()["result"],
            json!("warnings")
        );
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn filters_by_device_prefix_result_and_start_time() {
        let w = world().await;
        let [c1, c2, c3, c4, c5] = w.ids;
        let hex = w.a.as_str().trim_start_matches("pseudonym:");
        for prefix in [&hex[..8], &hex[..20], w.a.as_str()] {
            let only_a = Filter {
                device: Some(prefix.to_string()),
                ..filter()
            };
            let listing = list(&w.db, &w.kek, None, &only_a).await.unwrap();
            assert_eq!(ids(&listing), [c5, c3, c1], "{prefix}");
        }
        let short = Filter {
            device: Some(hex[..7].to_string()),
            ..filter()
        };
        assert!(list(&w.db, &w.kek, None, &short).await.is_err());

        for (result, expected) in [
            (Outcome::Accepted, vec![c4, c1]),
            (Outcome::Warnings, vec![c5, c2]),
            (Outcome::Denied, vec![c3]),
        ] {
            let only = Filter {
                result: Some(result),
                ..filter()
            };
            let listing = list(&w.db, &w.kek, None, &only).await.unwrap();
            assert_eq!(ids(&listing), expected, "{result:?}");
        }

        let since = Filter {
            since: Some(at("2026-10-03T08:00:00Z")),
            ..filter()
        };
        let listing = list(&w.db, &w.kek, None, &since).await.unwrap();
        assert_eq!(ids(&listing), [c5, c4, c3], "since is inclusive");

        let both = Filter {
            device: Some(hex[..8].to_string()),
            result: Some(Outcome::Warnings),
            since: Some(at("2026-10-01T08:00:00Z")),
            ..filter()
        };
        assert_eq!(ids(&list(&w.db, &w.kek, None, &both).await.unwrap()), [c5]);
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn stops_after_limit_matches_across_batches() {
        let w = world().await;
        let two = Filter {
            limit: 2,
            ..filter()
        };
        let listing = list(&w.db, &w.kek, None, &two).await.unwrap();
        assert_eq!(ids(&listing), [w.ids[4], w.ids[3]]);

        let hash = w.manifest.hash();
        let ok = [("disk_encryption", "full"), ("firewall", "on")];
        for i in 0..(BATCH + 5) {
            let time = at("2026-10-06T00:00:00Z") + Duration::minutes(i);
            put(
                &w.db,
                "12mo",
                &claim(&w.b, hash, Os::Linux, time, &ok),
                true,
            )
            .await;
        }
        let only_a = Filter {
            device: Some(w.a.as_str().into()),
            ..filter()
        };
        let listing = list(&w.db, &w.kek, None, &only_a).await.unwrap();
        assert_eq!(
            ids(&listing),
            [w.ids[4], w.ids[2], w.ids[0]],
            "claims of A sit behind more than one batch"
        );
        let all = list(&w.db, &w.kek, None, &filter()).await.unwrap();
        assert_eq!(all.claims.len(), 100);
        let all = Filter {
            limit: 1000,
            ..filter()
        };
        assert_eq!(
            list(&w.db, &w.kek, None, &all).await.unwrap().claims.len(),
            5 + BATCH as usize + 5
        );
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn counts_a_claim_of_a_shredded_month_as_unreadable() {
        let w = world().await;
        let hash = w.manifest.hash();
        let short = put(
            &w.db,
            "1h",
            &claim(
                &w.a,
                hash,
                Os::Linux,
                at("2026-08-10T08:00:00Z"),
                &[("firewall", "on")],
            ),
            true,
        )
        .await;
        sqlx::query("ALTER TABLE claims DROP CONSTRAINT claims_period_fkey")
            .execute(&w.db)
            .await
            .unwrap();
        let shredded = sqlx::query("DELETE FROM claim_keys WHERE period = '2026-08-01'")
            .execute(&w.db)
            .await
            .unwrap()
            .rows_affected();
        assert_eq!(shredded, 1);

        let listing = list(&w.db, &w.kek, None, &filter()).await.unwrap();
        assert_eq!(listing.unreadable, 1);
        assert_eq!(
            listing.claims.len(),
            5,
            "the five readable claims still list"
        );
        assert!(!ids(&listing).contains(&short));
        let only_denied = Filter {
            result: Some(Outcome::Denied),
            ..filter()
        };
        let listing = list(&w.db, &w.kek, None, &only_denied).await.unwrap();
        assert_eq!((ids(&listing), listing.unreadable), (vec![w.ids[2]], 1));
        let since = Filter {
            since: Some(at("2026-09-01T00:00:00Z")),
            ..filter()
        };
        assert_eq!(
            list(&w.db, &w.kek, None, &since).await.unwrap().unreadable,
            0
        );

        let error = show(&w.db, &w.kek, None, short).await.unwrap_err();
        assert!(error.to_string().contains("month was deleted"), "{error:#}");
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn show_evaluates_each_control_with_its_grace_and_deadline() {
        let w = world().await;
        let first = at("2026-10-02T06:00:00Z");
        sqlx::query(
            "INSERT INTO control_failures (pseudonym, manifest_hash, control, first_failed_at) VALUES ($1, $2, 'firewall', $3)",
        )
        .bind(w.b.as_str())
        .bind(w.manifest.hash().as_str())
        .bind(first)
        .execute(&w.db)
        .await
        .unwrap();

        let warned = show(&w.db, &w.kek, None, w.ids[1]).await.unwrap();
        assert_eq!(warned.result, Some(Outcome::Warnings));
        assert_eq!(warned.os, Os::Linux);
        assert_eq!(warned.client_version, "0.6.0");
        assert_eq!(warned.trust_level, TrustLevel::L0);
        assert_eq!(warned.device, w.b.as_str());
        assert_eq!(warned.manifest_hash, w.manifest.hash().as_str());
        assert_eq!(warned.controls.len(), 2);
        let disk = &warned.controls[0];
        assert_eq!(
            (disk.id.as_str(), disk.status, disk.required.as_deref()),
            ("disk_encryption", Status::Pass, Some("full"))
        );
        assert_eq!(
            (&disk.grace, &disk.first_failed_at, &disk.deadline),
            (&None, &None, &None)
        );
        let firewall = &warned.controls[1];
        assert_eq!(firewall.value, Some("off".into()));
        assert_eq!(firewall.required.as_deref(), Some("on"));
        assert_eq!(firewall.status, Status::Fail);
        assert_eq!(firewall.grace.as_deref(), Some("1d"));
        assert_eq!(
            firewall.first_failed_at.as_deref(),
            Some("2026-10-02T06:00:00Z")
        );
        assert_eq!(firewall.deadline.as_deref(), Some("2026-10-03T06:00:00Z"));
        let document = serde_json::to_value(&warned).unwrap();
        assert_eq!(document["controls"][1]["status"], "fail");
        assert_eq!(document["controls"][1]["value"], "off");

        let denied = show(&w.db, &w.kek, None, w.ids[2]).await.unwrap();
        assert_eq!(denied.result, Some(Outcome::Denied));
        let disk = &denied.controls[0];
        assert_eq!(
            (disk.status, disk.grace.as_deref()),
            (Status::Fail, Some("0d"))
        );
        assert_eq!(
            disk.first_failed_at, None,
            "the gateway holds no start for it"
        );
        assert_eq!(disk.deadline, None);
    }

    /// A month of grace ends when the evaluator stops accepting the failure: 28 days, not a
    /// calendar month.
    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn show_deadline_of_a_month_grace_is_the_day_the_evaluator_stops_accepting() {
        let db = testdb::fresh().await;
        let toml = manifest_toml()
            .replace(
                "required = { linux = \"on\" }\ngrace = \"1d\"",
                "required = { linux = \"on\" }\ngrace = \"1mo\"",
            )
            .replace("unknown_grace = \"7d\"", "unknown_grace = \"1mo\"");
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        sqlx::query("INSERT INTO manifest_versions (toml, hash, active) VALUES ($1, $2, false)")
            .bind(&toml)
            .bind(manifest.hash().as_str())
            .execute(&db)
            .await
            .unwrap();
        let device = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        testdb::enrolled_device(&db, device.as_str(), manifest.hash().as_str()).await;
        sqlx::query(
            "INSERT INTO control_failures (pseudonym, manifest_hash, control, first_failed_at) VALUES ($1, $2, 'firewall', $3)",
        )
        .bind(device.as_str())
        .bind(manifest.hash().as_str())
        .bind(at("2026-10-01T08:00:00Z"))
        .execute(&db)
        .await
        .unwrap();
        let evaluated = at("2026-10-30T08:00:00Z");
        let off = put(
            &db,
            "12mo",
            &claim(
                &device,
                manifest.hash(),
                Os::Linux,
                evaluated,
                &[("disk_encryption", "full"), ("firewall", "off")],
            ),
            false,
        )
        .await;
        let unknown = put(
            &db,
            "12mo",
            &claim(
                &device,
                manifest.hash(),
                Os::Linux,
                evaluated,
                &[("disk_encryption", "full"), ("firewall", "unknown")],
            ),
            false,
        )
        .await;

        let kek = SealingKey::new(&KEK);
        for id in [off, unknown] {
            let detail = show(&db, &kek, None, id).await.unwrap();
            let firewall = detail.controls.iter().find(|c| c.id == "firewall").unwrap();
            assert_eq!(
                firewall.deadline.as_deref(),
                Some("2026-10-29T08:00:00Z"),
                "claim {id}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn show_marks_unknown_values_missing_values_and_controls_the_os_does_not_require() {
        let w = world().await;
        sqlx::query(
            "INSERT INTO control_failures (pseudonym, manifest_hash, control, first_failed_at) VALUES ($1, $2, 'disk_encryption', $3)",
        )
        .bind(w.a.as_str())
        .bind(w.manifest.hash().as_str())
        .bind(at("2026-10-04T08:00:00Z"))
        .execute(&w.db)
        .await
        .unwrap();

        let unknown = show(&w.db, &w.kek, None, w.ids[4]).await.unwrap();
        assert_eq!(unknown.os, Os::Macos);
        let disk = &unknown.controls[0];
        assert_eq!(disk.status, Status::Unknown);
        assert_eq!(
            disk.grace.as_deref(),
            Some("7d"),
            "an unknown value waits for unknown_grace"
        );
        assert_eq!(disk.deadline.as_deref(), Some("2026-10-11T08:00:00Z"));
        let firewall = &unknown.controls[1];
        assert_eq!(
            (
                firewall.status,
                firewall.required.as_deref(),
                &firewall.value
            ),
            (Status::NotRequired, None, &None),
            "macos has no firewall requirement"
        );
        assert_eq!(
            serde_json::to_value(firewall).unwrap()["status"],
            "not_required"
        );
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn show_reads_the_manifest_the_process_started_with_or_gives_up_evaluating() {
        let db = testdb::fresh().await;
        let kek = SealingKey::new(&KEK);
        let manifest = manifest();
        let device = Pseudonym::of(&PublicKey::from(&dev_key::generate()));
        let results = [("disk_encryption", "none"), ("firewall", "on")];
        let id = put(
            &db,
            "12mo",
            &claim(
                &device,
                manifest.hash(),
                Os::Linux,
                at("2026-10-01T08:00:00Z"),
                &results,
            ),
            true,
        )
        .await;

        let from_startup = show(&db, &kek, Some(&manifest), id).await.unwrap();
        assert_eq!(from_startup.result, Some(Outcome::Warnings));
        assert_eq!(from_startup.controls[0].status, Status::Fail);
        assert_eq!(from_startup.controls[0].required.as_deref(), Some("full"));
        let listing = list(&db, &kek, Some(&manifest), &filter()).await.unwrap();
        assert_eq!(listing.claims[0].failed_controls, ["disk_encryption"]);

        let blind = show(&db, &kek, None, id).await.unwrap();
        assert_eq!(
            blind.result,
            Some(Outcome::Accepted),
            "only the stored decision is left"
        );
        assert!(
            blind
                .controls
                .iter()
                .all(|c| c.required.is_none() && c.status == Status::Unknown)
        );
        assert_eq!(blind.controls.len(), 2);
        let listing = list(&db, &kek, None, &filter()).await.unwrap();
        assert_eq!(listing.claims[0].result, Some(Outcome::Accepted));
        assert!(listing.claims[0].failed_controls.is_empty());
    }

    #[tokio::test]
    #[ignore = "needs TEST_DATABASE_URL"]
    async fn show_fails_for_an_unknown_id_and_reads_a_claim_nothing_decided() {
        let w = world().await;
        let error = show(&w.db, &w.kek, None, 987_654).await.unwrap_err();
        assert_eq!(error.to_string(), "no claim with id 987654");

        sqlx::query("UPDATE claims SET allowed = NULL WHERE id = $1")
            .bind(w.ids[0])
            .execute(&w.db)
            .await
            .unwrap();
        let listing = list(&w.db, &w.kek, None, &filter()).await.unwrap();
        assert_eq!(listing.claims[4].result, None);
        let none = Filter {
            result: Some(Outcome::Accepted),
            ..filter()
        };
        assert_eq!(
            ids(&list(&w.db, &w.kek, None, &none).await.unwrap()),
            [w.ids[3]]
        );
    }

    #[test]
    fn a_failed_control_makes_an_allowed_claim_a_warning() {
        let failed = ["firewall".to_string()];
        assert_eq!(outcome(Some(true), Some(&failed)), Some(Outcome::Warnings));
        assert_eq!(outcome(Some(true), Some(&[])), Some(Outcome::Accepted));
        assert_eq!(outcome(Some(true), None), Some(Outcome::Accepted));
        assert_eq!(outcome(Some(false), Some(&[])), Some(Outcome::Denied));
        assert_eq!(outcome(None, Some(&failed)), None);
    }

    #[test]
    fn the_text_forms_name_the_device_by_its_code() {
        let listing = Listing {
            claims: vec![Summary {
                id: 7,
                received_at: "2026-10-05T08:00:00Z".into(),
                device: format!("pseudonym:{}", "ab".repeat(32)),
                device_note: "Example laptop".into(),
                manifest_hash: "sha256:x".into(),
                result: Some(Outcome::Denied),
                failed_controls: vec!["firewall".into(), "screen_lock".into()],
            }],
            unreadable: 2,
        };
        let text = render_list(&listing);
        assert!(
            text.starts_with("     7  2026-10-05T08:00:00Z  denied    abababababab  Example laptop  firewall,screen_lock\n"),
            "{text}"
        );
        assert!(text.contains("2 claims cannot be read"), "{text}");
    }
}

#[cfg(test)]
mod timestamp_pins {
    use super::*;

    #[test]
    fn stamps_are_whole_seconds_in_utc() {
        assert_eq!(
            stamp(open_pact_core::timestamp::parse_rfc3339("2026-10-05T08:00:00.9Z").unwrap()),
            "2026-10-05T08:00:00Z"
        );
        assert_eq!(
            stamp(open_pact_core::timestamp::parse_rfc3339("2026-10-05T10:00:00.5+02:00").unwrap()),
            "2026-10-05T08:00:00Z"
        );
    }

    #[test]
    fn since_accepts_the_rfc3339_spellings_clap_reads() {
        for (text, ok) in [
            ("2026-10-05T08:00:00Z", true),
            ("2026-10-05T10:00:00.5+02:00", true),
            ("2026-10-05 08:00:00Z", true),
            ("2026-10-05T08:00:00", false),
            ("2026-10-05", false),
        ] {
            assert_eq!(parse_since(text).is_ok(), ok, "{text}");
        }
    }

    #[test]
    fn since_keeps_a_leap_second_as_the_first_second_of_the_next_minute() {
        assert_eq!(
            stamp(parse_since("2016-12-31T23:59:60Z").unwrap()),
            "2017-01-01T00:00:00Z"
        );
    }

    #[test]
    fn since_out_of_range_is_an_error_not_a_panic() {
        for text in ["9999-12-31T23:59:59-23:59", "+10000-01-01T00:00:00Z"] {
            assert_eq!(
                parse_since(text),
                Err(format!("not an RFC 3339 time: {text}"))
            );
        }
    }
}
