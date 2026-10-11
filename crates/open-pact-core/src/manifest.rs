use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::{Error, ManifestHash, WitnessKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Macos,
    Windows,
    Linux,
}

impl Os {
    pub const ALL: [Os; 3] = [Os::Macos, Os::Windows, Os::Linux];
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Os::Macos => "macos",
            Os::Windows => "windows",
            Os::Linux => "linux",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    L0,
    L1,
    L2,
}

/// A claim field besides `results`. Every claim carries the mandatory ones, so a manifest must list
/// them all. The client sends an optional one only if the manifest lists it, and the gateway
/// denies and does not store a claim with an optional field the manifest does not list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Metadata {
    ManifestHash,
    DevicePseudonym,
    DeviceKey,
    Nonce,
    Time,
    ClientVersion,
    Os,
    TrustLevel,
    VpnCertificateRequest,
    Virtualized,
    LogCheckpoint,
}

impl Metadata {
    pub const MANDATORY: [Metadata; 9] = [
        Metadata::ManifestHash,
        Metadata::DevicePseudonym,
        Metadata::DeviceKey,
        Metadata::Nonce,
        Metadata::Time,
        Metadata::ClientVersion,
        Metadata::Os,
        Metadata::TrustLevel,
        Metadata::VpnCertificateRequest,
    ];
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Metadata::ManifestHash => "manifest_hash",
            Metadata::DevicePseudonym => "device_pseudonym",
            Metadata::DeviceKey => "device_key",
            Metadata::Nonce => "nonce",
            Metadata::Time => "time",
            Metadata::ClientVersion => "client_version",
            Metadata::Os => "os",
            Metadata::TrustLevel => "trust_level",
            Metadata::VpnCertificateRequest => "vpn_certificate_request",
            Metadata::Virtualized => "virtualized",
            Metadata::LogCheckpoint => "log_checkpoint",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Law,
    CustomerContract,
    Standard,
    CompanyPolicy,
}

/// A manifest duration. Months have no fixed length, so comparisons use each span's possible range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Span {
    amount: u64,
    unit: Unit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    Hour,
    Day,
    Week,
    Month,
}

const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;

impl Span {
    fn min_secs(&self) -> u64 {
        self.amount
            * match self.unit {
                Unit::Hour => HOUR,
                Unit::Day => DAY,
                Unit::Week => 7 * DAY,
                Unit::Month => 28 * DAY,
            }
    }

    fn max_secs(&self) -> u64 {
        match self.unit {
            Unit::Month => self.amount * 31 * DAY,
            _ => self.min_secs(),
        }
    }

    pub fn min_duration(&self) -> Option<chrono::TimeDelta> {
        chrono::TimeDelta::try_seconds(i64::try_from(self.min_secs()).ok()?)
    }

    /// The instant this span before `t`, in calendar months for `mo`, so `12mo` before
    /// 2026-10-15 is 2025-10-15. `None` when that is before the start of the calendar.
    pub fn before(
        &self,
        t: chrono::DateTime<chrono::Utc>,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        match self.unit {
            Unit::Month => {
                t.checked_sub_months(chrono::Months::new(u32::try_from(self.amount).ok()?))
            }
            _ => t.checked_sub_signed(self.min_duration()?),
        }
    }

    /// The instant this span after `t`, in calendar months for `mo`. `None` past the calendar.
    pub fn after(&self, t: chrono::DateTime<chrono::Utc>) -> Option<chrono::DateTime<chrono::Utc>> {
        match self.unit {
            Unit::Month => {
                t.checked_add_months(chrono::Months::new(u32::try_from(self.amount).ok()?))
            }
            _ => t.checked_add_signed(self.min_duration()?),
        }
    }

    pub fn is_zero(&self) -> bool {
        self.amount == 0
    }

    pub fn certainly_shorter_or_equal(&self, other: &Span) -> bool {
        self == other || self.max_secs() <= other.min_secs()
    }
}

impl TryFrom<String> for Span {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (digits, suffix) = s.split_at(split);
        let unit = match suffix {
            "h" => Unit::Hour,
            "d" => Unit::Day,
            "w" => Unit::Week,
            "mo" => Unit::Month,
            _ => return Err(format!("duration {s:?} must end in h, d, w or mo")),
        };
        let amount: u64 = digits
            .parse()
            .map_err(|_| format!("duration {s:?} must start with a number"))?;
        if amount > u64::MAX / (31 * DAY) {
            return Err(format!("duration {s:?} is too long"));
        }
        Ok(Span { amount, unit })
    }
}

impl From<Span> for String {
    fn from(span: Span) -> String {
        span.to_string()
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unit = match self.unit {
            Unit::Hour => "h",
            Unit::Day => "d",
            Unit::Week => "w",
            Unit::Month => "mo",
        };
        write!(f, "{}{unit}", self.amount)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "OneOrMany")]
pub struct Accepted(pub BTreeSet<String>);

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl From<OneOrMany> for Accepted {
    fn from(v: OneOrMany) -> Self {
        Accepted(match v {
            OneOrMany::One(s) => BTreeSet::from([s]),
            OneOrMany::Many(v) => v.into_iter().collect(),
        })
    }
}

impl Accepted {
    pub fn contains(&self, value: &str) -> bool {
        self.0.contains(value)
    }
}

impl fmt::Display for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let values: Vec<&str> = self.0.iter().map(String::as_str).collect();
        match values.as_slice() {
            [one] => f.write_str(one),
            many => write!(f, "one of {}", many.join(", ")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub id: String,
    pub source: Source,
    pub source_ref: Option<String>,
    pub rationale: Option<String>,
    pub check: String,
    pub output: Vec<String>,
    pub required: BTreeMap<Os, Accepted>,
    pub grace: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestBody {
    pub manifest_version: u32,
    pub issuer: String,
    pub valid_from: NaiveDate,
    pub claim_max_age: Span,
    pub claim_retention: Span,
    pub claim_recipients: BTreeSet<String>,
    pub disclosed_metadata: BTreeSet<Metadata>,
    pub data_controller: String,
    pub min_trust_level: TrustLevel,
    pub unknown_grace: Span,
    #[serde(rename = "control")]
    pub controls: Vec<Control>,
    /// Always present after `Manifest::parse`.
    #[serde(default)]
    pub log: Option<LogPolicy>,
}

/// Which witnesses must cosign a log checkpoint before a client trusts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogPolicy {
    /// Accepts a policy without witnesses, so the gateway can show devices different histories.
    #[serde(default)]
    pub allow_split_views: bool,
    #[serde(default)]
    pub witnesses: Vec<Witness>,
    pub witness_quorum: usize,
    /// The oldest witness cosignature a client accepts, so a frozen checkpoint stops verifying.
    pub checkpoint_max_age: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub name: String,
    pub key: WitnessKey,
}

impl LogPolicy {
    fn validate(&self) -> Result<(), String> {
        let mut names = BTreeSet::new();
        for w in &self.witnesses {
            if w.key.name() != w.name {
                return Err(format!(
                    "log.witnesses: key {} is not named {:?}",
                    w.key.vkey(),
                    w.name
                ));
            }
            if !names.insert(&w.name) {
                return Err(format!("log.witnesses: duplicate witness {:?}", w.name));
            }
        }
        let (quorum, listed) = (self.witness_quorum, self.witnesses.len());
        match (listed, self.allow_split_views) {
            (0, true) if quorum == 0 => {}
            (0, true) => return Err("log.witness_quorum must be 0 without witnesses".into()),
            (0, false) => {
                return Err("log.witnesses is empty: list witnesses, or set \
                     log.allow_split_views = true to accept that the gateway can show devices \
                     different histories"
                    .into());
            }
            (_, true) => {
                return Err("log.allow_split_views is only for a policy without witnesses".into());
            }
            // Two sets of more than half the witnesses share one, and an honest witness cosigns one
            // history only, so no two accepted checkpoints can belong to different histories.
            (_, false) if 2 * quorum <= listed || quorum > listed => {
                return Err(format!(
                    "log.witness_quorum {quorum} must be more than half of the {listed} witnesses \
                     listed and at most {listed}"
                ));
            }
            (_, false) => {}
        }
        if self.checkpoint_max_age.is_zero() {
            return Err("log.checkpoint_max_age must not be zero".into());
        }
        Ok(())
    }
}

impl ManifestBody {
    pub fn control(&self, id: &str) -> Option<&Control> {
        self.controls.iter().find(|c| c.id == id)
    }

    pub fn discloses(&self, field: Metadata) -> bool {
        self.disclosed_metadata.contains(&field)
    }

    fn validate(&self) -> Result<(), String> {
        let missing: Vec<String> = Metadata::MANDATORY
            .iter()
            .filter(|m| !self.discloses(**m))
            .map(ToString::to_string)
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "disclosed_metadata must list {}: every claim carries them",
                missing.join(", ")
            ));
        }
        if self.unknown_grace.is_zero() {
            return Err("unknown_grace must not be zero".into());
        }
        self.log
            .as_ref()
            .ok_or("the manifest needs a [log] section: list witnesses, or set allow_split_views = true")?
            .validate()?;
        let mut ids = BTreeSet::new();
        for c in &self.controls {
            if !ids.insert(&c.id) {
                return Err(format!("duplicate control id {:?}", c.id));
            }
            if !c.check.starts_with("builtin:") {
                return Err(format!("{}: check must be builtin:<name>@<version>", c.id));
            }
            let outputs: BTreeSet<&String> = c.output.iter().collect();
            if outputs.is_empty() || outputs.len() != c.output.len() {
                return Err(format!("{}: output must be non-empty and unique", c.id));
            }
            for (os, accepted) in &c.required {
                if accepted.0.is_empty() || !accepted.0.iter().all(|v| outputs.contains(v)) {
                    return Err(format!(
                        "{}: required.{os} must be a non-empty subset of output",
                        c.id
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    hash: ManifestHash,
    body: ManifestBody,
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| Error::InvalidManifest("not UTF-8".into()))?;
        let body: ManifestBody = toml::from_str(text)?;
        body.validate().map_err(Error::InvalidManifest)?;
        Ok(Manifest {
            hash: ManifestHash::of(bytes),
            body,
        })
    }

    pub fn hash(&self) -> &ManifestHash {
        &self.hash
    }

    pub fn body(&self) -> &ManifestBody {
        &self.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = include_str!("../../../examples/manifest.toml");

    #[test]
    fn demo_manifest_parses() {
        let m = Manifest::parse(DEMO.as_bytes()).unwrap();
        let disk = m.body().control("disk_encryption").unwrap();
        assert_eq!(
            disk.required[&Os::Macos],
            Accepted(BTreeSet::from(["full".to_string()]))
        );
        assert!(disk.grace.is_zero());
        assert_eq!(m.body().min_trust_level, TrustLevel::L0);
    }

    #[test]
    fn paper_appendix_a_parses() {
        let paper = include_str!("../../../PAPER.md");
        let appendix = &paper[paper.find("## Appendix A").unwrap()..];
        let start = appendix.find("```toml\n").unwrap() + "```toml\n".len();
        let toml = &appendix[start..start + appendix[start..].find("```").unwrap()];
        let m = Manifest::parse(toml.as_bytes()).unwrap();
        assert_eq!(m.body().controls.len(), 15);
        assert!(
            !m.body()
                .control("antimalware_active")
                .unwrap()
                .required
                .contains_key(&Os::Linux)
        );
    }

    #[test]
    fn required_accepts_a_list() {
        let toml = DEMO.replace(
            r#"required = { macos = "le_5min", windows = "le_5min", linux = "le_5min" }"#,
            r#"required = { macos = ["le_5min", "le_15min"] }"#,
        );
        let m = Manifest::parse(toml.as_bytes()).unwrap();
        let lock = m.body().control("screen_lock").unwrap();
        assert!(lock.required[&Os::Macos].contains("le_15min"));
        assert!(!lock.required.contains_key(&Os::Linux));
    }

    fn rejects(from: &str, to: &str) {
        assert!(DEMO.contains(from), "fixture lacks {from}");
        let toml = DEMO.replacen(from, to, 1);
        assert!(Manifest::parse(toml.as_bytes()).is_err(), "accepted {to}");
    }

    #[test]
    fn parse_rejects_invalid_manifests() {
        rejects(r#"unknown_grace = "7d""#, r#"unknown_grace = "0d""#);
        rejects(r#"macos = "full""#, r#"macos = "encrypted""#);
        rejects(
            r#"check = "builtin:firewall@1""#,
            r#"check = "shell:ufw status""#,
        );
        rejects(r#"id = "firewall""#, r#"id = "disk_encryption""#);
        rejects(r#"grace = "0d""#, r#"grace = "0 days""#);
        rejects(r#"source = "company_policy""#, r#"source = "vibes""#);
        rejects("manifest_version = 1", "manifest_version = 1\nextra = true");
        rejects(
            r#"claim_retention = "12mo""#,
            r#"claim_retention = "300000000000000d""#,
        );
    }

    #[test]
    fn disclosed_metadata_must_list_every_mandatory_field_and_nothing_unknown() {
        let line = DEMO
            .lines()
            .find(|l| l.starts_with("disclosed_metadata = "))
            .unwrap();
        for to in [
            "disclosed_metadata = []",
            r#"disclosed_metadata = ["log_checkpoint"]"#,
            &line.replace(r#""trust_level", "#, ""),
            &line.replace(r#""time", "#, r#""time", "home_address", "#),
        ] {
            assert_ne!(to, line);
            let toml = DEMO.replace(line, to);
            assert!(Manifest::parse(toml.as_bytes()).is_err(), "accepted {to}");
        }
    }

    #[test]
    fn witness_policy_parses_and_rejects_inconsistent_witnesses() {
        let log = Manifest::parse(DEMO.as_bytes())
            .unwrap()
            .body()
            .log
            .clone()
            .unwrap();
        assert_eq!(log.witness_quorum, 1);
        assert_eq!(log.witnesses[0].name, "witness.example.org/demo");
        assert_eq!(log.checkpoint_max_age.to_string(), "1h");

        rejects("witness_quorum = 1", "witness_quorum = 2");
        rejects(
            r#"checkpoint_max_age = "1h""#,
            r#"checkpoint_max_age = "0h""#,
        );
        rejects(
            r#"name = "witness.example.org/demo""#,
            r#"name = "witness.example.org/other""#,
        );
        rejects("+BDnDJtIcX1p95tKTK", "+BDnDJtIcX1p95tKTX");
        rejects("witness_quorum = 1", "witness_quorum = 1\nextra = true");
        let twice = DEMO.replace(
            "witnesses = [{",
            r#"witnesses = [{ name = "witness.example.org/demo", key = "witness.example.org/demo+10c00e9a+BDnDJtIcX1p95tKTK+ggaN1dSvTB9a0EYGVntufeUB5t" }, {"#,
        );
        assert!(Manifest::parse(twice.as_bytes()).is_err());
    }

    fn with_log(log: &str) -> Result<Manifest, Error> {
        let toml = format!("{}[log]\n{log}", &DEMO[..DEMO.find("[log]").unwrap()]);
        Manifest::parse(toml.as_bytes())
    }

    fn witnesses(quorum: usize, count: u8) -> String {
        let list: Vec<String> = (1..=count)
            .map(|i| {
                let name = format!("witness.example.org/w{i}");
                let signer = ed25519_dalek::SigningKey::from_bytes(&[i; 32]);
                let key = WitnessKey::new(&name, signer.verifying_key());
                format!(r#"{{ name = "{name}", key = "{}" }}"#, key.vkey())
            })
            .collect();
        format!(
            "witnesses = [{}]\nwitness_quorum = {quorum}\ncheckpoint_max_age = \"1h\"\n",
            list.join(", ")
        )
    }

    #[test]
    fn any_two_accepted_witness_quorums_share_a_witness() {
        for (quorum, count) in [(1, 1), (2, 2), (2, 3), (3, 4), (3, 5)] {
            with_log(&witnesses(quorum, count))
                .unwrap_or_else(|e| panic!("{quorum} of {count}: {e}"));
        }
        for (quorum, count) in [(1, 2), (2, 4), (0, 1), (1, 3), (2, 5)] {
            let err = with_log(&witnesses(quorum, count))
                .err()
                .unwrap_or_else(|| panic!("accepted {quorum} of {count}"));
            assert!(err.to_string().contains("more than half"), "{err}");
        }
    }

    #[test]
    fn running_without_witnesses_needs_an_explicit_allow_split_views() {
        let err = with_log(&witnesses(0, 0)).expect_err("0 of 0 without the flag");
        assert!(err.to_string().contains("allow_split_views"), "{err}");
        let without = &DEMO[..DEMO.find("[log]").unwrap()];
        let err = Manifest::parse(without.as_bytes()).expect_err("no [log] section");
        assert!(err.to_string().contains("allow_split_views"), "{err}");

        let open = with_log(&format!("allow_split_views = true\n{}", witnesses(0, 0))).unwrap();
        assert!(open.body().log.as_ref().unwrap().allow_split_views);

        let err = with_log(&format!("allow_split_views = true\n{}", witnesses(1, 1)))
            .expect_err("the flag with witnesses listed");
        assert!(err.to_string().contains("allow_split_views"), "{err}");
    }

    #[test]
    fn month_spans_compare_by_their_possible_range() {
        let span = |s: &str| Span::try_from(s.to_string()).unwrap();
        assert!(span("28d").certainly_shorter_or_equal(&span("1mo")));
        assert!(!span("30d").certainly_shorter_or_equal(&span("1mo")));
        assert!(!span("1mo").certainly_shorter_or_equal(&span("30d")));
        assert!(span("1mo").certainly_shorter_or_equal(&span("31d")));
        assert!(span("12mo").certainly_shorter_or_equal(&span("12mo")));
        assert!(span("24h").certainly_shorter_or_equal(&span("1d")));
    }

    #[test]
    fn before_counts_calendar_months_and_exact_hours() {
        let t: chrono::DateTime<chrono::Utc> = "2026-03-31T10:00:00Z".parse().unwrap();
        let span = |s: &str| Span::try_from(s.to_string()).unwrap();
        assert_eq!(
            span("12mo").before(t).unwrap().to_rfc3339(),
            "2025-03-31T10:00:00+00:00"
        );
        assert_eq!(
            span("1mo").before(t).unwrap().to_rfc3339(),
            "2026-02-28T10:00:00+00:00"
        );
        assert_eq!(
            span("1h").before(t).unwrap().to_rfc3339(),
            "2026-03-31T09:00:00+00:00"
        );
        assert_eq!(
            span("2w").before(t).unwrap().to_rfc3339(),
            "2026-03-17T10:00:00+00:00"
        );
        assert_eq!(span("300000000mo").before(t), None);
        assert_eq!(
            span("1mo").after(t).unwrap().to_rfc3339(),
            "2026-04-30T10:00:00+00:00"
        );
        assert_eq!(
            span("1h").after(t).unwrap().to_rfc3339(),
            "2026-03-31T11:00:00+00:00"
        );
        assert_eq!(span("300000000mo").after(t), None);
    }
}
