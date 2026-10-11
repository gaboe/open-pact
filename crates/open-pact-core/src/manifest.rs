use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::{Error, ManifestHash};

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
        let amount = digits
            .parse()
            .map_err(|_| format!("duration {s:?} must start with a number"))?;
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
    pub disclosed_metadata: BTreeSet<String>,
    pub data_controller: String,
    pub min_trust_level: TrustLevel,
    pub unknown_grace: Span,
    #[serde(rename = "control")]
    pub controls: Vec<Control>,
}

impl ManifestBody {
    pub fn control(&self, id: &str) -> Option<&Control> {
        self.controls.iter().find(|c| c.id == id)
    }

    fn validate(&self) -> Result<(), String> {
        if self.unknown_grace.is_zero() {
            return Err("unknown_grace must not be zero".into());
        }
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
}
