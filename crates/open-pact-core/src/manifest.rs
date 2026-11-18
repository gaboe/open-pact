use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use time::{Date, Duration, OffsetDateTime};

use crate::{Error, ManifestHash, WitnessKey, timestamp};

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

    pub fn min_duration(&self) -> Option<Duration> {
        timestamp::seconds(i64::try_from(self.min_secs()).ok()?)
    }

    /// The instant this span before `t`, in calendar months for `mo`, so `12mo` before
    /// 2026-10-15 is 2025-10-15. `None` when that is before the start of the calendar.
    pub fn before(&self, t: OffsetDateTime) -> Option<OffsetDateTime> {
        match self.unit {
            Unit::Month => timestamp::add_months(t, -i64::from(u32::try_from(self.amount).ok()?)),
            _ => t.checked_sub(self.min_duration()?),
        }
    }

    /// The instant this span after `t`, in calendar months for `mo`. `None` past the calendar.
    pub fn after(&self, t: OffsetDateTime) -> Option<OffsetDateTime> {
        match self.unit {
            Unit::Month => timestamp::add_months(t, i64::from(u32::try_from(self.amount).ok()?)),
            _ => t.checked_add(self.min_duration()?),
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RemotePattern(String);

impl RemotePattern {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RemotePattern {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let invalid = || format!("remote pattern {value:?} must be a host/path-prefix/ pattern");
        if value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
            || value.contains(['*', '?', '@', ':'])
            || !value.ends_with('/')
        {
            return Err(invalid());
        }

        let mut segments: Vec<&str> = value[..value.len() - 1].split('/').collect();
        if segments.len() < 2 || segments.iter().any(|segment| segment.is_empty()) {
            return Err(invalid());
        }

        let valid_host = |host: &str| {
            host.len() <= 253
                && host.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label.as_bytes()[0].is_ascii_alphanumeric()
                        && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
        };
        if !valid_host(segments[0]) {
            return Err(invalid());
        }

        let host = segments[0].to_ascii_lowercase();
        let last = segments.len() - 1;
        let path_end = segments[last]
            .strip_suffix(".git")
            .unwrap_or(segments[last]);
        if path_end.is_empty() || path_end.ends_with(".git") {
            return Err(invalid());
        }
        segments[last] = path_end;

        Ok(Self(format!("{host}/{}/", segments[1..].join("/"))))
    }
}

impl From<RemotePattern> for String {
    fn from(pattern: RemotePattern) -> Self {
        pattern.0
    }
}

impl fmt::Display for RemotePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
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
#[serde(untagged)]
pub enum ControlValue {
    Text(String),
    Integer(i32),
    Null,
}

impl From<&str> for ControlValue {
    fn from(value: &str) -> Self {
        Self::Text(value.into())
    }
}
impl From<String> for ControlValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}
impl From<i32> for ControlValue {
    fn from(value: i32) -> Self {
        Self::Integer(value)
    }
}
impl PartialEq<str> for ControlValue {
    fn eq(&self, other: &str) -> bool {
        matches!(self, Self::Text(text) if text == other)
    }
}
impl PartialEq<&str> for ControlValue {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}
impl fmt::Display for ControlValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => f.write_str(text),
            Self::Integer(n) => n.fmt(f),
            Self::Null => f.write_str("null"),
        }
    }
}

// Serde struct visitors also accept positional sequences. Numeric policy fields must
// name the operation and bounds, so untagged variants require a map before decoding.
fn named_fields<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Named<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Named<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map with named numeric fields")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Named(std::marker::PhantomData))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Output {
    Enumerated(Vec<String>),
    Timestamp(#[serde(deserialize_with = "named_fields")] TimestampOutput),
    Integer(#[serde(deserialize_with = "named_fields")] IntegerOutput),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimestampOutput {
    pub timestamp: bool,
    #[serde(default)]
    pub nullable: bool,
    #[serde(default)]
    pub values: Vec<String>,
}

fn utc_timestamp(text: &str) -> bool {
    text.ends_with('Z') && timestamp::is_rfc3339(text)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegerOutput {
    #[serde(deserialize_with = "named_fields")]
    pub integer: IntegerRange,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegerRange {
    pub min: i32,
    pub max: i32,
}

impl Output {
    pub fn contains(&self, value: &ControlValue) -> bool {
        match (self, value) {
            (Self::Timestamp(domain), ControlValue::Text(text)) => {
                text == "unknown" || domain.values.contains(text) || utc_timestamp(text)
            }
            (Self::Timestamp(domain), ControlValue::Null) => domain.nullable,
            (Self::Enumerated(values), ControlValue::Text(text)) => values.contains(text),
            (Self::Integer(bounds), ControlValue::Integer(n)) => {
                (bounds.integer.min..=bounds.integer.max).contains(n)
            }
            (Self::Integer(bounds), ControlValue::Text(text)) => {
                text == "unknown" || bounds.values.contains(text)
            }
            _ => false,
        }
    }
    pub fn is_subset_of(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Enumerated(values), Self::Enumerated(old)) => {
                values.iter().all(|v| old.contains(v))
            }
            (Self::Timestamp(now), Self::Timestamp(old)) => {
                (!now.nullable || old.nullable) && now.values.iter().all(|v| old.values.contains(v))
            }
            (Self::Integer(now), Self::Integer(old)) => {
                now.integer.min >= old.integer.min
                    && now.integer.max <= old.integer.max
                    && now.values.iter().all(|v| old.values.contains(v))
            }
            _ => false,
        }
    }
    fn validate(&self) -> bool {
        match self {
            Self::Timestamp(domain) => {
                domain.timestamp
                    && domain.values.iter().all(|v| v == "n/a")
                    && domain.values.iter().collect::<BTreeSet<_>>().len() == domain.values.len()
            }
            Self::Enumerated(values) => {
                !values.is_empty() && values.iter().collect::<BTreeSet<_>>().len() == values.len()
            }
            Self::Integer(bounds) => {
                bounds.integer.min <= bounds.integer.max
                    && bounds
                        .values
                        .iter()
                        .all(|v| matches!(v.as_str(), "n/a" | "none"))
                    && bounds.values.iter().collect::<BTreeSet<_>>().len() == bounds.values.len()
            }
        }
    }
}
impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timestamp(domain) => write!(
                f,
                "RFC 3339 UTC, unknown{}{}",
                if domain.nullable { ", null" } else { "" },
                if domain.values.is_empty() {
                    String::new()
                } else {
                    format!(", {}", domain.values.join(", "))
                }
            ),
            Self::Enumerated(values) => f.write_str(&values.join(", ")),
            Self::Integer(bounds) => write!(
                f,
                "integer {}..={}, unknown{}",
                bounds.integer.min,
                bounds.integer.max,
                if bounds.values.is_empty() {
                    String::new()
                } else {
                    format!(", {}", bounds.values.join(", "))
                }
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Accepted {
    Values(AcceptedValues),
    Max(#[serde(deserialize_with = "named_fields")] Maximum),
    Min(#[serde(deserialize_with = "named_fields")] Minimum),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Maximum {
    pub max: i32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Minimum {
    pub min: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "OneOrMany")]
pub struct AcceptedValues(pub BTreeSet<String>);

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}
impl From<OneOrMany> for AcceptedValues {
    fn from(v: OneOrMany) -> Self {
        Self(match v {
            OneOrMany::One(s) => BTreeSet::from([s]),
            OneOrMany::Many(v) => v.into_iter().collect(),
        })
    }
}
impl Accepted {
    pub fn contains(&self, value: &ControlValue) -> bool {
        match (self, value) {
            (Self::Values(values), ControlValue::Null) => values.0.contains("null"),
            (Self::Values(values), ControlValue::Text(text)) => values.0.contains(text),
            (Self::Max(limit), ControlValue::Integer(n)) => *n <= limit.max,
            (Self::Min(limit), ControlValue::Integer(n)) => *n >= limit.min,
            _ => false,
        }
    }
    pub fn is_superset_of(&self, old: &Self) -> bool {
        match (self, old) {
            (Self::Values(now), Self::Values(old)) => now.0.is_superset(&old.0),
            (Self::Max(now), Self::Max(old)) => now.max >= old.max,
            (Self::Min(now), Self::Min(old)) => now.min <= old.min,
            _ => false,
        }
    }
    fn valid_for(&self, output: &Output) -> bool {
        match (self, output) {
            (Self::Values(values), Output::Enumerated(outputs)) => {
                !values.0.is_empty() && values.0.iter().all(|v| outputs.contains(v))
            }
            (Self::Values(values), Output::Timestamp(domain)) => {
                !values.0.is_empty()
                    && values.0.iter().all(|v| {
                        domain.values.contains(v)
                            || utc_timestamp(v)
                            || (v == "null" && domain.nullable)
                    })
            }
            (Self::Values(values), Output::Integer(bounds)) => {
                !values.0.is_empty() && values.0.iter().all(|v| bounds.values.contains(v))
            }
            (Self::Max(limit), Output::Integer(bounds)) => {
                (bounds.integer.min..=bounds.integer.max).contains(&limit.max)
            }
            (Self::Min(limit), Output::Integer(bounds)) => {
                (bounds.integer.min..=bounds.integer.max).contains(&limit.min)
            }
            _ => false,
        }
    }
}
impl fmt::Display for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Values(values) => {
                let values: Vec<&str> = values.0.iter().map(String::as_str).collect();
                match values.as_slice() {
                    [one] => f.write_str(one),
                    many => write!(f, "one of {}", many.join(", ")),
                }
            }
            Self::Max(limit) => write!(f, "<= {}", limit.max),
            Self::Min(limit) => write!(f, ">= {}", limit.min),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub id: String,
    /// Ignored. Older manifests name who asked for the control, so the key still parses and a
    /// round trip keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// What the control protects, in words for the owner. Older manifests call it `rationale`.
    #[serde(default, alias = "rationale")]
    pub description: Option<String>,
    /// Where the rule comes from, such as a contract clause. Older manifests call it
    /// `source_ref`.
    #[serde(default, alias = "source_ref")]
    pub reference: Option<String>,
    pub check: String,
    pub output: Output,
    pub required: BTreeMap<Os, Accepted>,
    pub grace: Span,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remotes: Vec<RemotePattern>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestBody {
    pub manifest_version: u32,
    pub issuer: String,
    #[serde(with = "crate::timestamp::serde_date")]
    pub valid_from: Date,
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
    /// When the client sends claims by itself. Without it the owner sends claims by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Schedule>,
}

/// When and where the scheduled job checks and sends. It always names at least one place: the
/// type has no empty schedule, and `Schedule::new` returns `None` for one.
///
/// Two TOML forms parse into it. The flat form of 0.7 (`mode`, `vpn_probe`,
/// `vpn_probe_name`, `interval`) keeps its 0.7 meaning and its consent line. The place form
/// has the sub-tables `[schedule.vpn]` and `[schedule.always]`. A table cannot hold both forms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSchedule", into = "RawSchedule")]
pub struct Schedule {
    kind: Kind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    /// The flat 0.7 form. Without a probe it is `mode = "always"`.
    Legacy {
        probe: Option<Probe>,
        interval: Interval,
    },
    Vpn(VpnSlot),
    Always(Interval),
    Both {
        vpn: VpnSlot,
        always: Interval,
    },
}

/// The `[schedule.vpn]` table: what the job does while the probe answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnSlot {
    pub probe: Probe,
    /// How often the job runs the local checks on the VPN.
    pub check: CheckPeriod,
    /// The longest time between two claims on the VPN.
    pub interval: Interval,
}

impl VpnSlot {
    /// A slot that checks every `CheckPeriod::DEFAULT`.
    pub fn new(probe: Probe, interval: Interval) -> Self {
        Self {
            probe,
            check: CheckPeriod::DEFAULT,
            interval,
        }
    }
}

/// The address that answers only on the company VPN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub address: ProbeAddress,
    /// With a name, the probe also needs a TLS certificate that is valid for it.
    pub name: Option<ProbeName>,
}

/// Where the device is, as one wake observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The probe answered.
    Vpn,
    /// The probe did not answer, or the schedule has no probe.
    Elsewhere,
}

/// What a detected VPN connection does. The form of the signed text decides it, because the owner
/// agreed to that text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnConnect {
    /// `[schedule.vpn]`: a claim at once.
    Send,
    /// The flat form with `mode = "vpn"`: the connect claim waits for the interval.
    WaitForInterval,
}

impl Schedule {
    /// A schedule from its places, or `None` when it has none.
    pub fn new(vpn: Option<VpnSlot>, always: Option<Interval>) -> Option<Self> {
        let kind = match (vpn, always) {
            (Some(vpn), Some(always)) => Kind::Both { vpn, always },
            (Some(vpn), None) => Kind::Vpn(vpn),
            (None, Some(always)) => Kind::Always(always),
            (None, None) => return None,
        };
        Some(Self { kind })
    }

    /// The flat 0.7 form with `mode = "vpn"`.
    pub fn legacy_vpn(probe: Probe, interval: Interval) -> Self {
        Self {
            kind: Kind::Legacy {
                probe: Some(probe),
                interval,
            },
        }
    }

    /// The flat 0.7 form with `mode = "always"`.
    pub fn legacy_always(interval: Interval) -> Self {
        Self {
            kind: Kind::Legacy {
                probe: None,
                interval,
            },
        }
    }

    /// Whether the table is the flat 0.7 form. It keeps its 0.7 consent line, its connect rule
    /// (`OnConnect::WaitForInterval`), and a check period of `CheckPeriod::DEFAULT`.
    pub fn is_legacy(&self) -> bool {
        matches!(self.kind, Kind::Legacy { .. })
    }

    /// The probe each wake runs, or `None` when the schedule has no VPN part.
    pub fn probe(&self) -> Option<&Probe> {
        match &self.kind {
            Kind::Legacy { probe, .. } => probe.as_ref(),
            Kind::Vpn(vpn) | Kind::Both { vpn, .. } => Some(&vpn.probe),
            Kind::Always(_) => None,
        }
    }

    /// How often the job checks on the VPN. `None` without a VPN part.
    pub fn vpn_check_period(&self) -> Option<CheckPeriod> {
        match &self.kind {
            Kind::Legacy { probe, .. } => probe.as_ref().map(|_| CheckPeriod::DEFAULT),
            Kind::Vpn(vpn) | Kind::Both { vpn, .. } => Some(vpn.check),
            Kind::Always(_) => None,
        }
    }

    /// The send interval of the VPN part. `None` without a VPN part.
    pub fn vpn_interval(&self) -> Option<Interval> {
        match &self.kind {
            Kind::Legacy {
                probe: Some(_),
                interval,
            } => Some(*interval),
            Kind::Legacy { probe: None, .. } | Kind::Always(_) => None,
            Kind::Vpn(vpn) | Kind::Both { vpn, .. } => Some(vpn.interval),
        }
    }

    /// The send interval of the part for any network. `None` without one.
    pub fn always_interval(&self) -> Option<Interval> {
        match &self.kind {
            Kind::Legacy {
                probe: None,
                interval,
            } => Some(*interval),
            Kind::Legacy { probe: Some(_), .. } | Kind::Vpn(_) => None,
            Kind::Always(always) | Kind::Both { always, .. } => Some(*always),
        }
    }

    /// The longest gap between two periodic claims at this place, or `None` when no claim
    /// may go there. The part for any network also applies on the VPN, so the shorter of the two
    /// wins there.
    pub fn period(&self, place: Place) -> Option<Interval> {
        match place {
            Place::Vpn => match (self.vpn_interval(), self.always_interval()) {
                (Some(vpn), Some(always)) => Some(vpn.min(always)),
                (vpn, always) => vpn.or(always),
            },
            Place::Elsewhere => self.always_interval(),
        }
    }

    /// How often the job runs its local checks at this place, or `None` when it checks nothing
    /// there. The VPN part sets the rate on the VPN. The part for any network checks every 5
    /// minutes wherever it applies: on the VPN when no VPN part sets the rate, and elsewhere.
    pub fn check_period(&self, place: Place) -> Option<CheckPeriod> {
        let any_network = self.always_interval().is_some();
        match place {
            Place::Vpn => self
                .vpn_check_period()
                .or(any_network.then_some(CheckPeriod::DEFAULT)),
            Place::Elsewhere => any_network.then_some(CheckPeriod::DEFAULT),
        }
    }

    /// Whether a claim may go at this place at all: periodic, on a change, or on connect.
    pub fn may_send(&self, place: Place) -> bool {
        self.period(place).is_some()
    }

    /// What a detected VPN connection does. `None` without a VPN part.
    pub fn on_connect(&self) -> Option<OnConnect> {
        match &self.kind {
            Kind::Legacy { probe, .. } => probe.as_ref().map(|_| OnConnect::WaitForInterval),
            Kind::Vpn(_) | Kind::Both { .. } => Some(OnConnect::Send),
            Kind::Always(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawMode {
    Vpn,
    Always,
}

/// Both TOML forms in one table, so that one parse step names the rule that a table breaks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSchedule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<RawMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vpn_probe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vpn_probe_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vpn: Option<RawVpn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    always: Option<RawAlways>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVpn {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    probe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    probe_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    check: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interval: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAlways {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interval: Option<String>,
}

const FLAT_KEYS: &str =
    "schedule.mode, schedule.vpn_probe, schedule.vpn_probe_name and schedule.interval";

fn required<T>(value: Option<T>, key: &str, hint: &str) -> Result<T, String> {
    value.ok_or_else(|| {
        let field = key.rsplit('.').next().unwrap_or(key);
        format!("{key}: missing field `{field}`, {hint}")
    })
}

impl RawVpn {
    fn into_slot(self) -> Result<VpnSlot, String> {
        let probe = ProbeAddress::parse(
            required(
                self.probe,
                "schedule.vpn.probe",
                "set it to a host:port that answers only on the company VPN",
            )?,
            "schedule.vpn.probe",
        )?;
        let name = self
            .probe_name
            .map(|name| ProbeName::parse(name, "schedule.vpn.probe_name"))
            .transpose()?;
        let check = self
            .check
            .map(|check| CheckPeriod::parse(&check, "schedule.vpn.check"))
            .transpose()?
            .unwrap_or(CheckPeriod::DEFAULT);
        let interval = Interval::parse(
            &required(
                self.interval,
                "schedule.vpn.interval",
                "set it to how often a claim goes on the VPN, such as \"1h\"",
            )?,
            "schedule.vpn.interval",
        )?;
        Ok(VpnSlot {
            probe: Probe {
                address: probe,
                name,
            },
            check,
            interval,
        })
    }
}

impl RawAlways {
    fn into_interval(self) -> Result<Interval, String> {
        Interval::parse(
            &required(
                self.interval,
                "schedule.always.interval",
                "set it to how often a claim goes on any network, such as \"24h\"",
            )?,
            "schedule.always.interval",
        )
    }
}

fn flat_schedule(raw: RawSchedule) -> Result<Schedule, String> {
    let mode = required(
        raw.mode,
        "schedule.mode",
        "set it to \"vpn\" or \"always\", or use [schedule.vpn] and [schedule.always]",
    )?;
    let interval = Interval::parse(
        &required(
            raw.interval,
            "schedule.interval",
            "set it to whole minutes or hours from 5m to 24h, such as \"55m\"",
        )?,
        "schedule.interval",
    )?;
    let probe = raw
        .vpn_probe
        .map(|probe| ProbeAddress::parse(probe, "schedule.vpn_probe"))
        .transpose()?;
    let name = raw
        .vpn_probe_name
        .map(|name| ProbeName::parse(name, "schedule.vpn_probe_name"))
        .transpose()?;
    match (mode, probe, name) {
        (RawMode::Vpn, Some(address), name) => Ok(Schedule::legacy_vpn(
            Probe { address, name },
            interval,
        )),
        (RawMode::Vpn, None, _) => Err(
            "schedule.vpn_probe is required with mode = \"vpn\": set it to a host:port that answers only on the company VPN"
                .into(),
        ),
        (RawMode::Always, None, None) => Ok(Schedule::legacy_always(interval)),
        (RawMode::Always, _, _) => Err(
            "schedule.mode = \"always\" sends on any network, so it takes no vpn_probe or vpn_probe_name"
                .into(),
        ),
    }
}

impl TryFrom<RawSchedule> for Schedule {
    type Error = String;

    fn try_from(raw: RawSchedule) -> Result<Self, String> {
        let flat = raw.mode.is_some()
            || raw.vpn_probe.is_some()
            || raw.vpn_probe_name.is_some()
            || raw.interval.is_some();
        match (flat, &raw.vpn, &raw.always) {
            (true, None, None) => flat_schedule(raw),
            (true, vpn, _) => {
                let table = if vpn.is_some() {
                    "schedule.vpn"
                } else {
                    "schedule.always"
                };
                Err(format!(
                    "{table} cannot be used with {FLAT_KEYS}: use the flat keys, or the tables [schedule.vpn] and [schedule.always], not both"
                ))
            }
            (false, None, None) => Err(
                "schedule.vpn and schedule.always are both missing: define [schedule.vpn], [schedule.always], or both"
                    .into(),
            ),
            (false, _, _) => {
                let vpn = raw.vpn.map(RawVpn::into_slot).transpose()?;
                let always = raw.always.map(RawAlways::into_interval).transpose()?;
                Schedule::new(vpn, always).ok_or_else(|| {
                    "schedule.vpn and schedule.always are both missing: define [schedule.vpn], [schedule.always], or both"
                        .to_owned()
                })
            }
        }
    }
}

impl From<VpnSlot> for RawVpn {
    fn from(slot: VpnSlot) -> Self {
        Self {
            probe: Some(slot.probe.address.into()),
            probe_name: slot.probe.name.map(Into::into),
            check: Some(slot.check.into()),
            interval: Some(slot.interval.into()),
        }
    }
}

impl From<Schedule> for RawSchedule {
    fn from(schedule: Schedule) -> Self {
        match schedule.kind {
            Kind::Legacy { probe, interval } => {
                let (mode, vpn_probe, vpn_probe_name) = match probe {
                    Some(Probe { address, name }) => {
                        (RawMode::Vpn, Some(address.into()), name.map(Into::into))
                    }
                    None => (RawMode::Always, None, None),
                };
                Self {
                    mode: Some(mode),
                    vpn_probe,
                    vpn_probe_name,
                    interval: Some(interval.into()),
                    ..Self::default()
                }
            }
            Kind::Vpn(vpn) => Self {
                vpn: Some(vpn.into()),
                ..Self::default()
            },
            Kind::Always(always) => Self {
                always: Some(RawAlways {
                    interval: Some(always.into()),
                }),
                ..Self::default()
            },
            Kind::Both { vpn, always } => Self {
                vpn: Some(vpn.into()),
                always: Some(RawAlways {
                    interval: Some(always.into()),
                }),
                ..Self::default()
            },
        }
    }
}

/// "minute", "5 minutes", "hour", "2 hours": the words after "every" in the consent line.
fn every(minutes: u32) -> String {
    match (minutes, minutes.is_multiple_of(60)) {
        (1, _) => "minute".into(),
        (60, _) => "hour".into(),
        (_, true) => format!("{} hours", minutes / 60),
        _ => format!("{minutes} minutes"),
    }
}

fn vpn_clause(vpn: &VpnSlot) -> String {
    let probe = match &vpn.probe.name {
        Some(name) => format!("{name} at {}", vpn.probe.address),
        None => vpn.probe.address.to_string(),
    };
    format!(
        "on the company VPN ({probe}) checks every {}, sends at once on connect or when a result gets worse, and at least every {}",
        every(vpn.check.minutes),
        every(vpn.interval.minutes),
    )
}

fn always_clause(always: Interval) -> String {
    format!(
        "on any network every {}, and at once when a result gets worse",
        every(always.minutes)
    )
}

impl fmt::Display for Schedule {
    /// The line the owner reads before agreeing to automatic claims. The flat form keeps its 0.7
    /// text exactly. The place form has one clause for each part.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Kind::Legacy {
                probe:
                    Some(Probe {
                        address,
                        name: Some(name),
                    }),
                interval,
            } => write!(
                f,
                "Automatic claims: only while {name} answers at {address}, every {interval}, and at once when a check result changes",
            ),
            Kind::Legacy {
                probe:
                    Some(Probe {
                        address,
                        name: None,
                    }),
                interval,
            } => write!(
                f,
                "Automatic claims: only while {address} answers, every {interval}, and at once when a check result changes",
            ),
            Kind::Legacy {
                probe: None,
                interval,
            } => write!(
                f,
                "Automatic claims: every {interval} on any network, and at once when a check result changes",
            ),
            Kind::Vpn(vpn) => write!(f, "Automatic claims: {}.", vpn_clause(vpn)),
            Kind::Always(always) => write!(f, "Automatic claims: {}.", always_clause(*always)),
            Kind::Both { vpn, always } => write!(
                f,
                "Automatic claims: {}; {}.",
                vpn_clause(vpn),
                always_clause(*always)
            ),
        }
    }
}

/// Reads whole minutes or hours: "90m", "2h". Not "+5m", "05m", "5", or "5.5h".
fn whole_minutes(text: &str) -> Option<u32> {
    let (digits, hours) = match (text.strip_suffix('m'), text.strip_suffix('h')) {
        (Some(digits), _) => (digits, false),
        (_, Some(digits)) => (digits, true),
        _ => return None,
    };
    if digits.is_empty()
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let amount: u32 = digits.parse().ok()?;
    if hours {
        amount.checked_mul(60)
    } else {
        Some(amount)
    }
}

const MAX_MINUTES: u32 = 24 * 60;

/// The time between periodic claims: whole minutes or hours, from 5 minutes to 24 hours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Interval {
    minutes: u32,
}

impl Interval {
    const MIN_MINUTES: u32 = 5;

    pub fn as_secs(&self) -> i64 {
        i64::from(self.minutes) * 60
    }

    /// Reads a manifest spelling such as "55m". `key` is the manifest key the error names.
    fn parse(text: &str, key: &str) -> Result<Self, String> {
        whole_minutes(text)
            .filter(|minutes| (Self::MIN_MINUTES..=MAX_MINUTES).contains(minutes))
            .map(|minutes| Self { minutes })
            .ok_or_else(|| {
                format!(
                    "{key} {text:?} must be whole minutes or hours from 5m to 24h, such as \"55m\""
                )
            })
    }
}

impl TryFrom<String> for Interval {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        Self::parse(&text, "schedule.interval")
    }
}

impl fmt::Display for Interval {
    /// Plain words for the owner: "55 minutes", "1 hour", "90 minutes".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.minutes.is_multiple_of(60) {
            let hours = self.minutes / 60;
            write!(f, "{hours} hour{}", if hours == 1 { "" } else { "s" })
        } else {
            write!(f, "{} minutes", self.minutes)
        }
    }
}

impl From<Interval> for String {
    /// The manifest spelling, such as `55m` or `2h`.
    fn from(interval: Interval) -> String {
        minutes_text(interval.minutes)
    }
}

fn minutes_text(minutes: u32) -> String {
    if minutes.is_multiple_of(60) {
        format!("{}h", minutes / 60)
    } else {
        format!("{minutes}m")
    }
}

/// How often the job runs the local checks on the VPN: whole minutes or hours, from 1 minute to
/// 24 hours. A check is local work. It sends nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CheckPeriod {
    minutes: u32,
}

impl CheckPeriod {
    /// The period of a `[schedule.vpn]` without `check`: the rate of 0.7.
    pub const DEFAULT: CheckPeriod = CheckPeriod { minutes: 5 };
    const MIN_MINUTES: u32 = 1;

    pub fn as_secs(&self) -> i64 {
        i64::from(self.minutes) * 60
    }

    fn parse(text: &str, key: &str) -> Result<Self, String> {
        whole_minutes(text)
            .filter(|minutes| (Self::MIN_MINUTES..=MAX_MINUTES).contains(minutes))
            .map(|minutes| Self { minutes })
            .ok_or_else(|| {
                format!(
                    "{key} {text:?} must be whole minutes or hours from 1m to 24h, such as \"5m\""
                )
            })
    }
}

impl Default for CheckPeriod {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TryFrom<String> for CheckPeriod {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        Self::parse(&text, "schedule.vpn.check")
    }
}

impl fmt::Display for CheckPeriod {
    /// Plain words for the owner: "1 minute", "5 minutes", "1 hour".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.minutes.is_multiple_of(60) {
            let hours = self.minutes / 60;
            write!(f, "{hours} hour{}", if hours == 1 { "" } else { "s" })
        } else {
            write!(
                f,
                "{} minute{}",
                self.minutes,
                if self.minutes == 1 { "" } else { "s" }
            )
        }
    }
}

impl From<CheckPeriod> for String {
    /// The manifest spelling, such as `1m` or `2h`.
    fn from(period: CheckPeriod) -> String {
        minutes_text(period.minutes)
    }
}

fn dns_name_ok(raw: &str) -> bool {
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    let last = raw.rsplit('.').next().unwrap_or_default();
    // An all-digit last label makes an IP address, which a DNS name cannot be here.
    let numeric_last = !last.is_empty() && last.bytes().all(|byte| byte.is_ascii_digit());
    raw.len() <= 253 && raw.split('.').all(label_ok) && !numeric_last
}

/// A `host:port`, checked once. The host is a DNS name, an IPv4 address or a bracketed IPv6
/// address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProbeAddress(String);

impl ProbeAddress {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ProbeAddress {
    /// `key` is the manifest key the error names.
    fn parse(raw: String, key: &str) -> Result<Self, String> {
        let bad =
            || format!("{key} must be host:port, with brackets around IPv6 addresses: {raw:?}");
        let (host, port) = raw.rsplit_once(':').ok_or_else(bad)?;
        let port_ok = !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port != 0);
        let host_ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(inner) => inner.parse::<std::net::Ipv6Addr>().is_ok(),
            None => host.parse::<std::net::Ipv4Addr>().is_ok() || dns_name_ok(host),
        };
        if !port_ok || !host_ok {
            return Err(bad());
        }
        Ok(Self(raw))
    }
}

impl TryFrom<String> for ProbeAddress {
    type Error = String;

    fn try_from(raw: String) -> Result<Self, String> {
        Self::parse(raw, "schedule.vpn_probe")
    }
}

impl From<ProbeAddress> for String {
    fn from(address: ProbeAddress) -> String {
        address.0
    }
}

impl fmt::Display for ProbeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The DNS name that the probe's TLS certificate must carry, checked once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProbeName(String);

impl ProbeName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ProbeName {
    /// `key` is the manifest key the error names.
    fn parse(raw: String, key: &str) -> Result<Self, String> {
        if !dns_name_ok(&raw) {
            return Err(format!(
                "{key} must be a DNS name such as \"vpn.example.org\", not an IP address, a value with spaces, or a trailing dot: {raw:?}"
            ));
        }
        Ok(Self(raw))
    }
}

impl TryFrom<String> for ProbeName {
    type Error = String;

    fn try_from(raw: String) -> Result<Self, String> {
        Self::parse(raw, "schedule.vpn_probe_name")
    }
}

impl From<ProbeName> for String {
    fn from(name: ProbeName) -> String {
        name.0
    }
}

impl fmt::Display for ProbeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
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
            let accepts_remotes = matches!(
                c.check.as_str(),
                "builtin:managed_repos_outside@1" | "builtin:managed_repos_total@1"
            );
            if accepts_remotes && c.remotes.is_empty() {
                return Err(format!("{}: remotes must list at least one pattern", c.id));
            }
            if !accepts_remotes && !c.remotes.is_empty() {
                return Err(format!(
                    "{}: remotes are only valid for managed repository checks",
                    c.id
                ));
            }
            if !c.output.validate() {
                return Err(format!(
                    "{}: output must be a non-empty unique enumeration, an ordered integer range, or a UTC timestamp domain",
                    c.id
                ));
            }
            for (os, accepted) in &c.required {
                if !accepted.valid_for(&c.output) {
                    return Err(format!(
                        "{}: required.{os} must match the output kind and stay within output",
                        c.id
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The manifest key a validation message opens with. Every message names its key first: a top-level
/// field, a `log.` or `schedule.` path, or `<control id>: <reason>` for a control.
pub(crate) fn key_named_by(message: &str) -> Option<String> {
    let key_char = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_';
    let word_end = message
        .find(|c: char| !key_char(c) && c != '.')
        .unwrap_or(message.len());
    let word = message[..word_end].trim_end_matches('.');
    let rest = &message[word_end..];
    if matches!(word, "disclosed_metadata" | "unknown_grace")
        || (word.starts_with("log.") || word.starts_with("schedule."))
            && word.split('.').all(|part| !part.is_empty())
    {
        return Some(word.to_string());
    }
    let reason = rest.strip_prefix(": ")?;
    if word.is_empty() || word.contains('.') {
        return None;
    }
    let field = ["check", "remotes", "output"]
        .into_iter()
        .find(|field| reason.starts_with(&format!("{field} ")));
    let field = match (field, reason.strip_prefix("required.")) {
        (Some(field), _) => format!(".{field}"),
        (None, Some(after)) => {
            let os = after
                .split(|c: char| !key_char(c))
                .next()
                .unwrap_or_default();
            if os.is_empty() {
                String::new()
            } else {
                format!(".required.{os}")
            }
        }
        (None, None) => String::new(),
    };
    Some(format!("controls.{word}{field}"))
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
    use crate::timestamp::ToRfc3339;

    const DEMO: &str = include_str!("../../../examples/manifest.toml");

    #[test]
    fn demo_manifest_parses() {
        let m = Manifest::parse(DEMO.as_bytes()).unwrap();
        let disk = m.body().control("disk_encryption").unwrap();
        assert_eq!(
            disk.required[&Os::Macos],
            Accepted::Values(AcceptedValues(BTreeSet::from(["full".to_string()])))
        );
        assert!(disk.grace.is_zero());
        assert_eq!(m.body().min_trust_level, TrustLevel::L0);
    }

    #[test]
    fn manifest_rejects_report_as_an_unknown_field() {
        let text =
            format!("{DEMO}\n[report]\ncollector = \"https://collector.example.org/status\"\n");
        let error = Manifest::parse(text.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("unknown field `report`"),
            "{error}"
        );
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
        assert!(lock.required[&Os::Macos].contains(&"le_15min".into()));
        assert!(!lock.required.contains_key(&Os::Linux));
    }

    fn rejects(from: &str, to: &str) {
        assert!(DEMO.contains(from), "fixture lacks {from}");
        let toml = DEMO.replacen(from, to, 1);
        assert!(Manifest::parse(toml.as_bytes()).is_err(), "accepted {to}");
    }

    #[test]
    fn a_manifest_error_names_its_key() {
        let key = |from: &str, to: &str| {
            let toml = DEMO.replacen(from, to, 1);
            assert_ne!(toml, DEMO, "fixture lacks {from}");
            Manifest::parse(toml.as_bytes()).unwrap_err().manifest_key()
        };
        assert_eq!(
            key("witness_quorum = 1", "witness_quorum = 2").as_deref(),
            Some("log.witness_quorum")
        );
        assert_eq!(
            key(
                r#"check = "builtin:firewall@1""#,
                r#"check = "shell:ufw status""#
            )
            .as_deref(),
            Some("controls.firewall.check")
        );
        assert_eq!(key(r#"id = "firewall""#, r#"id = "disk_encryption""#), None);
        assert_eq!(
            key(r#"unknown_grace = "7d""#, r#"unknown_grace = "0d""#).as_deref(),
            Some("unknown_grace")
        );
        assert_eq!(
            key("manifest_version = 1", "manifest_version = 1\nextra = true"),
            None
        );
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
        let t: OffsetDateTime = timestamp::parse_rfc3339("2026-03-31T10:00:00Z").unwrap();
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

    fn with_schedule(table: &str) -> String {
        let start = DEMO.find("\n[schedule]").unwrap();
        format!("{}\n{table}\n", &DEMO[..start])
    }

    #[test]
    fn schedule_parses_vpn_and_always() {
        let vpn = Manifest::parse(DEMO.as_bytes()).unwrap();
        let schedule = vpn.body().schedule.clone().unwrap();
        assert!(schedule.is_legacy());
        assert_eq!(schedule.vpn_interval().unwrap().as_secs(), 55 * 60);
        assert_eq!(schedule.always_interval(), None);
        let probe = schedule.probe().unwrap();
        assert_eq!(probe.address.as_str(), "10.0.0.1:443");
        assert_eq!(probe.name.as_ref().unwrap().as_str(), "vpn.example.org");
        assert_eq!(
            schedule.to_string(),
            "Automatic claims: only while vpn.example.org answers at 10.0.0.1:443, every 55 minutes, and at once when a check result changes"
        );
        let always = Manifest::parse(
            with_schedule("[schedule]\nmode = \"always\"\ninterval = \"1h\"").as_bytes(),
        )
        .unwrap();
        let schedule = always.body().schedule.clone().unwrap();
        assert!(schedule.is_legacy());
        assert_eq!(schedule.probe(), None);
        assert_eq!(schedule.always_interval().unwrap().as_secs(), 60 * 60);
        assert_eq!(schedule.vpn_interval(), None);
        assert_eq!(
            schedule.to_string(),
            "Automatic claims: every 1 hour on any network, and at once when a check result changes"
        );
        let unnamed = with_schedule(
            "[schedule]\nmode = \"vpn\"\nvpn_probe = \"[::1]:443\"\ninterval = \"5m\"",
        );
        let manifest = Manifest::parse(unnamed.as_bytes()).unwrap();
        assert_eq!(
            manifest.body().schedule.as_ref().unwrap().to_string(),
            "Automatic claims: only while [::1]:443 answers, every 5 minutes, and at once when a check result changes"
        );
    }

    #[test]
    fn a_manifest_without_a_schedule_has_none() {
        let start = DEMO.find("\n[schedule]").unwrap();
        let manifest = Manifest::parse(&DEMO.as_bytes()[..start]).unwrap();
        assert!(manifest.body().schedule.is_none());
    }

    #[test]
    fn schedule_rejects_bad_tables() {
        let cases = [
            (
                "mode = \"vpn\"\ninterval = \"55m\"",
                "vpn_probe is required",
            ),
            (
                "mode = \"always\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"55m\"",
                "takes no vpn_probe",
            ),
            (
                "mode = \"always\"\nvpn_probe_name = \"vpn.example.org\"\ninterval = \"55m\"",
                "takes no vpn_probe",
            ),
            (
                "mode = \"sometimes\"\ninterval = \"55m\"",
                "unknown variant `sometimes`",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"",
                "missing field `interval`",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"4m\"",
                "schedule.interval",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"25h\"",
                "schedule.interval",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"55\"",
                "schedule.interval",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"5é\"",
                "schedule.interval",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"+55m\"",
                "schedule.interval",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"055m\"",
                "schedule.interval",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"m\"",
                "schedule.interval",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"\"",
                "schedule.interval",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1\"\ninterval = \"55m\"",
                "schedule.vpn_probe must be host:port",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\nvpn_probe_name = \"10.0.0.1\"\ninterval = \"55m\"",
                "schedule.vpn_probe_name",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\nvpn_probe_name = \"vpn.example.org.\"\ninterval = \"55m\"",
                "schedule.vpn_probe_name",
            ),
            (
                "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\nextra = 1\ninterval = \"55m\"",
                "unknown field `extra`",
            ),
        ];
        for (table, expected) in cases {
            let text = with_schedule(&format!("[schedule]\n{table}"));
            let error = Manifest::parse(text.as_bytes()).unwrap_err().to_string();
            assert!(error.contains(expected), "{table}: {error}");
        }
    }

    #[test]
    fn intervals_print_in_plain_words_and_keep_the_manifest_spelling() {
        for (text, printed) in [
            ("5m", "5 minutes"),
            ("55m", "55 minutes"),
            ("60m", "1 hour"),
            ("90m", "90 minutes"),
            ("1h", "1 hour"),
            ("2h", "2 hours"),
            ("24h", "24 hours"),
        ] {
            let interval = Interval::try_from(text.to_string()).unwrap();
            assert_eq!(interval.to_string(), printed, "{text}");
            let written = String::from(interval);
            assert_eq!(Interval::try_from(written).unwrap(), interval, "{text}");
        }
        assert_eq!(
            String::from(Interval::try_from("2h".to_string()).unwrap()),
            "2h"
        );
        assert_eq!(
            String::from(Interval::try_from("90m".to_string()).unwrap()),
            "90m"
        );
    }

    #[test]
    fn probe_requires_host_and_port() {
        for address in ["vpn.example.org:443", "127.0.0.1:1234", "[::1]:443"] {
            assert!(
                ProbeAddress::try_from(address.to_string()).is_ok(),
                "{address}"
            );
        }
        for address in [
            "vpn.example.org",
            "example.org:443/path",
            "user@example.org:443",
            "example.org:443?x",
            "example.org:443#x",
            "bad host:443",
            "example.org:0",
            "example.org:70000",
            "::1:443",
            "300.0.0.1:443",
        ] {
            assert!(
                ProbeAddress::try_from(address.to_string()).is_err(),
                "{address}"
            );
        }
    }

    #[test]
    fn the_schedule_is_part_of_the_manifest_hash() {
        let changed = DEMO.replace("interval = \"55m\"", "interval = \"30m\"");
        assert_ne!(
            Manifest::parse(DEMO.as_bytes()).unwrap().hash(),
            Manifest::parse(changed.as_bytes()).unwrap().hash()
        );
    }

    fn schedule_of(table: &str) -> Schedule {
        let text = with_schedule(&format!("[schedule]\n{table}"));
        Manifest::parse(text.as_bytes())
            .unwrap_or_else(|error| panic!("{table}: {error}"))
            .body()
            .schedule
            .clone()
            .unwrap()
    }

    fn schedule_error(table: &str) -> String {
        let text = with_schedule(table);
        Manifest::parse(text.as_bytes())
            .expect_err(table)
            .to_string()
    }

    const VPN_TABLE: &str = "[schedule.vpn]\nprobe = \"10.0.0.1:443\"\nprobe_name = \"vpn.example.org\"\ninterval = \"1h\"\n";

    #[test]
    fn the_place_form_parses_a_vpn_table_with_a_default_check_period() {
        let schedule = schedule_of(
            "vpn.probe = \"10.0.0.1:443\"\nvpn.probe_name = \"vpn.example.org\"\nvpn.interval = \"1h\"",
        );
        assert!(!schedule.is_legacy());
        let probe = schedule.probe().unwrap();
        assert_eq!(probe.address.as_str(), "10.0.0.1:443");
        assert_eq!(probe.name.as_ref().unwrap().as_str(), "vpn.example.org");
        assert_eq!(schedule.vpn_check_period(), Some(CheckPeriod::DEFAULT));
        assert_eq!(schedule.vpn_check_period().unwrap().as_secs(), 300);
        assert_eq!(schedule.vpn_interval().unwrap().as_secs(), 3600);
        assert_eq!(schedule.always_interval(), None);
        assert_eq!(schedule.on_connect(), Some(OnConnect::Send));
        assert!(schedule.may_send(Place::Vpn));
        assert!(!schedule.may_send(Place::Elsewhere));
        assert_eq!(schedule.period(Place::Elsewhere), None);
    }

    #[test]
    fn the_place_form_parses_each_part_alone_and_both_together() {
        let vpn_only =
            schedule_of("vpn.probe = \"10.0.0.1:443\"\nvpn.check = \"1m\"\nvpn.interval = \"30m\"");
        assert_eq!(vpn_only.vpn_check_period().unwrap().as_secs(), 60);

        let always = schedule_of("always.interval = \"24h\"");
        assert_eq!(always.probe(), None);
        assert_eq!(always.vpn_check_period(), None);
        assert_eq!(always.vpn_interval(), None);
        assert_eq!(always.always_interval().unwrap().as_secs(), 24 * 3600);
        assert_eq!(always.on_connect(), None);
        assert!(always.may_send(Place::Elsewhere));
        assert!(always.may_send(Place::Vpn), "any network includes the VPN");

        let both = schedule_of(
            "vpn.probe = \"10.0.0.1:443\"\nvpn.interval = \"1h\"\nalways.interval = \"24h\"",
        );
        assert_eq!(both.vpn_interval().unwrap().as_secs(), 3600);
        assert_eq!(both.always_interval().unwrap().as_secs(), 24 * 3600);
        assert_eq!(both.period(Place::Vpn).unwrap().as_secs(), 3600);
        assert_eq!(both.period(Place::Elsewhere).unwrap().as_secs(), 24 * 3600);
    }

    #[test]
    fn the_shorter_interval_wins_on_the_vpn_when_the_other_part_is_shorter() {
        let both = schedule_of(
            "vpn.probe = \"10.0.0.1:443\"\nvpn.interval = \"24h\"\nalways.interval = \"1h\"",
        );
        assert_eq!(both.period(Place::Vpn).unwrap().as_secs(), 3600);
        assert_eq!(both.period(Place::Elsewhere).unwrap().as_secs(), 3600);
    }

    #[test]
    fn check_periods_run_from_one_minute_to_a_day_in_whole_minutes_or_hours() {
        for (text, secs) in [("1m", 60), ("5m", 300), ("90m", 5400), ("24h", 86_400)] {
            let schedule = schedule_of(&format!(
                "vpn.probe = \"10.0.0.1:443\"\nvpn.check = \"{text}\"\nvpn.interval = \"1h\""
            ));
            assert_eq!(
                schedule.vpn_check_period().unwrap().as_secs(),
                secs,
                "{text}"
            );
        }
        for text in [
            "0m", "25h", "1441m", "1", "01m", "+1m", "1.5h", "", "m", "1d",
        ] {
            let error = schedule_error(&format!(
                "[schedule.vpn]\nprobe = \"10.0.0.1:443\"\ncheck = {text:?}\ninterval = \"1h\"\n"
            ));
            assert!(
                error.contains("schedule.vpn.check") && error.contains("from 1m to 24h"),
                "{text}: {error}"
            );
        }
    }

    #[test]
    fn place_intervals_keep_the_five_minute_floor_and_name_their_key() {
        for (table, key) in [
            (
                "[schedule.vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"4m\"\n",
                "schedule.vpn.interval",
            ),
            (
                "[schedule.vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"25h\"\n",
                "schedule.vpn.interval",
            ),
            (
                "[schedule.always]\ninterval = \"4m\"\n",
                "schedule.always.interval",
            ),
            (
                "[schedule.always]\ninterval = \"55\"\n",
                "schedule.always.interval",
            ),
            (
                "[schedule.always]\ninterval = \"025m\"\n",
                "schedule.always.interval",
            ),
        ] {
            let error = schedule_error(table);
            assert!(
                error.contains(key) && error.contains("from 5m to 24h"),
                "{table}: {error}"
            );
        }
    }

    #[test]
    fn the_place_form_rejects_missing_and_malformed_keys() {
        for (table, expected) in [
            (
                "[schedule.vpn]\ninterval = \"1h\"\n",
                "schedule.vpn.probe: missing field",
            ),
            (
                "[schedule.vpn]\nprobe = \"10.0.0.1:443\"\n",
                "schedule.vpn.interval: missing field",
            ),
            (
                "[schedule.always]\n",
                "schedule.always.interval: missing field",
            ),
            (
                "[schedule.vpn]\nprobe = \"10.0.0.1\"\ninterval = \"1h\"\n",
                "schedule.vpn.probe must be host:port",
            ),
            (
                "[schedule.vpn]\nprobe = \"10.0.0.1:443\"\nprobe_name = \"10.0.0.1\"\ninterval = \"1h\"\n",
                "schedule.vpn.probe_name must be a DNS name",
            ),
            (
                "[schedule.vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"1h\"\nextra = 1\n",
                "unknown field `extra`",
            ),
            (
                "[schedule.always]\ninterval = \"1h\"\ncheck = \"1m\"\n",
                "unknown field `check`",
            ),
            (
                "[schedule.sometimes]\ninterval = \"1h\"\n",
                "unknown field `sometimes`",
            ),
        ] {
            let error = schedule_error(table);
            assert!(error.contains(expected), "{table}: {error}");
        }
    }

    #[test]
    fn a_schedule_needs_at_least_one_place() {
        let error = schedule_error("[schedule]\n");
        assert!(
            error.contains("define [schedule.vpn], [schedule.always], or both"),
            "{error}"
        );
        assert!(Schedule::new(None, None).is_none());
    }

    #[test]
    fn the_flat_and_place_forms_cannot_mix() {
        for table in [
            "[schedule]\nmode = \"always\"\ninterval = \"1h\"\n[schedule.always]\ninterval = \"1h\"\n",
            "[schedule]\ninterval = \"1h\"\n[schedule.vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"1h\"\n",
            "[schedule]\nvpn_probe = \"10.0.0.1:443\"\n[schedule.always]\ninterval = \"1h\"\n",
        ] {
            let error = schedule_error(table);
            assert!(
                error.contains("cannot be used with schedule.mode") && error.contains("not both"),
                "{table}: {error}"
            );
        }
        let error = schedule_error(
            "[schedule]\nmode = \"always\"\ninterval = \"1h\"\n[schedule.vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"1h\"\n",
        );
        assert!(
            error.starts_with("invalid manifest: schedule.vpn cannot")
                || error.contains("schedule.vpn cannot"),
            "{error}"
        );
    }

    #[test]
    fn a_flat_table_without_mode_or_interval_names_the_missing_key() {
        for (table, expected) in [
            ("interval = \"1h\"", "schedule.mode: missing field"),
            (
                "vpn_probe = \"10.0.0.1:443\"\ninterval = \"1h\"",
                "schedule.mode: missing field",
            ),
            ("mode = \"always\"", "schedule.interval: missing field"),
        ] {
            let text = with_schedule(&format!("[schedule]\n{table}"));
            let error = Manifest::parse(text.as_bytes()).unwrap_err().to_string();
            assert!(error.contains(expected), "{table}: {error}");
        }
    }

    #[test]
    fn schedule_errors_name_their_key_for_the_editor() {
        let key = |table: &str| {
            let text = with_schedule(table);
            Manifest::parse(text.as_bytes()).unwrap_err().manifest_key()
        };
        assert_eq!(
            key("[schedule.vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"4m\"\n").as_deref(),
            Some("schedule.vpn.interval")
        );
        assert_eq!(
            key("[schedule.always]\ninterval = \"4m\"\n").as_deref(),
            Some("schedule.always.interval")
        );
        assert_eq!(
            key("[schedule.vpn]\nprobe = \"10.0.0.1:443\"\ncheck = \"0m\"\ninterval = \"1h\"\n")
                .as_deref(),
            Some("schedule.vpn.check")
        );
        assert_eq!(
            key("[schedule]\nmode = \"vpn\"\ninterval = \"1h\"\n").as_deref(),
            Some("schedule.vpn_probe")
        );
        assert_eq!(key("[schedule]\n").as_deref(), Some("schedule.vpn"));
    }

    #[test]
    fn the_flat_form_keeps_its_zero_seven_meaning() {
        let vpn = schedule_of("mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"55m\"");
        assert!(vpn.is_legacy());
        assert_eq!(vpn.on_connect(), Some(OnConnect::WaitForInterval));
        assert_eq!(vpn.vpn_check_period(), Some(CheckPeriod::DEFAULT));
        assert_eq!(vpn.period(Place::Vpn).unwrap().as_secs(), 55 * 60);
        assert_eq!(vpn.period(Place::Elsewhere), None);
        assert!(!vpn.may_send(Place::Elsewhere));

        let always = schedule_of("mode = \"always\"\ninterval = \"55m\"");
        assert!(always.is_legacy());
        assert_eq!(always.on_connect(), None);
        assert_eq!(always.vpn_check_period(), None);
        assert_eq!(always.period(Place::Elsewhere).unwrap().as_secs(), 55 * 60);
    }

    #[test]
    fn every_schedule_round_trips_through_its_own_form() {
        for table in [
            "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\nvpn_probe_name = \"vpn.example.org\"\ninterval = \"55m\"",
            "mode = \"vpn\"\nvpn_probe = \"[::1]:443\"\ninterval = \"5m\"",
            "mode = \"always\"\ninterval = \"2h\"",
            "vpn.probe = \"10.0.0.1:443\"\nvpn.interval = \"1h\"",
            "vpn.probe = \"10.0.0.1:443\"\nvpn.probe_name = \"vpn.example.org\"\nvpn.check = \"1m\"\nvpn.interval = \"90m\"",
            "always.interval = \"24h\"",
            "vpn.probe = \"10.0.0.1:443\"\nvpn.check = \"10m\"\nvpn.interval = \"1h\"\nalways.interval = \"24h\"",
        ] {
            let schedule = schedule_of(table);
            let json = serde_json::to_value(&schedule).unwrap();
            assert_eq!(
                serde_json::from_value::<Schedule>(json.clone()).unwrap(),
                schedule,
                "{table}: {json}"
            );
            let written = toml::to_string(&schedule).unwrap();
            assert_eq!(
                toml::from_str::<Schedule>(&written).unwrap(),
                schedule,
                "{table}: {written}"
            );
        }
        let flat =
            serde_json::to_value(schedule_of("mode = \"always\"\ninterval = \"2h\"")).unwrap();
        assert_eq!(
            flat,
            serde_json::json!({"mode": "always", "interval": "2h"})
        );
        let places = serde_json::to_value(schedule_of(
            "vpn.probe = \"10.0.0.1:443\"\nvpn.interval = \"1h\"\nalways.interval = \"24h\"",
        ))
        .unwrap();
        assert_eq!(
            places,
            serde_json::json!({
                "vpn": {"probe": "10.0.0.1:443", "check": "5m", "interval": "1h"},
                "always": {"interval": "24h"},
            })
        );
    }

    #[test]
    fn consent_lines_have_one_clause_for_each_part() {
        let both = schedule_of(
            "vpn.probe = \"10.0.0.1:443\"\nvpn.probe_name = \"vpn.example.org\"\nvpn.interval = \"1h\"\nalways.interval = \"24h\"",
        );
        assert_eq!(
            both.to_string(),
            "Automatic claims: on the company VPN (vpn.example.org at 10.0.0.1:443) checks every 5 minutes, sends at once on connect or when a result gets worse, and at least every hour; on any network every 24 hours, and at once when a result gets worse."
        );
        let vpn =
            schedule_of("vpn.probe = \"10.0.0.1:443\"\nvpn.check = \"1m\"\nvpn.interval = \"90m\"");
        assert_eq!(
            vpn.to_string(),
            "Automatic claims: on the company VPN (10.0.0.1:443) checks every minute, sends at once on connect or when a result gets worse, and at least every 90 minutes."
        );
        let hourly =
            schedule_of("vpn.probe = \"10.0.0.1:443\"\nvpn.check = \"2h\"\nvpn.interval = \"2h\"");
        assert!(hourly.to_string().contains("checks every 2 hours"));
        let always = schedule_of("always.interval = \"6h\"");
        assert_eq!(
            always.to_string(),
            "Automatic claims: on any network every 6 hours, and at once when a result gets worse."
        );
    }

    #[test]
    fn check_periods_print_in_plain_words_and_keep_the_manifest_spelling() {
        for (text, printed) in [
            ("1m", "1 minute"),
            ("5m", "5 minutes"),
            ("60m", "1 hour"),
            ("90m", "90 minutes"),
            ("2h", "2 hours"),
        ] {
            let period = CheckPeriod::try_from(text.to_string()).unwrap();
            assert_eq!(period.to_string(), printed, "{text}");
            assert_eq!(CheckPeriod::try_from(String::from(period)).unwrap(), period);
        }
        assert_eq!(String::from(CheckPeriod::DEFAULT), "5m");
        assert_eq!(CheckPeriod::default(), CheckPeriod::DEFAULT);
    }

    #[test]
    fn the_place_form_is_part_of_the_manifest_hash() {
        let first = with_schedule(VPN_TABLE);
        let second = first.replace("interval = \"1h\"", "interval = \"2h\"");
        assert_ne!(
            Manifest::parse(first.as_bytes()).unwrap().hash(),
            Manifest::parse(second.as_bytes()).unwrap().hash()
        );
    }

    #[test]
    fn manifests_written_before_the_place_form_keep_their_hash() {
        let paper = include_str!("../../../PAPER.md");
        let appendix = &paper[paper.find("## Appendix A").unwrap()..];
        let start = appendix.find("```toml\n").unwrap() + "```toml\n".len();
        let appendix = &appendix[start..start + appendix[start..].find("```").unwrap()];
        for text in [DEMO, appendix] {
            let manifest = Manifest::parse(text.as_bytes()).unwrap();
            assert_eq!(manifest.hash(), &ManifestHash::of(text.as_bytes()));
        }
    }

    #[test]
    fn controls_take_a_description_and_a_reference_and_ignore_the_source() {
        let new_style = DEMO
            .replacen(
                "source = \"customer_contract\"\nsource_ref = \"Client contract, security annex, 4.2\"\nrationale = \"A lost laptop must not expose client data.\"\n",
                "description = \"A lost laptop must not expose client data.\"\nreference = \"Client contract, security annex, 4.2\"\n",
                1,
            );
        assert_ne!(new_style, DEMO);
        let old = Manifest::parse(DEMO.as_bytes()).unwrap();
        let new = Manifest::parse(new_style.as_bytes()).unwrap();
        for manifest in [&old, &new] {
            let control = manifest.body().control("disk_encryption").unwrap();
            assert_eq!(
                control.description.as_deref(),
                Some("A lost laptop must not expose client data.")
            );
            assert_eq!(
                control.reference.as_deref(),
                Some("Client contract, security annex, 4.2")
            );
        }
        assert!(
            old.body()
                .control("disk_encryption")
                .unwrap()
                .source
                .is_some()
        );
        assert!(
            new.body()
                .control("disk_encryption")
                .unwrap()
                .source
                .is_none()
        );
        assert_ne!(old.hash(), new.hash());

        let bare = new.body().control("firewall").unwrap();
        assert_eq!(
            (bare.description.as_ref(), bare.reference.as_ref()),
            (None, None)
        );
    }

    #[test]
    fn controls_serialize_the_new_names_and_no_source() {
        let manifest = Manifest::parse(DEMO.as_bytes()).unwrap();
        let control = manifest.body().control("disk_encryption").unwrap();
        let json = serde_json::to_value(control).unwrap();
        assert_eq!(
            json["description"],
            "A lost laptop must not expose client data."
        );
        assert_eq!(json["reference"], "Client contract, security annex, 4.2");
        assert!(json.get("rationale").is_none());
        assert!(json.get("source_ref").is_none());
        assert_eq!(json["source"], "customer_contract");
        let back: Control = serde_json::from_value(json).unwrap();
        assert_eq!(&back, control);
        let bare = serde_json::to_value(manifest.body().control("firewall").unwrap()).unwrap();
        assert_eq!(bare["source"], "company_policy");
        let without_source = DEMO.replace("source = \"company_policy\"\n", "");
        let manifest = Manifest::parse(without_source.as_bytes()).unwrap();
        let control = manifest.body().control("firewall").unwrap();
        assert!(
            serde_json::to_value(control)
                .unwrap()
                .get("source")
                .is_none()
        );
    }

    #[test]
    fn a_control_cannot_name_a_field_twice_under_its_old_and_new_name() {
        let text = DEMO.replacen(
            "rationale = \"A lost laptop must not expose client data.\"",
            "rationale = \"A lost laptop must not expose client data.\"\ndescription = \"Again.\"",
            1,
        );
        assert!(Manifest::parse(text.as_bytes()).is_err());
    }

    #[test]
    fn an_invalid_source_is_still_rejected_when_present() {
        rejects(r#"source = "company_policy""#, r#"source = "vibes""#);
    }

    mod timestamp_pins {
        use super::*;

        fn at(s: &str) -> OffsetDateTime {
            timestamp::parse_rfc3339(s).unwrap()
        }

        fn span(s: &str) -> Span {
            Span::try_from(s.to_string()).unwrap()
        }

        fn with_valid_from(value: &str) -> Result<Manifest, Error> {
            let text = DEMO.replace(
                "valid_from = \"2026-10-01\"",
                &format!("valid_from = {value}"),
            );
            Manifest::parse(text.as_bytes())
        }

        #[test]
        fn calendar_months_clamp_to_the_last_day_of_the_month() {
            let leap = at("2024-02-29T10:00:00Z");
            assert_eq!(
                span("12mo").before(leap).unwrap().to_rfc3339(),
                "2023-02-28T10:00:00+00:00"
            );
            assert_eq!(
                span("12mo").after(leap).unwrap().to_rfc3339(),
                "2025-02-28T10:00:00+00:00"
            );
            assert_eq!(
                span("1mo")
                    .after(at("2026-01-31T23:59:59.5Z"))
                    .unwrap()
                    .to_rfc3339(),
                "2026-02-28T23:59:59.500+00:00"
            );
            assert_eq!(
                span("1mo")
                    .before(at("2026-03-31T10:00:00.25Z"))
                    .unwrap()
                    .to_rfc3339(),
                "2026-02-28T10:00:00.250+00:00"
            );
            assert_eq!(
                span("3mo")
                    .before(at("2026-05-31T00:00:00Z"))
                    .unwrap()
                    .to_rfc3339(),
                "2026-02-28T00:00:00+00:00"
            );
            assert_eq!(
                span("0mo").after(leap).unwrap().to_rfc3339(),
                "2024-02-29T10:00:00+00:00"
            );
        }

        #[test]
        fn fixed_spans_keep_fractions_and_stop_past_the_chrono_range() {
            let t = at("2026-03-31T10:00:00.5Z");
            assert_eq!(
                span("36h").after(t).unwrap().to_rfc3339(),
                "2026-04-01T22:00:00.500+00:00"
            );
            assert_eq!(
                span("2w").before(t).unwrap().to_rfc3339(),
                "2026-03-17T10:00:00.500+00:00"
            );
            assert!(span("100000000000d").min_duration().is_some());
            assert_eq!(span("200000000000d").min_duration(), None);
            assert!(span("200000000000d").after(t).is_none());
        }

        #[test]
        fn rfc3339_timestamp_check_accepts_the_spellings_chrono_reads() {
            for (text, expected) in [
                ("2026-10-12T09:00:00Z", true),
                ("2026-10-12T09:00:00.5Z", true),
                ("2026-10-12T09:00:00.123456789Z", true),
                ("2026-10-12T09:00:00+00:00", false),
                ("2026-10-12T09:00:00z", false),
                ("2026-10-12t09:00:00Z", true),
                ("2026-10-12 09:00:00Z", true),
                // chrono read a leap second, and the validity check still does.
                ("2026-10-12T23:59:60Z", true),
                ("2026-02-30T00:00:00Z", false),
                ("2026-10-12T09:00Z", false),
                ("unknown", false),
            ] {
                assert_eq!(utc_timestamp(text), expected, "{text}");
            }
        }

        #[test]
        fn valid_from_reads_iso_dates_and_writes_them_back() {
            let m = with_valid_from("\"2026-10-01\"").unwrap();
            assert_eq!(
                serde_json::to_value(m.body()).unwrap()["valid_from"],
                "2026-10-01"
            );
            // chrono's NaiveDate serde read white space around the numbers and the dashes.
            for text in [
                "2026-10-01 ",
                " 2026-10-01",
                "2026- 10- 01",
                "2026 -10 -01",
                "2026-10-01\t",
                "2026-10-1 ",
            ] {
                let m = with_valid_from(&format!("\"{text}\"")).expect(text);
                assert_eq!(
                    serde_json::to_value(m.body()).unwrap()["valid_from"],
                    "2026-10-01",
                    "{text:?}"
                );
            }
            for (value, accepted) in [
                ("\"2026-1-5\"", true),
                ("\"2026-10-01x\"", false),
                ("\"2026-02-30\"", false),
                ("\"2026-10-01T00:00:00Z\"", false),
                ("2026-10-01", false),
            ] {
                assert_eq!(with_valid_from(value).is_ok(), accepted, "{value}");
            }
        }
    }
}
