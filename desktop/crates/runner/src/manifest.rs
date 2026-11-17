//! The manifest as the Form view reads and edits it. Every edit parses the text with toml_edit,
//! changes one value and prints the document again, so comments and order stay as written.
use crate::admin::CheckError;
use crate::text::humanize;
use crate::{Runner, args};
use chrono::{Datelike, NaiveDate};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, TableLike, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    Minute,
    Hour,
    Day,
    Week,
    Month,
}

impl Unit {
    pub const SPANS: [Unit; 4] = [Unit::Hour, Unit::Day, Unit::Week, Unit::Month];
    pub const INTERVALS: [Unit; 2] = [Unit::Minute, Unit::Hour];

    pub fn code(self) -> &'static str {
        match self {
            Self::Minute => "m",
            Self::Hour => "h",
            Self::Day => "d",
            Self::Week => "w",
            Self::Month => "mo",
        }
    }

    pub fn name(self, amount: u64) -> &'static str {
        match (self, amount == 1) {
            (Self::Minute, true) => "minute",
            (Self::Minute, false) => "minutes",
            (Self::Hour, true) => "hour",
            (Self::Hour, false) => "hours",
            (Self::Day, true) => "day",
            (Self::Day, false) => "days",
            (Self::Week, true) => "week",
            (Self::Week, false) => "weeks",
            (Self::Month, true) => "month",
            (Self::Month, false) => "months",
        }
    }

    fn short(self) -> &'static str {
        match self {
            Self::Minute => "min",
            other => other.code(),
        }
    }
}

/// A manifest duration such as "24h", "1mo", "7d" or "55m".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub amount: u64,
    pub unit: Unit,
}

impl Span {
    pub fn parse(text: &str) -> Option<Self> {
        let split = text.find(|c: char| !c.is_ascii_digit())?;
        let (digits, suffix) = text.split_at(split);
        let unit = match suffix {
            "m" => Unit::Minute,
            "h" => Unit::Hour,
            "d" => Unit::Day,
            "w" => Unit::Week,
            "mo" => Unit::Month,
            _ => return None,
        };
        Some(Self {
            amount: digits.parse().ok()?,
            unit,
        })
    }

    /// The manifest spelling.
    pub fn print(&self) -> String {
        format!("{}{}", self.amount, self.unit.code())
    }

    /// "24 hours", "1 month".
    pub fn words(&self) -> String {
        format!("{} {}", self.amount, self.unit.name(self.amount))
    }

    /// "1 d", as in the table.
    pub fn short(&self) -> String {
        format!("{} {}", self.amount, self.unit.short())
    }
}

pub fn parse_date(text: &str) -> Option<NaiveDate> {
    let text = text.trim();
    ["%Y-%m-%d", "%d %b %Y", "%d %B %Y"]
        .iter()
        .find_map(|format| NaiveDate::parse_from_str(text, format).ok())
}

/// "2026-10-01" reads as "1 Oct 2026". Text that is not a date stays as it is.
pub fn date_text(text: &str) -> String {
    match parse_date(text) {
        Some(date) => format!("{} {}", date.day(), date.format("%b %Y")),
        None => text.to_owned(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Os {
    Macos,
    Windows,
    Linux,
}

impl Os {
    pub const ALL: [Os; 3] = [Os::Macos, Os::Windows, Os::Linux];

    pub fn key(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Macos => "macOS",
            Self::Windows => "Windows",
            Self::Linux => "Linux",
        }
    }
}

pub const TRUST_LEVELS: [(&str, &str); 3] = [
    ("L0", "L0 software"),
    ("L1", "L1 hardware"),
    ("L2", "L2 attested"),
];

/// Every field a claim can carry besides the check values, with its plain name. The first nine
/// are mandatory: the core refuses a manifest that does not list them.
pub const METADATA: [(&str, &str); 11] = [
    ("manifest_hash", "Manifest hash"),
    ("device_pseudonym", "Device pseudonym"),
    ("device_key", "Device key"),
    ("nonce", "Nonce"),
    ("time", "Time"),
    ("client_version", "Client version"),
    ("os", "Operating system"),
    ("trust_level", "Trust level"),
    ("vpn_certificate_request", "VPN certificate request"),
    ("virtualized", "Runs in a virtual machine"),
    ("log_checkpoint", "Log checkpoint"),
];

pub fn metadata_mandatory(key: &str) -> bool {
    METADATA.iter().take(9).any(|(known, _)| *known == key)
}

/// The possible results of a check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    Choices(Vec<String>),
    Integer {
        min: i64,
        max: i64,
        values: Vec<String>,
    },
    Timestamp {
        nullable: bool,
        values: Vec<String>,
    },
    Unreadable,
}

impl Output {
    /// The values in the read-only list of the panel.
    pub fn values(&self) -> Vec<String> {
        match self {
            Self::Choices(values) => values.clone(),
            Self::Integer { min, max, values } => std::iter::once(format!("{min}..{max}"))
                .chain(values.iter().cloned())
                .chain(["unknown".to_owned()])
                .collect(),
            Self::Timestamp { nullable, values } => ["time".to_owned()]
                .into_iter()
                .chain(nullable.then(|| "null".to_owned()))
                .chain(values.iter().cloned())
                .chain(["unknown".to_owned()])
                .collect(),
            Self::Unreadable => Vec::new(),
        }
    }

    /// The results a requirement may name. A time check offers "null" when it can report that and
    /// its own sentinels, never the word "time" or "unknown", which the core refuses there.
    pub fn choices(&self) -> Vec<String> {
        match self {
            Self::Choices(values) | Self::Integer { values, .. } => values.clone(),
            Self::Timestamp { nullable, values } => nullable
                .then(|| "null".to_owned())
                .into_iter()
                .chain(values.iter().cloned())
                .collect(),
            Self::Unreadable => Vec::new(),
        }
    }

    /// The whole numbers a number requirement may use. The core takes 32-bit numbers, so an
    /// output the form cannot read falls back to that range.
    pub fn number_range(&self) -> Option<(i64, i64)> {
        match self {
            Self::Integer { min, max, .. } => Some((*min, *max)),
            Self::Unreadable => Some((i64::from(i32::MIN), i64::from(i32::MAX))),
            Self::Choices(_) | Self::Timestamp { .. } => None,
        }
    }
}

/// What a manifest asks of one OS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Requirement {
    Reported,
    Values(Vec<String>),
    Max(i64),
    Min(i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    pub id: String,
    /// What the owner writes about the check. Optional.
    pub description: String,
    /// A link or text that names where the check comes from. Optional.
    pub reference: String,
    pub check: String,
    pub output: Output,
    pub required: [Requirement; 3],
    pub grace: String,
}

impl Control {
    /// The entry of the version this check names. Name, group and limit kind come from the newest
    /// entry, but what the check reads and reports differs by version.
    pub fn builtin(&self) -> Option<&'static Builtin> {
        builtin_of_check(&self.check)
    }

    /// "screen_lock" from "builtin:screen_lock@1".
    pub fn builtin_id(&self) -> &str {
        self.check
            .strip_prefix("builtin:")
            .map(|rest| rest.split('@').next().unwrap_or(rest))
            .unwrap_or(&self.id)
    }

    pub fn name(&self) -> String {
        builtin(self.builtin_id()).map_or_else(|| self.id.clone(), |known| known.name.to_owned())
    }

    pub fn group(&self) -> Group {
        builtin(self.builtin_id()).map_or(Group::Other, |known| known.group)
    }

    pub fn is_required(&self) -> bool {
        self.required
            .iter()
            .any(|requirement| *requirement != Requirement::Reported)
    }

    pub fn requirement(&self, os: Os) -> &Requirement {
        &self.required[os as usize]
    }

    pub fn requirement_text(&self, os: Os) -> String {
        requirement_text(self, self.requirement(os))
    }

    /// "days", "characters" and so on, next to a number limit.
    pub fn limit_unit(&self) -> &'static str {
        match self.builtin_id() {
            id if id.ends_with("_days") => "days",
            "password_min_length" => "characters",
            "managed_repos_outside" | "managed_repos_total" => "repositories",
            "antimalware_active_threats" => "threats",
            "screen_lock" => "minutes",
            _ => "",
        }
    }

    /// Whether a number limit is a maximum, from the manifest first and from the check second.
    pub fn limit_is_max(&self) -> bool {
        for requirement in &self.required {
            match requirement {
                Requirement::Max(_) => return true,
                Requirement::Min(_) => return false,
                _ => (),
            }
        }
        builtin(self.builtin_id()).is_none_or(|known| known.max)
    }

    /// "≤" or "≥" for the number of one OS. An OS without a bound gets the control's default.
    pub fn limit_symbol(&self, os: Os) -> &'static str {
        let max = match self.requirement(os) {
            Requirement::Max(_) => true,
            Requirement::Min(_) => false,
            _ => self.limit_is_max(),
        };
        if max { "≤" } else { "≥" }
    }

    /// Whether some OS has a maximum and another a minimum, so no one direction fits them all.
    pub fn mixed_limits(&self) -> bool {
        let has = |wanted: fn(&Requirement) -> bool| self.required.iter().any(wanted);
        has(|r| matches!(r, Requirement::Max(_))) && has(|r| matches!(r, Requirement::Min(_)))
    }

    pub fn grace_text(&self) -> String {
        Span::parse(&self.grace).map_or_else(|| self.grace.clone(), |span| span.short())
    }

    /// A built-in check keeps its ID: every client runs a check only under the ID it was signed
    /// with.
    pub fn id_locked(&self) -> bool {
        self.check.starts_with("builtin:")
    }

    /// The number requirement for one OS. An OS that has a bound keeps its own operator; the
    /// control's default applies only to an OS that had no bound.
    pub fn limit(&self, os: Os, number: i64) -> Requirement {
        match self.requirement(os) {
            Requirement::Max(_) => Requirement::Max(number),
            Requirement::Min(_) => Requirement::Min(number),
            _ if self.limit_is_max() => Requirement::Max(number),
            _ => Requirement::Min(number),
        }
    }
}

/// How devices send. At least one part is on. With both parts off the manifest has no [schedule].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub vpn: Option<VpnSend>,
    pub always: Option<AlwaysSend>,
}

/// Sending on the company VPN: the probe that answers when the VPN is up, how often a device
/// checks it, and how often it sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VpnSend {
    pub probe: String,
    pub name: String,
    pub check: String,
    pub interval: String,
}

/// Sending on any network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlwaysSend {
    pub interval: String,
}

/// One part of the sending section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendPart {
    Vpn,
    Always,
}

impl SendPart {
    fn table(self) -> &'static str {
        match self {
            Self::Vpn => "vpn",
            Self::Always => "always",
        }
    }
}

/// The values of the parts that are off. The session keeps them, so that turning a part on
/// again restores what it had.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeptSends {
    pub vpn: Option<VpnSend>,
    pub always: Option<AlwaysSend>,
}

const CHECK_DEFAULT: &str = "5m";
const VPN_INTERVAL_DEFAULT: &str = "1h";
const ALWAYS_INTERVAL_DEFAULT: &str = "24h";

fn default_vpn() -> VpnSend {
    VpnSend {
        probe: String::new(),
        name: String::new(),
        check: CHECK_DEFAULT.to_owned(),
        interval: VPN_INTERVAL_DEFAULT.to_owned(),
    }
}

fn default_always() -> AlwaysSend {
    AlwaysSend {
        interval: ALWAYS_INTERVAL_DEFAULT.to_owned(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Form {
    pub issuer: String,
    pub valid_from: String,
    pub data_controller: String,
    pub recipients: Vec<String>,
    pub max_age: String,
    pub retention: String,
    pub unknown_grace: String,
    pub trust: String,
    pub metadata: Vec<String>,
    pub schedule: Option<Schedule>,
    pub controls: Vec<Control>,
}

fn text_of(item: Option<&Item>) -> String {
    item.and_then(Item::as_str).unwrap_or_default().to_owned()
}

fn strings_of(item: Option<&Item>) -> Vec<String> {
    item.and_then(Item::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn number_of(item: Option<&Item>) -> Option<i64> {
    item.and_then(Item::as_integer)
}

fn read_output(item: Option<&Item>) -> Output {
    let Some(item) = item else {
        return Output::Unreadable;
    };
    if item.is_array() {
        return Output::Choices(strings_of(Some(item)));
    }
    let Some(table) = item.as_table_like() else {
        return Output::Unreadable;
    };
    let values = strings_of(table.get("values"));
    if let Some(range) = table.get("integer").and_then(Item::as_table_like) {
        return Output::Integer {
            min: number_of(range.get("min")).unwrap_or(0),
            max: number_of(range.get("max")).unwrap_or(i64::from(i32::MAX)),
            values,
        };
    }
    if table.get("timestamp").is_some() {
        return Output::Timestamp {
            nullable: table
                .get("nullable")
                .and_then(Item::as_bool)
                .unwrap_or(false),
            values,
        };
    }
    Output::Unreadable
}

fn read_requirement(item: Option<&Item>) -> Requirement {
    let Some(item) = item else {
        return Requirement::Reported;
    };
    if let Some(text) = item.as_str() {
        return Requirement::Values(vec![text.to_owned()]);
    }
    if item.is_array() {
        return Requirement::Values(strings_of(Some(item)));
    }
    if let Some(table) = item.as_table_like() {
        if let Some(max) = number_of(table.get("max")) {
            return Requirement::Max(max);
        }
        if let Some(min) = number_of(table.get("min")) {
            return Requirement::Min(min);
        }
    }
    Requirement::Reported
}

/// The sending parts of a manifest. An older flat [schedule] with `mode` reads as the VPN part
/// when its mode is "vpn", and as the any-network part otherwise.
fn read_schedule(document: &DocumentMut) -> Option<Schedule> {
    let table = document.get("schedule").and_then(Item::as_table_like)?;
    if table.get("mode").is_some() {
        let interval = text_of(table.get("interval"));
        let vpn = (text_of(table.get("mode")) == "vpn").then(|| VpnSend {
            probe: text_of(table.get("vpn_probe")),
            name: text_of(table.get("vpn_probe_name")),
            check: CHECK_DEFAULT.to_owned(),
            interval: interval.clone(),
        });
        let always = vpn.is_none().then_some(AlwaysSend { interval });
        return Some(Schedule { vpn, always });
    }
    let vpn = table
        .get(SendPart::Vpn.table())
        .and_then(Item::as_table_like)
        .map(|part| VpnSend {
            probe: text_of(part.get("probe")),
            name: text_of(part.get("probe_name")),
            check: or_default(part.get("check"), CHECK_DEFAULT),
            interval: text_of(part.get("interval")),
        });
    let always = table
        .get(SendPart::Always.table())
        .and_then(Item::as_table_like)
        .map(|part| AlwaysSend {
            interval: text_of(part.get("interval")),
        });
    (vpn.is_some() || always.is_some()).then_some(Schedule { vpn, always })
}

fn or_default(item: Option<&Item>, default: &str) -> String {
    match text_of(item) {
        text if text.is_empty() => default.to_owned(),
        text => text,
    }
}

impl Form {
    pub fn parse(text: &str) -> Result<Self, String> {
        let document = text.parse::<DocumentMut>().map_err(|e| e.to_string())?;
        let get = |key: &str| document.get(key);
        let schedule = read_schedule(&document);
        let controls = get("control")
            .and_then(Item::as_array_of_tables)
            .map(|tables| {
                tables
                    .iter()
                    .map(|table| {
                        let required = table.get("required");
                        let per_os = |os: Os| {
                            read_requirement(
                                required
                                    .and_then(Item::as_table_like)
                                    .and_then(|t| t.get(os.key())),
                            )
                        };
                        Control {
                            id: text_of(table.get("id")),
                            description: text_of(
                                table.get("description").or_else(|| table.get("rationale")),
                            ),
                            reference: text_of(
                                table.get("reference").or_else(|| table.get("source_ref")),
                            ),
                            check: text_of(table.get("check")),
                            output: read_output(table.get("output")),
                            required: Os::ALL.map(per_os),
                            grace: text_of(table.get("grace")),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            issuer: text_of(get("issuer")),
            valid_from: text_of(get("valid_from")),
            data_controller: text_of(get("data_controller")),
            recipients: strings_of(get("claim_recipients")),
            max_age: text_of(get("claim_max_age")),
            retention: text_of(get("claim_retention")),
            unknown_grace: text_of(get("unknown_grace")),
            trust: text_of(get("min_trust_level")),
            metadata: strings_of(get("disclosed_metadata")),
            schedule,
            controls,
        })
    }

    pub fn control(&self, id: &str) -> Option<&Control> {
        self.controls.iter().find(|control| control.id == id)
    }
}

/// The short wording of one result value, as in the table. The long wording is the menu label.
pub fn value_label(check: &str, value: &str, long: bool) -> String {
    let word = match (check, value) {
        ("screen_lock", "le_5min") if long => "Locks within 5 min",
        ("screen_lock", "le_15min") if long => "Locks within 15 min",
        ("screen_lock", "gt_15min") if long => "Locks after more than 15 min",
        ("screen_lock", "le_5min") => "≤ 5 min",
        ("screen_lock", "le_15min") => "≤ 15 min",
        ("screen_lock", "gt_15min") => "> 15 min",
        ("screen_lock", "none") => "Never locks",
        ("preboot_auth", "user_secret") => "User secret",
        ("preboot_auth", "hardware_only") => "Hardware only",
        ("work_account", "admin") => "Administrator",
        ("work_account", "standard") => "Standard user",
        ("log_cleared", "null") => "Never cleared",
        (_, "on") => "On",
        (_, "off") => "Off",
        (_, "yes") => "Yes",
        (_, "no") => "No",
        (_, "full") => "Full",
        (_, "partial") => "Partial",
        (_, "none") => "None",
        (_, "unknown") => "Unknown",
        (_, "n/a") if long => "Not applicable",
        (_, "n/a") => "n/a",
        _ => return humanize(value),
    };
    word.to_owned()
}

fn limit_text(control: &Control, symbol: &str, number: i64) -> String {
    match control.limit_unit() {
        "days" => format!("{symbol} {number} days"),
        _ => format!("{symbol} {number}"),
    }
}

/// What the table shows for one OS.
pub fn requirement_text(control: &Control, requirement: &Requirement) -> String {
    match requirement {
        Requirement::Reported => "reported".into(),
        Requirement::Values(values) => values
            .iter()
            .map(|value| value_label(control.builtin_id(), value, false))
            .collect::<Vec<_>>()
            .join(" or "),
        Requirement::Max(number) => limit_text(control, "≤", *number),
        Requirement::Min(number) => limit_text(control, "≥", *number),
    }
}

/// Where a check sits under a heading in the checks table and in the add-check list. The order
/// of the variants is the order of the headings. A heading is display only: the manifest stays a
/// flat list in its own order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    DiskAndStartup,
    SignIn,
    Updates,
    MalwareAndNetwork,
    LogsAndAudit,
    LostDevice,
    Account,
    Uptime,
    Repositories,
    /// A check that is not built in.
    Other,
}

impl Group {
    pub const ALL: [Group; 10] = [
        Self::DiskAndStartup,
        Self::SignIn,
        Self::Updates,
        Self::MalwareAndNetwork,
        Self::LogsAndAudit,
        Self::LostDevice,
        Self::Account,
        Self::Uptime,
        Self::Repositories,
        Self::Other,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::DiskAndStartup => "Disk and start-up",
            Self::SignIn => "Sign-in",
            Self::Updates => "Updates",
            Self::MalwareAndNetwork => "Malware and network",
            Self::LogsAndAudit => "Logs and audit",
            Self::LostDevice => "Lost device",
            Self::Account => "Account rights",
            Self::Uptime => "Uptime",
            Self::Repositories => "Work repositories",
            Self::Other => "Other",
        }
    }
}

/// Puts items under their group headings, in the order of `Group::ALL`. An item keeps its place
/// among the others of its group, and a group with no item is left out.
pub fn by_group<T>(
    items: impl IntoIterator<Item = T>,
    group: impl Fn(&T) -> Group,
) -> Vec<(Group, Vec<T>)> {
    let mut sections: Vec<(Group, Vec<T>)> = Group::ALL
        .into_iter()
        .map(|group| (group, Vec::new()))
        .collect();
    for item in items {
        sections[group(&item) as usize].1.push(item);
    }
    sections.retain(|(_, items)| !items.is_empty());
    sections
}

/// The default text of each built-in check, keyed by its check name, `builtin:<id>@<version>`.
/// The CLI gives these texts, so the app keeps no copy.
pub type BuiltinTexts = BTreeMap<String, String>;

/// The default texts of this run. Empty until `load_builtin_texts` or `set_builtin_texts` sets them.
static BUILTIN_TEXTS: OnceLock<BuiltinTexts> = OnceLock::new();

#[derive(Deserialize)]
struct BuiltinText {
    check: String,
    about: String,
}

/// Reads what `manifest builtins --json` printed: one `{"check", "id", "about"}` per built-in check.
/// A check whose text is empty has no default.
pub fn parse_builtin_texts(text: &str) -> Result<BuiltinTexts, String> {
    let texts: Vec<BuiltinText> = serde_json::from_str(text)
        .map_err(|error| format!("Invalid JSON from open-pact-client: {error}"))?;
    Ok(texts
        .into_iter()
        .filter(|text| !text.about.is_empty())
        .map(|text| (text.check, text.about))
        .collect())
}

/// Asks the CLIs in order for the default texts and keeps them from the first one that answers.
/// A CLI that fails, or is too old to know the command, is skipped. Returns false when none
/// answers, and then no check has a default text.
pub fn load_builtin_texts(programs: &[PathBuf]) -> bool {
    let runner = Runner::default().with_timeout(Duration::from_secs(5));
    let words = args(&["manifest", "builtins", "--json"]);
    let texts = programs.iter().find_map(|program| {
        let log = runner.run(program, &words).ok()?;
        parse_builtin_texts(&log.stdout).ok()
    });
    match texts {
        Some(texts) => {
            let _ = BUILTIN_TEXTS.set(texts);
            true
        }
        None => false,
    }
}

/// Sets the default texts without a CLI, for snapshot scenes. Only the first set counts.
pub fn set_builtin_texts(texts: BuiltinTexts) {
    let _ = BUILTIN_TEXTS.set(texts);
}

/// The default text of a built-in check, or None when the CLI gave none.
pub fn default_about(check: &str) -> Option<&'static str> {
    BUILTIN_TEXTS.get()?.get(check).map(String::as_str)
}

/// A built-in check the client can run.
pub struct Builtin {
    pub id: &'static str,
    pub name: &'static str,
    pub line: &'static str,
    pub scope: &'static str,
    pub output: &'static str,
    /// The version of the check the client runs, as in `builtin:<id>@<version>`.
    pub version: u8,
    /// For a number check, whether the limit is a maximum.
    pub max: bool,
    /// What a number limit counts, as a noun, for the panel heading.
    pub noun: &'static str,
    pub group: Group,
}

const INTEGER_3650: &str = "{ integer = { min = 0, max = 3650 } }";
const INTEGER_MAX: &str = "{ integer = { min = 0, max = 2147483647 } }";
/// Core takes only `n/a` and `none` as explicit words of an integer output; `unknown` is always
/// allowed without being listed. The bound matches the client, which reports any whole number of
/// minutes that fits an i32.
const LOCK_MINUTES: &str = r#"{ integer = { min = 0, max = 2147483647 }, values = ["none"] }"#;

pub const BUILTINS: [Builtin; 27] = [
    Builtin {
        id: "disk_encryption",
        version: 1,
        name: "Disk encryption",
        line: "The disk is encrypted",
        scope: "",
        output: r#"["full", "partial", "none", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::DiskAndStartup,
    },
    Builtin {
        id: "firewall",
        version: 1,
        name: "Firewall",
        line: "The firewall is on",
        scope: "",
        output: r#"["on", "off", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::MalwareAndNetwork,
    },
    Builtin {
        id: "screen_lock",
        version: 1,
        name: "Screen lock",
        line: "The screen locks after a short idle time",
        scope: "",
        output: r#"["le_5min", "le_15min", "gt_15min", "none", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::SignIn,
    },
    Builtin {
        id: "screen_lock",
        version: 2,
        name: "Screen lock",
        line: "The screen locks after a short idle time",
        scope: "",
        output: LOCK_MINUTES,
        max: true,
        noun: "time before the lock",
        group: Group::SignIn,
    },
    Builtin {
        id: "os_patch_age_days",
        version: 1,
        name: "OS updates",
        line: "How old the last system update is",
        scope: "",
        output: INTEGER_3650,
        max: true,
        noun: "last OS update",
        group: Group::Updates,
    },
    Builtin {
        id: "os_supported",
        version: 1,
        name: "Supported OS",
        line: "The OS version still gets vendor updates",
        scope: "",
        output: r#"["yes", "no", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::Updates,
    },
    Builtin {
        id: "os_auto_updates",
        version: 1,
        name: "Automatic OS updates",
        line: "The OS installs updates by itself",
        scope: "",
        output: r#"["on", "off", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::Updates,
    },
    Builtin {
        id: "antimalware_active",
        version: 1,
        name: "Antimalware active",
        line: "An antimalware program is installed and on",
        scope: "",
        output: r#"["yes", "no", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::MalwareAndNetwork,
    },
    Builtin {
        id: "antimalware_realtime",
        version: 1,
        name: "Antimalware real-time",
        line: "The antimalware program scans files as they open",
        scope: "",
        output: r#"["on", "off", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::MalwareAndNetwork,
    },
    Builtin {
        id: "antimalware_signature_age_days",
        version: 1,
        name: "Antimalware signatures",
        line: "How old the antimalware signatures are",
        scope: "",
        output: INTEGER_3650,
        max: true,
        noun: "signature age",
        group: Group::MalwareAndNetwork,
    },
    Builtin {
        id: "antimalware_full_scan_age_days",
        version: 1,
        name: "Full scan age",
        line: "How long ago the last full scan ran",
        scope: "Windows",
        output: r#"{ integer = { min = 0, max = 3650 }, values = ["n/a"] }"#,
        max: true,
        noun: "last full scan",
        group: Group::MalwareAndNetwork,
    },
    Builtin {
        id: "antimalware_active_threats",
        version: 1,
        name: "Active threats",
        line: "Threats the antimalware program has not cleaned",
        scope: "Windows",
        output: r#"{ integer = { min = 0, max = 2147483647 }, values = ["n/a"] }"#,
        max: true,
        noun: "active threats",
        group: Group::MalwareAndNetwork,
    },
    Builtin {
        id: "preboot_auth",
        version: 1,
        name: "Pre-boot login",
        line: "A secret is needed before the disk unlocks",
        scope: "",
        output: r#"["user_secret", "hardware_only", "none", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::DiskAndStartup,
    },
    Builtin {
        id: "password_min_length",
        version: 1,
        name: "Password policy",
        line: "The shortest password the device accepts",
        scope: "",
        output: r#"{ integer = { min = 0, max = 2147483647 }, values = ["none"] }"#,
        max: false,
        noun: "password length",
        group: Group::SignIn,
    },
    Builtin {
        id: "password_set",
        version: 1,
        name: "Password set",
        line: "The account has a password",
        scope: "",
        output: r#"["yes", "no"]"#,
        max: true,
        noun: "",
        group: Group::SignIn,
    },
    Builtin {
        id: "auto_login",
        version: 1,
        name: "Automatic login",
        line: "The device signs in without a password",
        scope: "",
        output: r#"["off", "on", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::SignIn,
    },
    Builtin {
        id: "secure_boot",
        version: 1,
        name: "Secure boot",
        line: "Only trusted software starts the device",
        scope: "Windows and Linux",
        output: r#"["on", "off", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::DiskAndStartup,
    },
    Builtin {
        id: "work_account",
        version: 1,
        name: "Work account",
        line: "Whether the work account is an administrator",
        scope: "",
        output: r#"["standard", "admin", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::Account,
    },
    Builtin {
        id: "uptime_days",
        version: 1,
        name: "Uptime",
        line: "Days since the device last restarted",
        scope: "",
        output: INTEGER_MAX,
        max: true,
        noun: "uptime",
        group: Group::Uptime,
    },
    Builtin {
        id: "web_protection",
        version: 1,
        name: "Web protection",
        line: "Browser blocks known bad sites",
        scope: "",
        output: r#"["on", "off", "unknown", "n/a"]"#,
        max: true,
        noun: "",
        group: Group::MalwareAndNetwork,
    },
    Builtin {
        id: "log_oldest_record_days",
        version: 1,
        name: "Oldest log record",
        line: "How far back the system log reaches",
        scope: "Windows and Linux",
        output: r#"{ integer = { min = 0, max = 2147483647 }, values = ["n/a"] }"#,
        max: false,
        noun: "oldest log record",
        group: Group::LogsAndAudit,
    },
    Builtin {
        id: "log_cleared",
        version: 1,
        name: "Log cleared",
        line: "When someone last cleared the security log",
        scope: "Windows",
        output: r#"{ timestamp = true, nullable = true, values = ["n/a"] }"#,
        max: true,
        noun: "",
        group: Group::LogsAndAudit,
    },
    Builtin {
        id: "process_audit",
        version: 1,
        name: "Process audit",
        line: "Windows logs which programs start",
        scope: "Windows",
        output: r#"["on", "off", "n/a", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::LogsAndAudit,
    },
    Builtin {
        id: "remote_wipe",
        version: 1,
        name: "Remote wipe",
        line: "Can the device be erased from a distance",
        scope: "macOS",
        output: r#"["on", "off", "n/a", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::LostDevice,
    },
    Builtin {
        id: "powershell_logging",
        version: 1,
        name: "PowerShell logging",
        line: "Scripts are logged",
        scope: "Windows",
        output: r#"["on", "off", "n/a", "unknown"]"#,
        max: true,
        noun: "",
        group: Group::LogsAndAudit,
    },
    Builtin {
        id: "managed_repos_outside",
        version: 1,
        name: "Repositories outside folders",
        line: "Work repositories outside the declared folders",
        scope: "",
        output: INTEGER_MAX,
        max: true,
        noun: "repositories",
        group: Group::Repositories,
    },
    Builtin {
        id: "managed_repos_total",
        version: 1,
        name: "Managed repositories",
        line: "All work repositories on the device",
        scope: "",
        output: INTEGER_MAX,
        max: true,
        noun: "repositories",
        group: Group::Repositories,
    },
];

/// The newest version of a built-in check. A control that uses an older version keeps its name,
/// group and limit kind from this entry.
pub fn builtin(id: &str) -> Option<&'static Builtin> {
    BUILTINS
        .iter()
        .filter(|known| known.id == id)
        .max_by_key(|known| known.version)
}

/// The built-in check that a `check` value such as `builtin:screen_lock@1` names, with that
/// exact version. A version this editor does not know falls back to the newest entry.
pub fn builtin_of_check(check: &str) -> Option<&'static Builtin> {
    let rest = check.strip_prefix("builtin:")?;
    let (id, version) = rest.split_once('@').unwrap_or((rest, ""));
    let version = version.parse::<u8>().ok();
    BUILTINS
        .iter()
        .find(|known| known.id == id && Some(known.version) == version)
        .or_else(|| builtin(id))
}

/// The built-in checks the manifest does not use yet. The two repository checks need remote
/// patterns that only the TOML can hold, so the list leaves them out.
pub fn addable(form: &Form) -> Vec<&'static Builtin> {
    BUILTINS
        .iter()
        .filter(|known| !known.id.starts_with("managed_repos"))
        .filter(|known| builtin(known.id).is_some_and(|newest| newest.version == known.version))
        .filter(|known| !form.controls.iter().any(|c| c.builtin_id() == known.id))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    All,
    Required,
    Reported,
}

impl Form {
    pub fn counts(&self) -> (usize, usize, usize) {
        let required = self.controls.iter().filter(|c| c.is_required()).count();
        (
            self.controls.len(),
            required,
            self.controls.len() - required,
        )
    }

    /// Indexes of the controls a filter and a search show.
    pub fn visible(&self, filter: Filter, search: &str) -> Vec<usize> {
        let search = search.trim().to_lowercase();
        self.controls
            .iter()
            .enumerate()
            .filter(|(_, control)| match filter {
                Filter::All => true,
                Filter::Required => control.is_required(),
                Filter::Reported => !control.is_required(),
            })
            .filter(|(_, control)| {
                search.is_empty()
                    || control.name().to_lowercase().contains(&search)
                    || control.id.to_lowercase().contains(&search)
            })
            .map(|(index, _)| index)
            .collect()
    }
}

/// What changed between the active manifest and the draft, in words.
pub fn changes(before: &Form, after: &Form) -> Vec<String> {
    let mut list = Vec::new();
    let mut text = |label: &str, old: &str, new: &str| {
        if old != new {
            list.push(format!("{label}: {old} → {new}"));
        }
    };
    text("Issuer", &before.issuer, &after.issuer);
    text(
        "Valid from",
        &date_text(&before.valid_from),
        &date_text(&after.valid_from),
    );
    text(
        "Data controller",
        &before.data_controller,
        &after.data_controller,
    );
    let span = |raw: &str| Span::parse(raw).map_or_else(|| raw.to_owned(), |span| span.words());
    text(
        "A result is valid for",
        &span(&before.max_age),
        &span(&after.max_age),
    );
    text(
        "Results are kept for",
        &span(&before.retention),
        &span(&after.retention),
    );
    text(
        "Unknown is allowed for",
        &span(&before.unknown_grace),
        &span(&after.unknown_grace),
    );
    let trust = |raw: &str| {
        TRUST_LEVELS
            .iter()
            .find(|(key, _)| *key == raw)
            .map_or_else(|| raw.to_owned(), |(_, name)| (*name).to_owned())
    };
    text(
        "Device key at least",
        &trust(&before.trust),
        &trust(&after.trust),
    );
    let mut lists = |label: &str, old: &[String], new: &[String], name: &dyn Fn(&str) -> String| {
        for item in new.iter().filter(|item| !old.contains(item)) {
            list.push(format!("{label}: added {}", name(item)));
        }
        for item in old.iter().filter(|item| !new.contains(item)) {
            list.push(format!("{label}: removed {}", name(item)));
        }
    };
    lists(
        "Results go to",
        &before.recipients,
        &after.recipients,
        &str::to_owned,
    );
    lists(
        "Sent with each result",
        &before.metadata,
        &after.metadata,
        &|key| {
            METADATA
                .iter()
                .find(|(known, _)| *known == key)
                .map_or_else(|| key.to_owned(), |(_, name)| (*name).to_owned())
        },
    );
    send_changes(&mut list, before.schedule.as_ref(), after.schedule.as_ref());
    for old in &before.controls {
        if after.control(&old.id).is_none() {
            list.push(format!("Removed check: {}", old.name()));
        }
    }
    for new in &after.controls {
        let Some(old) = before.control(&new.id) else {
            list.push(format!("Added check: {}", new.name()));
            continue;
        };
        let name = new.name();
        if old.reference != new.reference {
            list.push(format!("{name}: reference changed"));
        }
        if old.description != new.description {
            list.push(format!("{name}: description changed"));
        }
        for os in Os::ALL {
            let (a, b) = (old.requirement(os), new.requirement(os));
            if a == b {
                continue;
            }
            let words = match (a, b) {
                (Requirement::Max(x), Requirement::Max(y))
                | (Requirement::Min(x), Requirement::Min(y)) => {
                    let unit = new.limit_unit();
                    format!(
                        "{x} → {y}{}",
                        if unit.is_empty() {
                            String::new()
                        } else {
                            format!(" {unit}")
                        }
                    )
                }
                _ => format!(
                    "{} → {}",
                    requirement_text(old, a),
                    requirement_text(new, b)
                ),
            };
            list.push(format!("{name}: {} {words}", os.name()));
        }
        if old.grace != new.grace {
            let span =
                |raw: &str| Span::parse(raw).map_or_else(|| raw.to_owned(), |span| span.words());
            list.push(format!(
                "{name}: time to fix {} → {}",
                span(&old.grace),
                span(&new.grace)
            ));
        }
    }
    list
}

/// The sending changes in words: each part turned on or off, then the values that changed.
fn send_changes(list: &mut Vec<String>, before: Option<&Schedule>, after: Option<&Schedule>) {
    let span = |raw: &str| Span::parse(raw).map_or_else(|| raw.to_owned(), |span| span.words());
    match (
        before.and_then(|s| s.vpn.as_ref()),
        after.and_then(|s| s.vpn.as_ref()),
    ) {
        (None, Some(_)) => list.push("On the company VPN: turned on".into()),
        (Some(_), None) => list.push("On the company VPN: turned off".into()),
        (Some(old), Some(new)) => {
            if old.probe != new.probe {
                list.push(format!("VPN answers at: {} → {}", old.probe, new.probe));
            }
            if old.name != new.name {
                list.push(format!("VPN shown as: {} → {}", old.name, new.name));
            }
            if old.check != new.check {
                list.push(format!(
                    "VPN: check every {} → {}",
                    span(&old.check),
                    span(&new.check)
                ));
            }
            if old.interval != new.interval {
                list.push(format!(
                    "VPN: send every {} → {}",
                    span(&old.interval),
                    span(&new.interval)
                ));
            }
        }
        (None, None) => (),
    }
    match (
        before.and_then(|s| s.always.as_ref()),
        after.and_then(|s| s.always.as_ref()),
    ) {
        (None, Some(_)) => list.push("On any network: turned on".into()),
        (Some(_), None) => list.push("On any network: turned off".into()),
        (Some(old), Some(new)) if old.interval != new.interval => list.push(format!(
            "On any network: send every {} → {}",
            span(&old.interval),
            span(&new.interval)
        )),
        _ => (),
    }
}

/// Ids of the controls that differ from the active manifest, or that it does not have.
pub fn changed_controls(before: &Form, after: &Form) -> Vec<String> {
    after
        .controls
        .iter()
        .filter(|control| before.control(&control.id) != Some(control))
        .map(|control| control.id.clone())
        .collect()
}

/// A top-level key of the manifest that the form edits.
const MODELLED_TOP: [&str; 9] = [
    "issuer",
    "valid_from",
    "data_controller",
    "claim_recipients",
    "claim_max_age",
    "claim_retention",
    "unknown_grace",
    "min_trust_level",
    "disclosed_metadata",
];
/// The keys of [schedule] that the form edits: the two parts, and the flat keys of older manifests.
const MODELLED_SCHEDULE: [&str; 6] = [
    "mode",
    "vpn_probe",
    "vpn_probe_name",
    "interval",
    "vpn",
    "always",
];
const MODELLED_SEND: [&str; 4] = ["probe", "probe_name", "check", "interval"];
const MODELLED_CONTROL: [&str; 8] = [
    "id",
    "source",
    "source_ref",
    "rationale",
    "description",
    "reference",
    "required",
    "grace",
];

fn differing(
    old: Option<&serde_json::Value>,
    new: Option<&serde_json::Value>,
    skip: &[&str],
    prefix: &str,
    keys: &mut Vec<String>,
) {
    let empty = serde_json::Map::new();
    let table = |value: Option<&serde_json::Value>| {
        value
            .and_then(serde_json::Value::as_object)
            .cloned()
            .unwrap_or_else(|| empty.clone())
    };
    let (old, new) = (table(old), table(new));
    let names: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    for name in names {
        if !skip.contains(&name.as_str()) && old.get(name) != new.get(name) {
            keys.push(format!("{prefix}{name}"));
        }
    }
}

/// The keys that differ between two manifests and that the form does not edit: "log",
/// "firewall.output" and so on. Both texts must parse.
pub fn other_edits(before: &str, after: &str) -> Vec<String> {
    let read = |text: &str| toml_edit::de::from_str::<serde_json::Value>(text).ok();
    let (Some(old), Some(new)) = (read(before), read(after)) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    let mut skip = MODELLED_TOP.to_vec();
    skip.extend(["schedule", "control"]);
    differing(Some(&old), Some(&new), &skip, "", &mut keys);
    differing(
        old.get("schedule"),
        new.get("schedule"),
        &MODELLED_SCHEDULE,
        "schedule.",
        &mut keys,
    );
    for part in ["vpn", "always"] {
        differing(
            old.get("schedule").and_then(|s| s.get(part)),
            new.get("schedule").and_then(|s| s.get(part)),
            &MODELLED_SEND,
            &format!("schedule.{part}."),
            &mut keys,
        );
    }
    let controls = |value: &serde_json::Value| {
        value
            .get("control")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let before_controls = controls(&old);
    for control in controls(&new) {
        let Some(id) = control.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(was) = before_controls
            .iter()
            .find(|c| c.get("id").and_then(serde_json::Value::as_str) == Some(id))
        else {
            continue;
        };
        let prefix = format!("{id}.");
        differing(
            Some(was),
            Some(&control),
            &MODELLED_CONTROL,
            &prefix,
            &mut keys,
        );
        let os_keys = Os::ALL.map(Os::key);
        differing(
            was.get("required"),
            control.get("required"),
            &os_keys,
            &format!("{prefix}required."),
            &mut keys,
        );
    }
    keys
}

/// The change list of the apply bar: what the form shows in words, then every edit it does not
/// model, even when modelled edits exist.
pub fn changes_between(before: &str, after: &str) -> Vec<String> {
    let (Ok(old), Ok(new)) = (Form::parse(before), Form::parse(after)) else {
        return if before == after {
            Vec::new()
        } else {
            vec!["The TOML text changed".into()]
        };
    };
    let mut list = changes(&old, &new);
    let other = other_edits(before, after);
    if !other.is_empty() {
        list.push(format!("Other edits in TOML: {}", other.join(", ")));
    }
    if comments(before) != comments(after) {
        list.push("Comments changed in TOML".into());
    } else if list.is_empty() && before != after {
        list.push("Layout changed in TOML".into());
    }
    list
}

/// Every comment of a TOML text, in order. A `#` inside a string is no comment.
fn comments(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'#' => {
                let end = text[at..].find('\n').map_or(bytes.len(), |n| at + n);
                found.push(text[at..end].trim_end().to_owned());
                at = end;
            }
            quote @ (b'"' | b'\'') => {
                let basic = quote == b'"';
                if bytes[at..].starts_with(&[quote; 3]) {
                    at += 3;
                    while at < bytes.len() && !bytes[at..].starts_with(&[quote; 3]) {
                        at += if basic && bytes[at] == b'\\' { 2 } else { 1 };
                    }
                    // Up to two quotes before the closing run are content: the last three close.
                    while at + 3 < bytes.len() && bytes[at + 3] == quote {
                        at += 1;
                    }
                    at += 3;
                } else {
                    at += 1;
                    while at < bytes.len() && bytes[at] != b'\n' && bytes[at] != quote {
                        at += if basic && bytes[at] == b'\\' { 2 } else { 1 };
                    }
                    at += 1;
                }
            }
            _ => at += 1,
        }
    }
    found
}

/// Where a problem sits in the form.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    Issuer,
    ValidFrom,
    Controller,
    Trust,
    MaxAge,
    Retention,
    UnknownGrace,
    VpnProbe,
    VpnProbeName,
    VpnCheck,
    VpnInterval,
    AlwaysInterval,
    /// The check with this ID.
    Id(String),
    Grace(String),
    Requirement(String, Os),
}

impl Field {
    /// Fields of the selected check's panel. They go away with the panel.
    pub fn in_panel(&self) -> bool {
        matches!(self, Self::Id(_) | Self::Grace(_) | Self::Requirement(..))
    }

    /// The ID of the check this field belongs to.
    pub fn control(&self) -> Option<&str> {
        match self {
            Self::Id(id) | Self::Grace(id) | Self::Requirement(id, _) => Some(id),
            _ => None,
        }
    }

    /// The name of the field, as the form shows it.
    pub fn label(&self, form: &Form) -> String {
        let name = |id: &str| {
            form.control(id)
                .map_or_else(|| id.to_owned(), Control::name)
        };
        match self {
            Self::Issuer => "Issuer".into(),
            Self::ValidFrom => "Valid from".into(),
            Self::Controller => "Data controller".into(),
            Self::Trust => "Device key at least".into(),
            Self::MaxAge => "A result is valid for".into(),
            Self::Retention => "Results are kept for".into(),
            Self::UnknownGrace => "Unknown is allowed for".into(),
            Self::VpnProbe => "VPN answers at".into(),
            Self::VpnProbeName => "VPN shown as".into(),
            Self::VpnCheck => "VPN: check every".into(),
            Self::VpnInterval => "VPN: send every".into(),
            Self::AlwaysInterval => "Any network: send every".into(),
            Self::Id(id) => format!("{}: ID", name(id)),
            Self::Grace(id) => format!("{}: time to fix", name(id)),
            Self::Requirement(id, os) => format!("{}: {}", name(id), os.name()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldError {
    pub field: Field,
    pub message: String,
}

/// Input that the form could not turn into a value yet, with one message per field. The draft
/// keeps the last good value, so the form must not offer review while any is left.
#[derive(Clone, Debug, Default)]
pub struct Pending(BTreeMap<Field, String>);

impl Pending {
    /// A good value clears the error of its own field only. A bad one replaces it.
    pub fn record(&mut self, field: Field, outcome: Result<(), String>) {
        match outcome {
            Ok(()) => {
                self.0.remove(&field);
            }
            Err(message) => {
                self.0.insert(field, message);
            }
        }
    }

    pub fn get(&self, field: &Field) -> Option<&str> {
        self.0.get(field).map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn errors(&self) -> Vec<FieldError> {
        self.0
            .iter()
            .map(|(field, message)| FieldError {
                field: field.clone(),
                message: message.clone(),
            })
            .collect()
    }

    /// The selected check got a new ID: its errors follow it.
    pub fn rename_control(&mut self, old: &str, new: &str) {
        let moved: Vec<Field> = self
            .0
            .keys()
            .filter(|field| field.control() == Some(old))
            .cloned()
            .collect();
        for field in moved {
            let Some(message) = self.0.remove(&field) else {
                continue;
            };
            let field = match field {
                Field::Id(_) => Field::Id(new.to_owned()),
                Field::Grace(_) => Field::Grace(new.to_owned()),
                Field::Requirement(_, os) => Field::Requirement(new.to_owned(), os),
                other => other,
            };
            self.0.insert(field, message);
        }
    }

    /// Why the panel may not be replaced: one of its inputs holds text that is not a value yet.
    pub fn panel_blocks(&self, form: &Form) -> Option<String> {
        let field = self.0.keys().find(|field| field.in_panel())?;
        Some(format!(
            "{} holds text that is not a value yet. Fix it before you switch checks.",
            field.label(form)
        ))
    }

    /// A part of sending that is off has no inputs, so it holds no unread text either.
    pub fn drop_absent_sends(&mut self, schedule: Option<&Schedule>) {
        let vpn = schedule.is_some_and(|schedule| schedule.vpn.is_some());
        let always = schedule.is_some_and(|schedule| schedule.always.is_some());
        self.0.retain(|field, _| match field {
            Field::VpnProbe | Field::VpnProbeName | Field::VpnCheck | Field::VpnInterval => vpn,
            Field::AlwaysInterval => always,
            _ => true,
        });
    }

    /// The first input that holds text the form could not read.
    pub fn first_unread(&self) -> Option<&Field> {
        self.0.keys().next()
    }

    /// Why the view may not change: one of the inputs holds text that is not a value yet.
    pub fn unread_blocks(&self, form: &Form) -> Option<String> {
        let field = self.first_unread()?;
        Some(format!(
            "{} holds text that is not a value yet. Fix it before you switch views.",
            field.label(form)
        ))
    }

    /// The panel's inputs are gone, and so is the text they held.
    pub fn drop_panel(&mut self) {
        self.0.retain(|field, _| !field.in_panel());
    }
}

/// Everything that stops a review. Unparsed input is the form's own business. Every rule of the
/// manifest comes from the open-pact CLI, which runs the same code as a client and the gateway.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Problems {
    /// Shown under their field: unparsed input first, then the CLI errors whose key names one.
    pub fields: Vec<FieldError>,
    /// The CLI errors that name no field of the form.
    pub listed: Vec<CheckError>,
}

impl Problems {
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.listed.is_empty()
    }

    /// The first problem as one line, with its field name when it has one.
    pub fn first(&self, form: &Form) -> Option<String> {
        self.fields
            .first()
            .map(|first| format!("{}: {}", first.field.label(form), first.message))
            .or_else(|| self.listed.first().map(CheckError::text))
    }

    pub fn len(&self) -> usize {
        self.fields.len() + self.listed.len()
    }
}

impl CheckError {
    /// "Line 3: message" for an error with a line, else the message.
    pub fn text(&self) -> String {
        match self.line {
            Some(line) => format!("Line {line}: {}", self.message),
            None => self.message.clone(),
        }
    }
}

/// The form field that a CLI error key names, or `None` when the key names none. A key is a
/// top-level name (`issuer`), `schedule.interval`, or `controls.<id>[.check|.required.<os>]`.
pub fn field_of(key: &str) -> Option<Field> {
    let key = key.trim();
    if let Some(rest) = key
        .strip_prefix("controls.")
        .or_else(|| key.strip_prefix("control."))
    {
        let mut parts = rest.split('.');
        let id = parts.next().filter(|id| !id.is_empty())?.to_owned();
        return match (parts.next(), parts.next(), parts.next()) {
            (Some("check"), None, _) => Some(Field::Id(id)),
            (Some("grace"), None, _) => Some(Field::Grace(id)),
            (Some("required"), Some(os), None) => Os::ALL
                .into_iter()
                .find(|known| known.key() == os)
                .map(|os| Field::Requirement(id, os)),
            _ => None,
        };
    }
    let name = key.strip_prefix("schedule.").unwrap_or(key);
    match name {
        "issuer" => Some(Field::Issuer),
        "valid_from" => Some(Field::ValidFrom),
        "data_controller" => Some(Field::Controller),
        "min_trust_level" | "trust" => Some(Field::Trust),
        "claim_max_age" => Some(Field::MaxAge),
        "claim_retention" => Some(Field::Retention),
        "unknown_grace" => Some(Field::UnknownGrace),
        "vpn.probe" | "vpn_probe" => Some(Field::VpnProbe),
        "vpn.probe_name" | "vpn_probe_name" => Some(Field::VpnProbeName),
        "vpn.check" => Some(Field::VpnCheck),
        "vpn.interval" => Some(Field::VpnInterval),
        "always.interval" => Some(Field::AlwaysInterval),
        _ => None,
    }
}

/// Unparsed input first, then what the CLI refused, each error under its field when its key
/// names one.
pub fn problems(pending: &Pending, refused: &[CheckError]) -> Problems {
    let mut all = Problems {
        fields: pending.errors(),
        listed: Vec::new(),
    };
    for error in refused {
        match error.key.as_deref().and_then(field_of) {
            Some(field) => all.fields.push(FieldError {
                field,
                message: error.message.clone(),
            }),
            None => all.listed.push(error.clone()),
        }
    }
    all
}

/// The answer of the CLI for one draft. A draft edited after the question was sent has no
/// answer yet, and a reply to an older question is dropped.
#[derive(Clone, Debug, Default)]
pub struct ManifestCheck {
    generation: u64,
    checked: String,
    outcome: Option<Result<Vec<CheckError>, String>>,
}

impl ManifestCheck {
    /// Starts a new question. Every earlier one is stale from now on, and no draft has an answer
    /// until its own reply lands.
    pub fn begin(&mut self) -> u64 {
        self.generation += 1;
        self.checked.clear();
        self.outcome = None;
        self.generation
    }

    pub fn is_current(&self, generation: u64) -> bool {
        self.generation == generation
    }

    /// Keeps the reply to the question `generation` about `draft`. A stale reply is dropped and
    /// the result is `false`.
    pub fn finish(
        &mut self,
        generation: u64,
        draft: &str,
        outcome: Result<Vec<CheckError>, String>,
    ) -> bool {
        if !self.is_current(generation) {
            return false;
        }
        self.checked = draft.to_owned();
        self.outcome = Some(outcome);
        true
    }

    /// The errors of the CLI for exactly this draft. `None` while the answer is not here. A CLI
    /// that did not answer is one error, so it stops a review like any other.
    pub fn result(&self, draft: &str) -> Option<Vec<CheckError>> {
        if self.checked != draft {
            return None;
        }
        Some(match self.outcome.as_ref()? {
            Ok(errors) => errors.clone(),
            Err(message) => vec![CheckError {
                message: format!("The manifest could not be checked. {message}"),
                line: None,
                key: None,
            }],
        })
    }
}
fn document(text: &str) -> Result<DocumentMut, String> {
    text.parse::<DocumentMut>().map_err(|e| e.to_string())
}

/// Replaces a value and keeps the spacing and the comment around it.
fn put(table: &mut dyn TableLike, key: &str, mut new: Value) {
    if let Some(Item::Value(old)) = table.get_mut(key) {
        *new.decor_mut() = old.decor().clone();
        *old = new;
        return;
    }
    table.insert(key, Item::Value(new));
}

fn array_of(items: &[String]) -> Value {
    let mut array = Array::new();
    for item in items {
        array.push(item.as_str());
    }
    array.fmt();
    Value::Array(array)
}

/// Adds an item behind the last one. In a list with one item per line the new item gets its own
/// line, and a comment after the last comma stays with the item it follows.
fn push_item(array: &mut Array, item: &str) {
    let last_prefix = array
        .iter()
        .last()
        .and_then(|value| value.decor().prefix())
        .and_then(|prefix| prefix.as_str())
        .map(str::to_owned);
    let Some(prefix) = last_prefix.filter(|prefix| prefix.contains('\n')) else {
        array.push(item);
        return;
    };
    let indent = prefix.rsplit('\n').next().unwrap_or_default().to_owned();
    let trailing = array.trailing().as_str().unwrap_or_default().to_owned();
    let carried = if trailing.contains('\n') {
        array.set_trailing("\n");
        format!("{trailing}{indent}")
    } else {
        format!("\n{indent}")
    };
    let mut value = Value::from(item);
    value.decor_mut().set_prefix(carried);
    array.push_formatted(value);
}

/// Changes a list to hold `items`: drops the strings that are no longer listed and adds the new
/// ones at the end. The items that stay keep their spacing and their comments.
fn edit_list(array: &mut Array, items: &[String]) {
    for at in (0..array.len()).rev() {
        let gone = array
            .get(at)
            .and_then(Value::as_str)
            .is_some_and(|text| !items.iter().any(|item| item == text));
        if !gone {
            continue;
        }
        let removed = array.remove(at);
        let prefix = removed.decor().prefix().cloned();
        if at == 0 {
            let single_line = prefix
                .as_ref()
                .and_then(|prefix| prefix.as_str())
                .is_some_and(|prefix| !prefix.contains('\n'));
            if let (true, Some(prefix), Some(next)) = (single_line, prefix, array.get_mut(0)) {
                next.decor_mut().set_prefix(prefix);
            }
        }
    }
    if array.is_empty() {
        array.set_trailing("");
        array.set_trailing_comma(false);
    }
    let listed: Vec<String> = array
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect();
    for item in items.iter().filter(|item| !listed.contains(item)) {
        push_item(array, item);
    }
}

pub fn set_top_text(text: &str, key: &str, value: &str) -> Result<String, String> {
    let mut document = document(text)?;
    put(document.as_table_mut(), key, Value::from(value));
    Ok(document.to_string())
}

pub fn set_top_list(text: &str, key: &str, items: &[String]) -> Result<String, String> {
    let mut document = document(text)?;
    let table = document.as_table_mut();
    if let Some(Item::Value(Value::Array(array))) = table.get_mut(key) {
        edit_list(array, items);
    } else {
        put(table, key, array_of(items));
    }
    Ok(document.to_string())
}

/// The document of a draft, with an older flat [schedule] turned into the sending parts.
fn converted(text: &str) -> Result<DocumentMut, String> {
    let mut document = document(text)?;
    let legacy = document
        .get("schedule")
        .and_then(Item::as_table_like)
        .is_some_and(|table| table.get("mode").is_some());
    if legacy {
        let schedule = read_schedule(&document);
        document.remove("schedule");
        if let Some(schedule) = schedule {
            if let Some(vpn) = &schedule.vpn {
                put_part(&mut document, SendPart::Vpn, vpn_table(vpn))?;
            }
            if let Some(always) = &schedule.always {
                put_part(&mut document, SendPart::Always, always_table(always))?;
            }
        }
    }
    Ok(document)
}

fn vpn_table(vpn: &VpnSend) -> Table {
    let mut table = Table::new();
    table.insert("probe", Item::Value(Value::from(vpn.probe.as_str())));
    if !vpn.name.is_empty() {
        table.insert("probe_name", Item::Value(Value::from(vpn.name.as_str())));
    }
    if vpn.check != CHECK_DEFAULT {
        table.insert("check", Item::Value(Value::from(vpn.check.as_str())));
    }
    table.insert("interval", Item::Value(Value::from(vpn.interval.as_str())));
    table
}

fn always_table(always: &AlwaysSend) -> Table {
    let mut table = Table::new();
    table.insert(
        "interval",
        Item::Value(Value::from(always.interval.as_str())),
    );
    table
}

/// Writes one part table of [schedule], creating [schedule] when the draft has none.
fn put_part(document: &mut DocumentMut, part: SendPart, table: Table) -> Result<(), String> {
    if document.get("schedule").is_none() {
        let mut schedule = Table::new();
        schedule.set_implicit(true);
        document.insert("schedule", Item::Table(schedule));
    }
    let schedule = document
        .get_mut("schedule")
        .and_then(Item::as_table_like_mut)
        .ok_or("schedule is not a table")?;
    schedule.insert(part.table(), Item::Table(table));
    Ok(())
}

/// Removes one part table. Without any part left, the manifest has no [schedule].
fn remove_part(document: &mut DocumentMut, part: SendPart) {
    let empty = match document
        .get_mut("schedule")
        .and_then(Item::as_table_like_mut)
    {
        Some(schedule) => {
            schedule.remove(part.table());
            schedule.is_empty()
        }
        None => return,
    };
    if empty {
        document.remove("schedule");
    }
}

/// The table of one part. A part written as an inline table, or inside an inline `schedule`, is
/// a table to core too.
fn send_table_mut(
    document: &mut DocumentMut,
    part: SendPart,
) -> Result<&mut dyn TableLike, String> {
    document
        .get_mut("schedule")
        .and_then(Item::as_table_like_mut)
        .and_then(|schedule| schedule.get_mut(part.table()))
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| "This part of sending is off".to_owned())
}

/// Sets one value of a sending part. Empty text removes \`probe_name\` and \`check\`.
pub fn set_send_text(text: &str, part: SendPart, key: &str, value: &str) -> Result<String, String> {
    let mut document = converted(text)?;
    let table = send_table_mut(&mut document, part)?;
    if value.is_empty() && matches!(key, "probe_name" | "check") {
        table.remove(key);
    } else {
        put(table, key, Value::from(value));
    }
    Ok(document.to_string())
}

/// Turns one sending part on or off. Turning it off keeps its values in \`kept\`. Turning it on
/// writes the kept values back, or the defaults when the session has none.
pub fn switch_send(
    text: &str,
    part: SendPart,
    on: bool,
    kept: &mut KeptSends,
) -> Result<String, String> {
    let mut document = converted(text)?;
    let schedule = read_schedule(&document);
    let is_on = match part {
        SendPart::Vpn => schedule.as_ref().is_some_and(|s| s.vpn.is_some()),
        SendPart::Always => schedule.as_ref().is_some_and(|s| s.always.is_some()),
    };
    if on == is_on {
        return Ok(document.to_string());
    }
    if on {
        let table = match part {
            SendPart::Vpn => vpn_table(&kept.vpn.clone().unwrap_or_else(default_vpn)),
            SendPart::Always => always_table(&kept.always.clone().unwrap_or_else(default_always)),
        };
        put_part(&mut document, part, table)?;
    } else {
        match (part, schedule) {
            (
                SendPart::Vpn,
                Some(Schedule {
                    vpn: Some(value), ..
                }),
            ) => kept.vpn = Some(value),
            (
                SendPart::Always,
                Some(Schedule {
                    always: Some(value),
                    ..
                }),
            ) => {
                kept.always = Some(value);
            }
            _ => (),
        }
        remove_part(&mut document, part);
    }
    Ok(document.to_string())
}

impl KeptSends {
    /// Forgets every remembered value. A draft that is replaced as a whole has no use for them.
    pub fn forget(&mut self) {
        *self = Self::default();
    }
}

/// Forgets the remembered sending values when a TOML edit changes the schedule. A form edit does
/// not come here: the form switches parts through \`switch_send\`.
///
/// A text with a syntax error has no schedule to compare, and it does not count as a schedule
/// that is gone. `seen` holds the schedule of the last text that parsed, so a schedule change
/// across a broken intermediate text still forgets the values.
pub fn sends_after_edit(before: &str, after: &str, kept: &mut KeptSends, seen: &mut SeenSchedule) {
    if let Some(schedule) = parsed_schedule(before) {
        seen.0 = Some(schedule);
    }
    let Some(now) = parsed_schedule(after) else {
        return;
    };
    if seen.0.as_ref().is_some_and(|was| *was != now) {
        kept.forget();
    }
    seen.0 = Some(now);
}

/// The schedule of a text, or `None` when the text does not parse as TOML.
fn parsed_schedule(text: &str) -> Option<Option<Schedule>> {
    text.parse::<DocumentMut>()
        .ok()
        .map(|document| read_schedule(&document))
}

/// The schedule of the last raw text that parsed, for `sends_after_edit`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeenSchedule(Option<Option<Schedule>>);

impl SeenSchedule {
    /// A draft replaced as a whole has no baseline from the old text.
    pub fn forget(&mut self) {
        self.0 = None;
    }
}

fn control_table(document: &mut DocumentMut, index: usize) -> Result<&mut Table, String> {
    let table = document
        .get_mut("control")
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|tables| tables.get_mut(index))
        .ok_or_else(|| "This check is no longer in the manifest".to_owned())?;
    current_names(table);
    Ok(table)
}

/// Writes a check with the current key names: `description` for `rationale`, `reference` for
/// `source_ref`, and no `source`. A value under the new name wins over the old one.
fn current_names(table: &mut Table) {
    for (old, new) in [("rationale", "description"), ("source_ref", "reference")] {
        if let Some(item) = table.remove(old)
            && table.get(new).is_none()
        {
            table.insert(new, item);
        }
    }
    table.remove("source");
}

/// Sets a text key of one check. Empty text removes an optional key.
pub fn set_control_text(
    text: &str,
    index: usize,
    key: &str,
    value: &str,
) -> Result<String, String> {
    let mut document = document(text)?;
    if key == "id" {
        let locked = document
            .get("control")
            .and_then(Item::as_array_of_tables)
            .and_then(|tables| tables.get(index))
            .and_then(|table| table.get("check"))
            .and_then(Item::as_str)
            .is_some_and(|check| check.starts_with("builtin:"));
        if locked {
            return Err("A built-in check keeps its ID.".into());
        }
        let duplicate = document
            .get("control")
            .and_then(Item::as_array_of_tables)
            .is_some_and(|tables| {
                tables.iter().enumerate().any(|(other, table)| {
                    other != index && table.get("id").and_then(Item::as_str) == Some(value)
                })
            });
        if value.is_empty() || duplicate {
            return Err("Every check needs its own ID".into());
        }
    }
    let table = control_table(&mut document, index)?;
    if value.is_empty() && matches!(key, "reference" | "description") {
        table.remove(key);
    } else {
        put(table, key, Value::from(value));
    }
    Ok(document.to_string())
}

pub fn set_requirement(
    text: &str,
    index: usize,
    os: Os,
    requirement: &Requirement,
) -> Result<String, String> {
    let mut document = document(text)?;
    let table = control_table(&mut document, index)?;
    if table.get("required").is_none() {
        table.insert(
            "required",
            Item::Value(Value::InlineTable(InlineTable::new())),
        );
    }
    let required = table
        .get_mut("required")
        .and_then(Item::as_table_like_mut)
        .ok_or("required is not a table")?;
    let value = match requirement {
        Requirement::Reported => {
            required.remove(os.key());
            return Ok(document.to_string());
        }
        Requirement::Values(values) if values.len() == 1 => Value::from(values[0].as_str()),
        Requirement::Values(values) => array_of(values),
        Requirement::Max(number) | Requirement::Min(number) => {
            let mut limit = InlineTable::new();
            let key = if matches!(requirement, Requirement::Max(_)) {
                "max"
            } else {
                "min"
            };
            limit.insert(key, Value::from(*number));
            limit.fmt();
            Value::InlineTable(limit)
        }
    };
    put(required, os.key(), value);
    if let Some(inline) = document
        .get_mut("control")
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|tables| tables.get_mut(index))
        .and_then(|table| table.get_mut("required"))
        .and_then(Item::as_inline_table_mut)
    {
        inline.fmt();
    }
    Ok(document.to_string())
}

/// Appends a built-in check that only reports. Returns the new text and the check's index.
pub fn add_control(text: &str, id: &str) -> Result<(String, usize), String> {
    let known = builtin(id).ok_or("This check is not built in")?;
    let mut document = document(text)?;
    let output = known.output.parse::<Value>().map_err(|e| e.to_string())?;
    let mut table = Table::new();
    table.insert("id", Item::Value(id.into()));
    table.insert(
        "check",
        Item::Value(format!("builtin:{id}@{}", known.version).into()),
    );
    table.insert("output", Item::Value(output));
    table.insert(
        "required",
        Item::Value(Value::InlineTable(InlineTable::new())),
    );
    table.insert("grace", Item::Value("1d".into()));
    let controls = document
        .entry("control")
        .or_insert_with(|| Item::ArrayOfTables(Default::default()))
        .as_array_of_tables_mut()
        .ok_or("control is not a list of tables")?;
    if controls
        .iter()
        .any(|existing| existing.get("id").and_then(Item::as_str) == Some(id))
    {
        return Err("The manifest already has this check".into());
    }
    controls.push(table);
    let index = controls.len() - 1;
    Ok((document.to_string(), index))
}

pub fn remove_control(text: &str, index: usize) -> Result<String, String> {
    let mut document = document(text)?;
    let controls = document
        .get_mut("control")
        .and_then(Item::as_array_of_tables_mut)
        .ok_or("This check is no longer in the manifest")?;
    if index >= controls.len() {
        return Err("This check is no longer in the manifest".into());
    }
    controls.remove(index);
    Ok(document.to_string())
}

pub fn diff(before: &str, after: &str) -> String {
    if before == after {
        return "No changes".into();
    }
    similar::TextDiff::from_lines(before, after)
        .unified_diff()
        .context_radius(2)
        .header("Active manifest", "Proposed manifest")
        .to_string()
}

/// The 1-based line of a TOML syntax error, or 1 when the error has no position.
pub fn error_line(text: &str, error: &toml_edit::TomlError) -> usize {
    error.span().map_or(1, |span| {
        text[..span.start.min(text.len())].matches('\n').count() + 1
    })
}

#[cfg(test)]
mod builtin_text_tests {
    use super::parse_builtin_texts;

    const FIXTURE: &str = r#"[
  {"check": "builtin:firewall@1", "id": "firewall", "about": "A device without a firewall accepts connections."},
  {"check": "builtin:screen_lock@2", "id": "screen_lock", "about": "A device that stays unlocked gives access to anyone nearby."},
  {"check": "builtin:firewall@2", "id": "firewall", "about": ""}
]"#;

    #[test]
    fn the_texts_are_keyed_by_check_and_an_empty_text_is_no_default() {
        let texts = parse_builtin_texts(FIXTURE).unwrap();
        assert_eq!(
            texts.get("builtin:firewall@1").map(String::as_str),
            Some("A device without a firewall accepts connections.")
        );
        assert_eq!(texts.len(), 2);
        assert!(!texts.contains_key("builtin:firewall@2"));
    }

    #[test]
    fn a_reply_that_is_not_the_list_is_an_error() {
        assert!(parse_builtin_texts("{\"error\": \"unknown command\"}").is_err());
        assert!(parse_builtin_texts("not json").is_err());
    }
}
