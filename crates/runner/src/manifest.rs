//! The manifest as the Form view reads and edits it. Every edit parses the text with toml_edit,
//! changes one value and prints the document again, so comments and order stay as written.
use crate::text::humanize;
use chrono::{Datelike, NaiveDate};
use std::collections::{BTreeMap, BTreeSet};
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

pub const SOURCES: [(&str, &str, &str); 4] = [
    ("customer_contract", "Customer contract", "Contract"),
    ("company_policy", "Company policy", "Policy"),
    ("standard", "Standard", "Standard"),
    ("law", "Law", "Law"),
];

pub fn source_name(key: &str) -> String {
    SOURCES
        .iter()
        .find(|(known, _, _)| *known == key)
        .map_or_else(|| key.to_owned(), |(_, name, _)| (*name).to_owned())
}

pub fn source_tag(key: &str) -> String {
    SOURCES
        .iter()
        .find(|(known, _, _)| *known == key)
        .map_or_else(|| key.to_owned(), |(_, _, tag)| (*tag).to_owned())
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
    pub source: String,
    pub source_ref: String,
    pub rationale: String,
    pub check: String,
    pub output: Output,
    pub required: [Requirement; 3],
    pub grace: String,
}

impl Control {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub mode: String,
    pub probe: String,
    pub name: String,
    pub interval: String,
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

impl Form {
    pub fn parse(text: &str) -> Result<Self, String> {
        let document = text.parse::<DocumentMut>().map_err(|e| e.to_string())?;
        let get = |key: &str| document.get(key);
        let schedule = get("schedule")
            .and_then(Item::as_table_like)
            .map(|table| Schedule {
                mode: text_of(table.get("mode")),
                probe: text_of(table.get("vpn_probe")),
                name: text_of(table.get("vpn_probe_name")),
                interval: text_of(table.get("interval")),
            });
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
                            source: text_of(table.get("source")),
                            source_ref: text_of(table.get("source_ref")),
                            rationale: text_of(table.get("rationale")),
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

/// A built-in check the client can run.
pub struct Builtin {
    pub id: &'static str,
    pub name: &'static str,
    pub line: &'static str,
    pub scope: &'static str,
    pub output: &'static str,
    /// For a number check, whether the limit is a maximum.
    pub max: bool,
    /// What a number limit counts, as a noun, for the panel heading.
    pub noun: &'static str,
}

const INTEGER_3650: &str = "{ integer = { min = 0, max = 3650 } }";
const INTEGER_MAX: &str = "{ integer = { min = 0, max = 2147483647 } }";

pub const BUILTINS: [Builtin; 26] = [
    Builtin {
        id: "disk_encryption",
        name: "Disk encryption",
        line: "The disk is encrypted",
        scope: "",
        output: r#"["full", "partial", "none", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "firewall",
        name: "Firewall",
        line: "The firewall is on",
        scope: "",
        output: r#"["on", "off", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "screen_lock",
        name: "Screen lock",
        line: "The screen locks after a short idle time",
        scope: "",
        output: r#"["le_5min", "le_15min", "gt_15min", "none", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "os_patch_age_days",
        name: "OS updates",
        line: "How old the last system update is",
        scope: "",
        output: INTEGER_3650,
        max: true,
        noun: "last OS update",
    },
    Builtin {
        id: "os_supported",
        name: "Supported OS",
        line: "The OS version still gets vendor updates",
        scope: "",
        output: r#"["yes", "no", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "os_auto_updates",
        name: "Automatic OS updates",
        line: "The OS installs updates by itself",
        scope: "",
        output: r#"["on", "off", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "antimalware_active",
        name: "Antimalware active",
        line: "An antimalware program is installed and on",
        scope: "",
        output: r#"["yes", "no", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "antimalware_realtime",
        name: "Antimalware real-time",
        line: "The antimalware program scans files as they open",
        scope: "",
        output: r#"["on", "off", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "antimalware_signature_age_days",
        name: "Antimalware signatures",
        line: "How old the antimalware signatures are",
        scope: "",
        output: INTEGER_3650,
        max: true,
        noun: "signature age",
    },
    Builtin {
        id: "antimalware_full_scan_age_days",
        name: "Full scan age",
        line: "How long ago the last full scan ran",
        scope: "Windows",
        output: r#"{ integer = { min = 0, max = 3650 }, values = ["n/a"] }"#,
        max: true,
        noun: "last full scan",
    },
    Builtin {
        id: "antimalware_active_threats",
        name: "Active threats",
        line: "Threats the antimalware program has not cleaned",
        scope: "Windows",
        output: r#"{ integer = { min = 0, max = 2147483647 }, values = ["n/a"] }"#,
        max: true,
        noun: "active threats",
    },
    Builtin {
        id: "preboot_auth",
        name: "Pre-boot login",
        line: "A secret is needed before the disk unlocks",
        scope: "",
        output: r#"["user_secret", "hardware_only", "none", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "password_min_length",
        name: "Password policy",
        line: "The shortest password the device accepts",
        scope: "",
        output: r#"{ integer = { min = 0, max = 2147483647 }, values = ["none"] }"#,
        max: false,
        noun: "password length",
    },
    Builtin {
        id: "password_set",
        name: "Password set",
        line: "The account has a password",
        scope: "",
        output: r#"["yes", "no"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "auto_login",
        name: "Automatic login",
        line: "The device signs in without a password",
        scope: "",
        output: r#"["off", "on", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "secure_boot",
        name: "Secure boot",
        line: "Only trusted software starts the device",
        scope: "Windows and Linux",
        output: r#"["on", "off", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "work_account",
        name: "Work account",
        line: "Whether the work account is an administrator",
        scope: "",
        output: r#"["standard", "admin", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "uptime_days",
        name: "Uptime",
        line: "Days since the device last restarted",
        scope: "",
        output: INTEGER_MAX,
        max: true,
        noun: "uptime",
    },
    Builtin {
        id: "web_protection",
        name: "Web protection",
        line: "Browser blocks known bad sites",
        scope: "",
        output: r#"["on", "off", "unknown", "n/a"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "log_oldest_record_days",
        name: "Oldest log record",
        line: "How far back the system log reaches",
        scope: "Windows and Linux",
        output: r#"{ integer = { min = 0, max = 2147483647 }, values = ["n/a"] }"#,
        max: false,
        noun: "oldest log record",
    },
    Builtin {
        id: "log_cleared",
        name: "Log cleared",
        line: "When someone last cleared the security log",
        scope: "Windows",
        output: r#"{ timestamp = true, nullable = true, values = ["n/a"] }"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "process_audit",
        name: "Process audit",
        line: "Windows logs which programs start",
        scope: "Windows",
        output: r#"["on", "off", "n/a", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "remote_wipe",
        name: "Remote wipe",
        line: "Can the device be erased from a distance",
        scope: "macOS",
        output: r#"["on", "off", "n/a", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "powershell_logging",
        name: "PowerShell logging",
        line: "Scripts are logged",
        scope: "Windows",
        output: r#"["on", "off", "n/a", "unknown"]"#,
        max: true,
        noun: "",
    },
    Builtin {
        id: "managed_repos_outside",
        name: "Repositories outside folders",
        line: "Work repositories outside the declared folders",
        scope: "",
        output: INTEGER_MAX,
        max: true,
        noun: "repositories",
    },
    Builtin {
        id: "managed_repos_total",
        name: "Managed repositories",
        line: "All work repositories on the device",
        scope: "",
        output: INTEGER_MAX,
        max: true,
        noun: "repositories",
    },
];

pub fn builtin(id: &str) -> Option<&'static Builtin> {
    BUILTINS.iter().find(|known| known.id == id)
}

/// The built-in checks the manifest does not use yet. The two repository checks need remote
/// patterns that only the TOML can hold, so the list leaves them out.
pub fn addable(form: &Form) -> Vec<&'static Builtin> {
    BUILTINS
        .iter()
        .filter(|known| !known.id.starts_with("managed_repos"))
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
    match (&before.schedule, &after.schedule) {
        (Some(old), Some(new)) => {
            let mode = |raw: &str| {
                if raw == "vpn" {
                    "only on the company VPN".to_owned()
                } else {
                    "always".to_owned()
                }
            };
            let mut text = |label: &str, old: &str, new: &str| {
                if old != new {
                    list.push(format!("{label}: {old} → {new}"));
                }
            };
            text("Send", &mode(&old.mode), &mode(&new.mode));
            text("VPN answers at", &old.probe, &new.probe);
            text("VPN shown as", &old.name, &new.name);
            let interval =
                |raw: &str| Span::parse(raw).map_or_else(|| raw.to_owned(), |span| span.words());
            text("Every", &interval(&old.interval), &interval(&new.interval));
        }
        (None, Some(_)) => list.push("Sending: automatic sending turned on".into()),
        (Some(_), None) => list.push("Sending: automatic sending turned off".into()),
        (None, None) => (),
    }
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
        if old.source != new.source {
            list.push(format!(
                "{name}: asked for by {} → {}",
                source_name(&old.source),
                source_name(&new.source)
            ));
        }
        if old.source_ref != new.source_ref {
            list.push(format!("{name}: reference changed"));
        }
        if old.rationale != new.rationale {
            list.push(format!("{name}: reason changed"));
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
const MODELLED_SCHEDULE: [&str; 4] = ["mode", "vpn_probe", "vpn_probe_name", "interval"];
const MODELLED_CONTROL: [&str; 6] = [
    "id",
    "source",
    "source_ref",
    "rationale",
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
    if list.is_empty() && before != after {
        list.push("Other edits in TOML: comments or layout".into());
    }
    list
}

/// Where a problem sits in the form.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    ValidFrom,
    MaxAge,
    Retention,
    UnknownGrace,
    Send,
    Interval,
    VpnProbe,
    VpnProbeName,
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
            Self::ValidFrom => "Valid from".into(),
            Self::MaxAge => "A result is valid for".into(),
            Self::Retention => "Results are kept for".into(),
            Self::UnknownGrace => "Unknown is allowed for".into(),
            Self::Send => "Send".into(),
            Self::Interval => "Every".into(),
            Self::VpnProbe => "VPN answers at".into(),
            Self::VpnProbeName => "VPN shown as".into(),
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

    /// The panel's inputs are gone, and so is the text they held.
    pub fn drop_panel(&mut self) {
        self.0.retain(|field, _| !field.in_panel());
    }
}

/// Everything that stops a review: unparsed input first, then what the gateway or a client
/// would refuse.
pub fn problems(form: &Form, pending: &Pending) -> Vec<FieldError> {
    let mut all = pending.errors();
    all.extend(validate(form));
    all
}

const SPAN_LIMIT: u64 = u64::MAX / (31 * 24 * 3600);

/// A duration as the core reads it: whole hours, days, weeks or months.
fn span_error(raw: &str) -> Option<String> {
    let split = raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len());
    let (digits, suffix) = raw.split_at(split);
    if !matches!(suffix, "h" | "d" | "w" | "mo") {
        return Some("Use hours, days, weeks or months.".into());
    }
    match digits.parse::<u64>() {
        Err(_) => Some("Type a whole number.".into()),
        Ok(amount) if amount > SPAN_LIMIT => Some("This is too long.".into()),
        Ok(_) => None,
    }
}

fn span_is_zero(raw: &str) -> bool {
    Span::parse(raw).is_some_and(|span| span.amount == 0)
}

/// The sending interval as the core reads it: whole minutes or hours, 5 minutes to 24 hours.
fn interval_error(raw: &str) -> Option<String> {
    let bad = || Some("Use whole minutes or hours, from 5 minutes to 24 hours.".to_owned());
    let (digits, hours) = match (raw.strip_suffix('m'), raw.strip_suffix('h')) {
        (Some(digits), _) => (digits, false),
        (_, Some(digits)) => (digits, true),
        _ => return bad(),
    };
    if digits.is_empty()
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return bad();
    }
    let Ok(amount) = digits.parse::<u32>() else {
        return bad();
    };
    let Some(minutes) = (if hours {
        amount.checked_mul(60)
    } else {
        Some(amount)
    }) else {
        return bad();
    };
    if (5..=24 * 60).contains(&minutes) {
        None
    } else {
        bad()
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
    let numeric_last = !last.is_empty() && last.bytes().all(|byte| byte.is_ascii_digit());
    raw.len() <= 253 && raw.split('.').all(label_ok) && !numeric_last
}

/// A `host:port` as the core reads it.
fn probe_error(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return Some("Type the address that answers only on the company VPN, as host:port.".into());
    }
    let ok = raw.rsplit_once(':').is_some_and(|(host, port)| {
        let port_ok = !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port != 0);
        let host_ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(inner) => inner.parse::<std::net::Ipv6Addr>().is_ok(),
            None => host.parse::<std::net::Ipv4Addr>().is_ok() || dns_name_ok(host),
        };
        port_ok && host_ok
    });
    (!ok).then(|| {
        "Type host:port, such as 10.0.0.1:443. Put brackets around an IPv6 address.".into()
    })
}

fn utc_timestamp(text: &str) -> bool {
    text.ends_with('Z') && chrono::DateTime::parse_from_rfc3339(text).is_ok()
}

/// Why the core or a client would refuse this requirement for this output, if it would.
fn requirement_error(control: &Control, requirement: &Requirement) -> Option<String> {
    match requirement {
        Requirement::Reported => None,
        Requirement::Values(values) if values.is_empty() => {
            Some("Choose a result, or Not required.".into())
        }
        Requirement::Values(values) => {
            let allowed = |value: &String| match &control.output {
                Output::Choices(outputs) => outputs.contains(value),
                Output::Timestamp { nullable, values } => {
                    values.contains(value) || utc_timestamp(value) || (value == "null" && *nullable)
                }
                Output::Integer { values, .. } => values.contains(value),
                Output::Unreadable => true,
            };
            values.iter().find(|value| !allowed(value)).map(|value| {
                format!(
                    "{} cannot be required for this check.",
                    value_label(control.builtin_id(), value, true)
                )
            })
        }
        Requirement::Max(number) | Requirement::Min(number) => {
            match control.output.number_range() {
                None => Some("This check reports no number.".into()),
                Some((min, max)) if !(min..=max).contains(number) => {
                    Some(format!("Type a whole number from {min} to {max}."))
                }
                Some(_) => None,
            }
        }
    }
}

/// What the gateway and the clients would refuse in a manifest, for the parts the form edits.
/// The limits come from the core's manifest checks and from the client's list of built-in checks.
pub fn validate(form: &Form) -> Vec<FieldError> {
    let mut errors = Vec::new();
    let mut add = |field: Field, message: String| errors.push(FieldError { field, message });
    for (field, raw) in [
        (Field::MaxAge, &form.max_age),
        (Field::Retention, &form.retention),
        (Field::UnknownGrace, &form.unknown_grace),
    ] {
        if let Some(message) = span_error(raw) {
            add(field, message);
        }
    }
    if span_error(&form.unknown_grace).is_none() && span_is_zero(&form.unknown_grace) {
        add(Field::UnknownGrace, "Type more than zero.".into());
    }
    if let Some(schedule) = &form.schedule {
        if let Some(message) = interval_error(&schedule.interval) {
            add(Field::Interval, message);
        }
        match schedule.mode.as_str() {
            "vpn" => {
                if let Some(message) = probe_error(&schedule.probe) {
                    add(Field::VpnProbe, message);
                }
                if !schedule.name.is_empty() && !dns_name_ok(&schedule.name) {
                    add(
                        Field::VpnProbeName,
                        "Type a DNS name such as vpn.example.org, not an IP address.".into(),
                    );
                }
            }
            "always" => {
                if !schedule.probe.is_empty() || !schedule.name.is_empty() {
                    add(
                        Field::Send,
                        "Always sends on any network, so it takes no VPN address.".into(),
                    );
                }
            }
            _ => add(
                Field::Send,
                "Choose Always or Only on the company VPN.".into(),
            ),
        }
    }
    let mut seen = BTreeSet::new();
    for control in &form.controls {
        let id = || Field::Id(control.id.clone());
        if control.id.is_empty() || !seen.insert(control.id.as_str()) {
            add(id(), "Every check needs its own ID.".into());
        }
        if !control.id_locked() {
            add(id(), "The check must be builtin:<name>@<version>.".into());
        } else if builtin(&control.id).is_none()
            || control.check != format!("builtin:{}@1", control.id)
        {
            let message = match builtin(control.builtin_id()) {
                Some(known) if known.id != control.id => format!(
                    "A built-in check keeps its ID. Clients run {} only as {}.",
                    control.check, known.id
                ),
                _ => format!("No client runs {}.", control.check),
            };
            add(id(), message);
        }
        if let Some(message) = span_error(&control.grace) {
            add(Field::Grace(control.id.clone()), message);
        }
        for os in Os::ALL {
            if let Some(message) = requirement_error(control, control.requirement(os)) {
                add(Field::Requirement(control.id.clone(), os), message);
            }
        }
    }
    errors
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

/// Sets a value of the [schedule] table. Empty text removes the key.
pub fn set_schedule(text: &str, key: &str, value: &str) -> Result<String, String> {
    let mut document = document(text)?;
    let table = schedule_table(&mut document)?;
    if value.is_empty() && key != "mode" && key != "interval" {
        table.remove(key);
    } else {
        put(table, key, Value::from(value));
    }
    Ok(document.to_string())
}

fn schedule_table(document: &mut DocumentMut) -> Result<&mut dyn TableLike, String> {
    if document.get("schedule").is_none() {
        let mut table = Table::new();
        table.insert("mode", Item::Value("always".into()));
        table.insert("interval", Item::Value("1h".into()));
        document.insert("schedule", Item::Table(table));
    }
    document
        .get_mut("schedule")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| "schedule is not a table".to_owned())
}

/// Chooses how devices send. "always" takes no probe, as the core demands.
pub fn set_send_mode(text: &str, mode: &str) -> Result<String, String> {
    let mut document = document(text)?;
    let table = schedule_table(&mut document)?;
    put(table, "mode", Value::from(mode));
    if mode == "always" {
        table.remove("vpn_probe");
        table.remove("vpn_probe_name");
    } else if table.get("vpn_probe").is_none() {
        table.insert("vpn_probe", Item::Value("".into()));
    }
    Ok(document.to_string())
}

fn control_table(document: &mut DocumentMut, index: usize) -> Result<&mut Table, String> {
    document
        .get_mut("control")
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|tables| tables.get_mut(index))
        .ok_or_else(|| "This check is no longer in the manifest".to_owned())
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
    if value.is_empty() && matches!(key, "source_ref" | "rationale") {
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
    table.insert("source", Item::Value("company_policy".into()));
    table.insert("check", Item::Value(format!("builtin:{id}@1").into()));
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
