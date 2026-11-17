//! The check results the gateway stores. The Results screen reads them with
//! `claims list --json` and `claims show <id> --json`. This module holds the filters, the JSON
//! shapes and the plain wording. No UI code lives here.

use crate::admin::Admin;
use crate::manifest::{self, Span};
use crate::text::{Tone, humanize, readable_local, short_hash};
use chrono::{Duration, SecondsFormat};
use serde::Deserialize;
use serde_json::Value;

pub use chrono::{DateTime, Utc};

/// The time every list and its `--since` flag count from.
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// The quiet note under the table when the gateway cannot read some old results.
pub fn unreadable_text(count: u64) -> Option<String> {
    match count {
        0 => None,
        1 => Some("1 older result can no longer be read.".into()),
        many => Some(format!("{many} older results can no longer be read.")),
    }
}

/// How many results one list asks for.
pub const LIMIT: u32 = 200;

/// What the Results screen says when the gateway does not know the `claims` command.
pub const OLD_GATEWAY: &str = "The gateway is older than 0.7; results need gateway 0.7 or later.";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ResultFilter {
    #[default]
    All,
    Accepted,
    Warnings,
    Denied,
}

impl ResultFilter {
    pub const ALL: [Self; 4] = [Self::All, Self::Accepted, Self::Warnings, Self::Denied];

    /// The value of `--result`, or none for every result.
    pub fn flag(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Accepted => Some("accepted"),
            Self::Warnings => Some("warnings"),
            Self::Denied => Some("denied"),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Accepted => "Accepted",
            Self::Warnings => "Warnings",
            Self::Denied => "Denied",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Period {
    Day,
    Week,
    Month,
    #[default]
    All,
}

impl Period {
    pub const ALL: [Self; 4] = [Self::Day, Self::Week, Self::Month, Self::All];

    pub fn label(self) -> &'static str {
        match self {
            Self::Day => "24 hours",
            Self::Week => "7 days",
            Self::Month => "30 days",
            Self::All => "All",
        }
    }

    /// The start of the period as `--since` takes it, or none for all results.
    pub fn since(self, now: DateTime<Utc>) -> Option<String> {
        let length = match self {
            Self::Day => Duration::hours(24),
            Self::Week => Duration::days(7),
            Self::Month => Duration::days(30),
            Self::All => return None,
        };
        Some((now - length).to_rfc3339_opts(SecondsFormat::Secs, true))
    }
}

/// What the filter bar holds. `device` is a device code.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filters {
    pub device: Option<String>,
    pub result: ResultFilter,
    pub period: Period,
}

impl Filters {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// The words after `open-pact-gateway` that list the matching results.
    pub fn list_words(&self, now: DateTime<Utc>) -> Vec<String> {
        let mut words: Vec<String> = ["claims", "list", "--json"].map(String::from).into();
        if let Some(device) = &self.device {
            words.extend(["--device".to_owned(), device.clone()]);
        }
        if let Some(result) = self.result.flag() {
            words.extend(["--result".to_owned(), result.to_owned()]);
        }
        if let Some(since) = self.period.since(now) {
            words.extend(["--since".to_owned(), since]);
        }
        words.extend(["--limit".to_owned(), LIMIT.to_string()]);
        words
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Claim {
    pub id: u64,
    pub received_at: String,
    pub device: String,
    #[serde(default)]
    pub device_note: Option<String>,
    pub manifest_hash: String,
    /// `accepted`, `warnings`, `denied` or none for a result the gateway cannot judge.
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub failed_controls: Vec<String>,
}

/// The short code of a device pseudonym, the same 12 characters the Devices screen shows.
pub fn device_code(device: &str) -> String {
    device
        .strip_prefix("pseudonym:")
        .unwrap_or(device)
        .chars()
        .take(12)
        .collect()
}

impl Claim {
    pub fn code(&self) -> String {
        device_code(&self.device)
    }

    pub fn failed_text(&self) -> String {
        failed_checks_text(&self.failed_controls)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ClaimList {
    #[serde(default)]
    pub claims: Vec<Claim>,
    /// Results the gateway can no longer read, because their month key is gone.
    #[serde(default)]
    pub unreadable: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    Pass,
    Fail,
    NotRequired,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClaimControl {
    pub id: String,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub required: Option<String>,
    pub status: ControlStatus,
    #[serde(default)]
    pub grace: Option<String>,
    #[serde(default)]
    pub first_failed_at: Option<String>,
    #[serde(default)]
    pub deadline: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClaimDetail {
    pub id: u64,
    pub received_at: String,
    pub device: String,
    #[serde(default)]
    pub device_note: Option<String>,
    pub manifest_hash: String,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub client_version: Option<String>,
    #[serde(default)]
    pub trust_level: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub controls: Vec<ClaimControl>,
}

impl ClaimDetail {
    pub fn code(&self) -> String {
        device_code(&self.device)
    }

    pub fn hash_text(&self) -> String {
        short_hash(&self.manifest_hash)
    }

    /// The controls in the order the panel shows them: failing ones first.
    pub fn ordered(&self) -> Vec<&ClaimControl> {
        order_controls(&self.controls)
    }
}

/// Failing controls first, then unreadable ones, then passing ones, then controls the manifest
/// does not require. Inside a group the gateway's order stays.
pub fn order_controls(controls: &[ClaimControl]) -> Vec<&ClaimControl> {
    let rank = |control: &ClaimControl| match control.status {
        ControlStatus::Fail => 0,
        ControlStatus::Unknown => 1,
        ControlStatus::Pass => 2,
        ControlStatus::NotRequired => 3,
    };
    let mut ordered: Vec<&ClaimControl> = controls.iter().collect();
    ordered.sort_by_key(|control| rank(control));
    ordered
}

/// The plain name of a check. The manifest editor's catalog names a built-in check; any other id
/// stays as the gateway wrote it.
pub fn check_name(id: &str) -> String {
    manifest::builtin(id).map_or_else(|| id.to_owned(), |known| known.name.to_owned())
}

/// Up to three plain names, then "+N" for the rest. A result with no failed check shows a dash.
pub fn failed_checks_text(ids: &[String]) -> String {
    if ids.is_empty() {
        return "–".into();
    }
    let mut text = ids
        .iter()
        .take(3)
        .map(|id| check_name(id))
        .collect::<Vec<_>>()
        .join(", ");
    if ids.len() > 3 {
        text.push_str(&format!(" +{}", ids.len() - 3));
    }
    text
}

/// The tag of a result: its words and its colour.
pub fn result_tag(result: Option<&str>) -> (String, Tone) {
    match result {
        Some("accepted") => ("Accepted".into(), Tone::Good),
        Some("warnings") => ("Warnings".into(), Tone::Warn),
        Some("denied") => ("Denied".into(), Tone::Bad),
        Some(other) => (humanize(other), Tone::Idle),
        None => ("Unknown".into(), Tone::Idle),
    }
}

pub fn status_tag(status: ControlStatus) -> (&'static str, Tone) {
    match status {
        ControlStatus::Pass => ("Pass", Tone::Good),
        ControlStatus::Fail => ("Fail", Tone::Bad),
        ControlStatus::Unknown => ("Unknown", Tone::Warn),
        ControlStatus::NotRequired => ("Not required", Tone::Idle),
    }
}

fn time_or_dash(time: Option<&str>) -> String {
    time.map_or_else(|| "–".into(), readable_local)
}

impl ClaimControl {
    pub fn name(&self) -> String {
        check_name(&self.id)
    }

    pub fn value_text(&self) -> String {
        match &self.value {
            None | Some(Value::Null) => "–".into(),
            Some(Value::String(text)) => manifest::value_label(&self.id, text, false),
            Some(other) => crate::text::plain_value(other),
        }
    }

    /// "<= 30" reads as "≤ 30", a word such as "on" as "On". No manifest to read gives a dash.
    pub fn required_text(&self) -> String {
        let Some(required) = self.required.as_deref() else {
            return "–".into();
        };
        for (ascii, symbol) in [("<=", "≤"), (">=", "≥")] {
            if let Some(limit) = required.strip_prefix(ascii) {
                return format!("{symbol}{limit}");
            }
        }
        manifest::value_label(&self.id, required, false)
    }

    pub fn grace_text(&self) -> String {
        self.grace.as_deref().map_or_else(
            || "–".into(),
            |grace| Span::parse(grace).map_or_else(|| grace.to_owned(), |span| span.short()),
        )
    }

    pub fn first_failed_text(&self) -> String {
        time_or_dash(self.first_failed_at.as_deref())
    }

    pub fn deadline_text(&self) -> String {
        time_or_dash(self.deadline.as_deref())
    }
}

/// The error of a `claims` command. A gateway that does not know the subcommand gets the
/// version hint; any other error stays as the command wrote it.
pub fn explain_error(error: &str) -> String {
    if error.to_lowercase().contains("unrecognized subcommand") {
        OLD_GATEWAY.into()
    } else {
        error.to_owned()
    }
}

impl Admin {
    /// `claims list --json` with the flags the filters need. `now` fixes what "24 hours" means.
    pub fn claims(&self, filters: &Filters, now: DateTime<Utc>) -> Result<ClaimList, String> {
        let words = filters.list_words(now);
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        self.runner
            .json::<ClaimList>(&self.kubectl, &self.gateway_args(&words))
            .map_err(|error| explain_error(&error))
    }

    pub fn claim(&self, id: u64) -> Result<ClaimDetail, String> {
        let id = id.to_string();
        self.runner
            .json::<ClaimDetail>(
                &self.kubectl,
                &self.gateway_args(&["claims", "show", &id, "--json"]),
            )
            .map_err(|error| explain_error(&error))
    }

    /// The command `claims list` runs, for the quiet line under the table.
    pub fn claims_command(filters: &Filters, now: DateTime<Utc>) -> String {
        format!(
            "kubectl exec deploy/open-pact-gateway -- open-pact-gateway {}",
            crate::shell_line(&filters.list_words(now))
        )
    }
}
