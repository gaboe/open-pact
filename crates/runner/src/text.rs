//! Plain-words wording for CLI and gateway JSON. No UI code lives here.

use crate::client::{Issue, Status};
use chrono::{DateTime, Local, TimeDelta, TimeZone, Utc};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Info,
    Idle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Headline {
    pub tone: Tone,
    pub heading: String,
    pub detail: String,
}

pub fn short_hash(hash: &str) -> String {
    hash.strip_prefix("sha256:")
        .unwrap_or(hash)
        .chars()
        .take(12)
        .collect()
}

pub fn readable_time<Z: TimeZone>(text: &str, zone: &Z) -> String
where
    Z::Offset: std::fmt::Display,
{
    DateTime::parse_from_rfc3339(text).map_or_else(
        |_| text.to_owned(),
        |time| {
            time.with_timezone(zone)
                .format("%-d %b %Y, %H:%M")
                .to_string()
        },
    )
}

pub fn readable_local(text: &str) -> String {
    readable_time(text, &Local)
}

pub fn humanize(id: &str) -> String {
    if id.eq_ignore_ascii_case("id") {
        return "ID".into();
    }
    let spaced = id.replace('_', " ");
    let mut chars = spaced.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// "55m" reads as "55 min", "2h" as "2 h", "7d" as "7 days". Other text stays as it is.
pub fn duration_text(text: &str) -> String {
    let split = text.len().saturating_sub(1);
    let (number, unit) = text.split_at_checked(split).unwrap_or((text, ""));
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return text.to_owned();
    }
    match unit {
        "s" => format!("{number} s"),
        "m" => format!("{number} min"),
        "h" => format!("{number} h"),
        "d" => format!("{number} days"),
        _ => text.to_owned(),
    }
}

pub fn plain_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(true) => "on".into(),
        Value::Bool(false) => "off".into(),
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .map(plain_value)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

pub fn devices_summary(counts: &Value) -> String {
    if !counts.is_object() {
        return "Not reported".into();
    }
    [
        ("pending", "waiting"),
        ("approved", "approved"),
        ("revoked", "revoked"),
    ]
    .iter()
    .map(|(key, label)| format!("{} {label}", counts[*key].as_u64().unwrap_or(0)))
    .collect::<Vec<_>>()
    .join(" · ")
}

pub fn reasons_text(reasons: Option<&Value>) -> String {
    reasons.map(plain_value).unwrap_or_default()
}

pub fn result_text(result: Option<&Value>) -> String {
    let text = result.map(plain_value).unwrap_or_default();
    if text.is_empty() {
        "No result yet".into()
    } else {
        text
    }
}

pub fn result_tone(result: &str) -> Tone {
    let lower = result.to_lowercase();
    if lower.contains("denied") || lower.contains("refused") {
        Tone::Bad
    } else if lower.contains("warning") {
        Tone::Warn
    } else if lower.contains("accepted") {
        Tone::Good
    } else {
        Tone::Idle
    }
}

pub fn headline(status: &Status) -> Headline {
    let last = status.last_claim.as_ref().map(|claim| {
        format!(
            "Last result {}, {}.",
            readable_local(&plain_value(&claim["response_at"])),
            plain_value(&claim["response"])
        )
    });
    let unchecked = status.current_compliance.starts_with("unknown");
    // A VPN probe that failed is not something to fix on this device.
    let off_vpn = status.issues.iter().any(is_vpn_probe);
    let count = status
        .issues
        .iter()
        .filter(|issue| !is_vpn_probe(issue))
        .count();
    match status.verdict.as_str() {
        "no_known_problem" => Headline {
            tone: Tone::Good,
            heading: "All good".into(),
            detail: last.unwrap_or_else(|| "No result saved on this device yet.".into()),
        },
        "action_needed" => Headline {
            tone: Tone::Warn,
            heading: match (count, off_vpn) {
                (0, true) => "Not on the company VPN".into(),
                (0, false) => "Action needed".into(),
                (1, false) => "Fix 1 thing".into(),
                (n, false) => format!("Fix {n} things"),
                (1, true) => "Fix 1 thing · not on VPN".into(),
                (n, true) => format!("Fix {n} things · not on VPN"),
            },
            detail: [
                last,
                unchecked.then(|| "Not checked again since then.".into()),
                Some("After a fix, check again.".into()),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" "),
        },
        "alarm" => Headline {
            tone: Tone::Bad,
            heading: "Tell IT now".into(),
            detail: status
                .issues
                .first()
                .and_then(|issue| issue.fix.clone())
                .unwrap_or_else(|| "Keep the last checkpoint and tell IT.".into()),
        },
        _ => Headline {
            tone: Tone::Idle,
            heading: "Not checked yet".into(),
            detail: "Press Check now to see where this device stands.".into(),
        },
    }
}

pub fn approval_text(state: Option<&str>, live: bool) -> String {
    match (state, live) {
        (Some("approved"), true) => "Approved".into(),
        (Some("approved"), false) => "Approved · last known, not confirmed now".into(),
        (Some("pending"), _) => "Waiting for IT to approve".into(),
        (Some("revoked"), _) => "Removed by IT".into(),
        (Some(other), _) => humanize(other),
        (None, _) => "Not enrolled".into(),
    }
}

pub fn job_text(raw: &str) -> String {
    let lower = raw.to_lowercase();
    if lower.starts_with("no installation record") {
        "Not installed".into()
    } else if lower.contains("not checked") {
        if lower.starts_with("installation recorded") {
            "Installed · not checked yet".into()
        } else {
            "Not checked yet".into()
        }
    } else if lower.starts_with("unknown") {
        "Unknown".into()
    } else {
        let state = lower.strip_suffix("; os checked now").unwrap_or(&lower);
        match state {
            "out of date" => "Needs update".into(),
            "missing" => "Needs installation".into(),
            "installed and current" => "Installed".into(),
            "not installed" => "Not installed".into(),
            "leftover job or saved state" => "Leftover job".into(),
            _ => humanize(raw),
        }
    }
}

/// True when the job needs the "Install job" button.
pub fn job_needs_install(raw: &str) -> bool {
    let lower = raw.to_lowercase();
    lower.starts_with("out of date") || lower.starts_with("missing")
}

pub fn agreement_text(raw: &str) -> Option<String> {
    let lower = raw.to_lowercase();
    if lower.starts_with("yes") {
        Some("Same list as the company".into())
    } else if lower.starts_with("no") {
        Some("The company list is different".into())
    } else {
        None
    }
}

pub fn deadline_text(issue: &Issue) -> Option<String> {
    let lower = issue.deadline.to_lowercase();
    (!lower.is_empty() && !lower.contains("unavailable") && !lower.starts_with("unknown"))
        .then(|| issue.deadline.clone())
}

/// What an action item can do with a button. The CLI names the command of each item, so the
/// choice follows the end of `Issue::command`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueAction {
    /// `schedule on`
    InstallJob,
    /// `schedule off`
    TurnOffJob,
    /// `status --online`
    Retry,
    /// `accept`: the manifest review.
    Review,
}

impl IssueAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::InstallJob => "Install job",
            Self::TurnOffJob => "Turn off job",
            Self::Retry => "Retry",
            Self::Review => "Review changes",
        }
    }
}

/// The CLI gives a failed VPN probe the command `check`, which would send a claim. A probe is
/// retried with `status --online`. The status JSON has no stable kind field, so this is the one
/// item found by its message.
pub fn is_vpn_probe(issue: &Issue) -> bool {
    issue.message.starts_with("The signed VPN probe failed")
}

pub fn issue_action(issue: &Issue) -> Option<IssueAction> {
    if is_vpn_probe(issue) {
        return Some(IssueAction::Retry);
    }
    let command = issue.command.as_deref()?;
    let ends = |action: &str| command.ends_with(&format!(" {action}"));
    if ends("schedule on") {
        Some(IssueAction::InstallJob)
    } else if ends("schedule off") {
        Some(IssueAction::TurnOffJob)
    } else if ends("status --online") {
        Some(IssueAction::Retry)
    } else if ends("accept") {
        Some(IssueAction::Review)
    } else {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueView {
    pub title: String,
    pub fix: Option<String>,
    pub note: Option<String>,
    pub action: Option<IssueAction>,
}

/// A gateway answer such as `Gateway at <time>: <id> = <value>, <required> required, access ends in 19h`.
struct Finding<'a> {
    at: &'a str,
    id: &'a str,
    value: &'a str,
    required: &'a str,
    span: Option<&'a str>,
}

fn parse_finding(message: &str) -> Option<Finding<'_>> {
    let (at, body) = message.strip_prefix("Gateway at ")?.split_once(": ")?;
    let (id, rest) = body.split_once(" = ")?;
    if id.contains(' ') {
        return None;
    }
    let (value, rest) = rest.split_once(", ")?;
    let (required, tail) = rest.split_once(" required")?;
    Some(Finding {
        at,
        id,
        value,
        required,
        span: tail.strip_prefix(", access ends in "),
    })
}

/// "19h", "30m", "3d" or "2d 5h" as the gateway prints the time left.
fn span_delta(span: &str) -> Option<TimeDelta> {
    let mut total = TimeDelta::zero();
    let mut parts = 0;
    for part in span.split(' ') {
        let (number, unit) = part.split_at(part.len().checked_sub(1)?);
        let number: i64 = number.parse().ok()?;
        total += match unit {
            "m" => TimeDelta::try_minutes(number)?,
            "h" => TimeDelta::try_hours(number)?,
            "d" => TimeDelta::try_days(number)?,
            _ => return None,
        };
        parts += 1;
    }
    (1..=2).contains(&parts).then_some(total)
}

const MEASURES: &[(&str, &str)] = &[
    (
        "password_min_length",
        "Password policy allows {} characters",
    ),
    ("os_patch_age_days", "System updates are {} days old"),
    (
        "antimalware_signature_age_days",
        "Antimalware signatures are {} days old",
    ),
    (
        "antimalware_full_scan_age_days",
        "The last full malware scan was {} days ago",
    ),
    ("log_oldest_record_days", "The event log covers {} days"),
];

const CONTROL_NAMES: &[(&str, &str)] = &[
    ("os_auto_updates", "Automatic updates"),
    ("antimalware_realtime", "Real-time malware protection"),
    ("antimalware_active_threats", "Active threats"),
    ("disk_encryption", "Disk encryption"),
    ("firewall", "Firewall"),
    ("screen_lock", "Screen lock"),
    ("os_supported", "Operating system support"),
    ("os_patch_age_days", "System update age"),
    ("password_set", "Password"),
    ("password_min_length", "Password length"),
    ("auto_login", "Automatic login"),
    ("secure_boot", "Secure boot"),
    ("antimalware_active", "Malware protection"),
    ("preboot_auth", "Boot-time sign-in"),
    ("antimalware_signature_age_days", "Malware signature age"),
    ("antimalware_full_scan_age_days", "Full malware scan age"),
    ("web_protection", "Web protection"),
    ("log_oldest_record_days", "Event log history"),
    ("process_audit", "Process auditing"),
    ("remote_wipe", "Remote wipe"),
    ("powershell_logging", "PowerShell logging"),
    ("log_cleared", "Cleared event log"),
];

fn finding_title(finding: &Finding) -> String {
    let name = CONTROL_NAMES
        .iter()
        .find(|(id, _)| *id == finding.id)
        .map_or_else(|| humanize(finding.id), |(_, name)| (*name).to_owned());
    if finding.value == "unknown" {
        return format!("{name} could not be read");
    }
    let measure = MEASURES
        .iter()
        .find(|(id, _)| *id == finding.id)
        .map(|(_, sentence)| sentence.replace("{}", finding.value));
    if let Some(sentence) = measure {
        if let Some(limit) = finding.required.strip_prefix(">= ") {
            return format!("{sentence}, at least {limit} needed");
        }
        if let Some(limit) = finding.required.strip_prefix("<= ") {
            return format!("{sentence}, at most {limit} allowed");
        }
    }
    let required = match finding.required {
        "le_5min" => "5 minutes or less".to_owned(),
        other => other.replace('_', " "),
    };
    format!("{name} is {}, it must be {required}", finding.value)
}

/// The words for one action item. The raw CLI text stays in the command log.
pub fn issue_view<Z: TimeZone>(issue: &Issue, now: DateTime<Utc>, zone: &Z) -> IssueView
where
    Z::Offset: std::fmt::Display,
{
    let action = issue_action(issue);
    let Some(finding) = parse_finding(&issue.message) else {
        let message = issue.message.as_str();
        let title = message
            .strip_prefix("Gateway at ")
            .and_then(|rest| rest.split_once(": "))
            .map_or(message, |(_, text)| text);
        return IssueView {
            title: title.to_owned(),
            fix: issue.fix.clone(),
            note: deadline_text(issue),
            action,
        };
    };
    let at = DateTime::parse_from_rfc3339(finding.at)
        .ok()
        .map(|time| time.to_utc());
    let when = |time: DateTime<Utc>| time.with_timezone(zone).format("%-d %b, %H:%M").to_string();
    let note = match (finding.span, at) {
        (Some(span), Some(at)) => span_delta(span).map(|left| {
            let deadline = at + left;
            if deadline < now {
                format!("Access ended {}", when(deadline))
            } else {
                format!("Access ends {} unless fixed", when(deadline))
            }
        }),
        (None, Some(at)) => Some(format!("Refused by the gateway on {}", when(at))),
        _ => None,
    };
    IssueView {
        title: finding_title(&finding),
        fix: issue.fix.clone(),
        note,
        action,
    }
}

/// `issue_view` in the time zone of this computer. `now` is an RFC 3339 time that a fixture sets
/// so that a picture does not change with the day; the app passes `None`.
pub fn issue_view_local(issue: &Issue, now: Option<&str>) -> IssueView {
    let now = now
        .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
        .map_or_else(Utc::now, |time| time.to_utc());
    issue_view(issue, now, &Local)
}

pub fn result_control(control: &Value) -> (String, String, bool) {
    let title = control["title"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| humanize(&plain_value(&control["id"])));
    (
        title,
        plain_value(&control["value"]),
        control["ok"].as_bool().unwrap_or(true),
    )
}

pub fn step_detail(detail: Option<&Value>) -> String {
    match detail {
        Some(Value::Object(map)) => map
            .get("device_code")
            .map(|code| format!("Device code {}. Send it to IT.", plain_value(code)))
            .unwrap_or_default(),
        Some(other) => plain_value(other),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;
    use serde_json::json;

    fn status(verdict: &str, issues: usize) -> Status {
        let mut status: Status =
            serde_json::from_str(include_str!("../../../tests/fixtures/status.json")).unwrap();
        status.verdict = verdict.into();
        status.issues.truncate(issues);
        status
    }

    #[test]
    fn hashes_show_twelve_hex_digits_and_keep_short_ones() {
        assert_eq!(
            short_hash(&format!("sha256:{}", "ab12".repeat(16))),
            "ab12ab12ab12"
        );
        assert_eq!(short_hash("sha256:97e1594a"), "97e1594a");
    }

    #[test]
    fn times_are_readable_in_the_given_zone_and_other_text_is_kept() {
        let prague = FixedOffset::east_opt(3600).unwrap();
        assert_eq!(
            readable_time("2026-11-19T12:00:00Z", &prague),
            "19 Nov 2026, 13:00"
        );
        assert_eq!(readable_time("10:53", &prague), "10:53");
    }

    #[test]
    fn durations_read_in_plain_units() {
        assert_eq!(duration_text("55m"), "55 min");
        assert_eq!(duration_text("2h"), "2 h");
        assert_eq!(
            duration_text("10 characters or more"),
            "10 characters or more"
        );
        assert_eq!(duration_text("m"), "m");
        assert_eq!(duration_text(""), "");
    }

    #[test]
    fn device_counts_read_as_words() {
        let counts = json!({"pending": 1, "approved": 2, "revoked": 0});
        assert_eq!(
            devices_summary(&counts),
            "1 waiting · 2 approved · 0 revoked"
        );
        assert_eq!(devices_summary(&json!(null)), "Not reported");
    }

    #[test]
    fn reasons_join_as_text_and_empty_means_nothing() {
        assert_eq!(reasons_text(Some(&json!([]))), "");
        assert_eq!(reasons_text(None), "");
        assert_eq!(
            reasons_text(Some(&json!([
                "password 4, at least 10 needed",
                "",
                "disk off"
            ]))),
            "password 4, at least 10 needed, disk off"
        );
        assert_eq!(result_text(None), "No result yet");
    }

    #[test]
    fn headlines_keep_uncertainty_in_plain_words() {
        let action = headline(&status("action_needed", 2));
        assert_eq!(action.heading, "Fix 2 things");
        assert_eq!(action.tone, Tone::Warn);
        assert!(action.detail.contains("Not checked again since then."));
        assert_eq!(headline(&status("action_needed", 1)).heading, "Fix 1 thing");
        assert_eq!(headline(&status("no_known_problem", 0)).heading, "All good");
        assert_eq!(headline(&status("alarm", 0)).tone, Tone::Bad);
        assert_eq!(headline(&status("unknown", 0)).heading, "Not checked yet");
    }

    #[test]
    fn status_fields_map_to_human_wording() {
        assert_eq!(
            approval_text(Some("approved"), false),
            "Approved · last known, not confirmed now"
        );
        assert_eq!(
            approval_text(Some("pending"), true),
            "Waiting for IT to approve"
        );
        assert_eq!(job_text("OS job not checked"), "Not checked yet");
        assert_eq!(
            job_text("installation recorded; OS job not checked"),
            "Installed · not checked yet"
        );
        assert_eq!(agreement_text("unknown; gateway not checked"), None);
        assert_eq!(
            agreement_text("yes; gateway checked now").unwrap(),
            "Same list as the company"
        );
        let issue = &status("action_needed", 1).issues[0];
        assert_eq!(deadline_text(issue), None);
    }

    #[test]
    fn control_results_and_join_details_read_plainly() {
        let (title, value, ok) =
            result_control(&json!({"id": "disk_encryption", "value": true, "ok": true}));
        assert_eq!(
            (title.as_str(), value.as_str(), ok),
            ("Disk encryption", "on", true)
        );
        assert_eq!(
            step_detail(Some(&json!({"device_code": "0a1b2c3d"}))),
            "Device code 0a1b2c3d. Send it to IT."
        );
    }

    fn issue(message: &str, command: Option<&str>) -> Issue {
        Issue {
            urgency: "action".into(),
            message: message.into(),
            fix: Some("Fix it.".into()),
            command: command.map(str::to_owned),
            deadline: "Exact deadline unavailable.".into(),
        }
    }

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text).unwrap().to_utc()
    }

    #[test]
    fn gateway_findings_read_in_plain_words_with_local_dates() {
        let prague = FixedOffset::east_opt(3600).unwrap();
        let now = at("2026-11-16T15:00:00Z");
        let view = issue_view(
            &issue(
                "Gateway at 2026-11-16T14:10:35Z: password_min_length = 4, >= 10 required, access ends in 19h",
                Some("open-pact-client check"),
            ),
            now,
            &prague,
        );
        assert_eq!(
            view.title,
            "Password policy allows 4 characters, at least 10 needed"
        );
        assert_eq!(
            view.note.as_deref(),
            Some("Access ends 17 Nov, 10:10 unless fixed")
        );
        assert_eq!(view.action, None);
        let view = issue_view(
            &issue(
                "Gateway at 2026-11-16T14:10:35Z: antimalware_signature_age_days = 4, <= 3 required, access ends in 19h",
                None,
            ),
            now,
            &prague,
        );
        assert_eq!(
            view.title,
            "Antimalware signatures are 4 days old, at most 3 allowed"
        );
        let view = issue_view(
            &issue(
                "Gateway at 2026-11-16T09:00:00Z: firewall = off, on required, access ends in 2h",
                None,
            ),
            now,
            &prague,
        );
        assert_eq!(view.title, "Firewall is off, it must be on");
        assert_eq!(view.note.as_deref(), Some("Access ended 16 Nov, 12:00"));
        let view = issue_view(
            &issue(
                "Gateway at 2026-11-16T09:00:00Z: disk_encryption = unknown, full required",
                None,
            ),
            now,
            &prague,
        );
        assert_eq!(view.title, "Disk encryption could not be read");
        assert_eq!(
            view.note.as_deref(),
            Some("Refused by the gateway on 16 Nov, 10:00")
        );
    }

    #[test]
    fn other_items_keep_their_message_and_get_a_button_by_command() {
        let prague = FixedOffset::east_opt(3600).unwrap();
        let now = at("2026-11-16T15:00:00Z");
        let job = issue(
            "Automatic sending is on, but its job needs installation or update.",
            Some("open-pact-client schedule on"),
        );
        let view = issue_view(&job, now, &prague);
        assert_eq!(view.title, job.message);
        assert_eq!(view.action, Some(IssueAction::InstallJob));
        assert_eq!(
            issue_action(&issue(
                "x",
                Some("'/a b/open-pact-client' --home /h accept")
            )),
            Some(IssueAction::Review)
        );
        assert_eq!(
            issue_action(&issue("x", Some("open-pact-client status --online"))),
            Some(IssueAction::Retry)
        );
        assert_eq!(
            issue_action(&issue("x", Some("open-pact-client check"))),
            None
        );
        assert_eq!(
            issue_action(&issue("x", Some("open-pact-client status"))),
            None
        );
        let probe = issue(
            "The signed VPN probe failed.",
            Some("open-pact-client check"),
        );
        assert_eq!(issue_action(&probe), Some(IssueAction::Retry));
    }

    #[test]
    fn a_failed_vpn_probe_is_not_counted_as_a_fix() {
        let mut shown = status("action_needed", 2);
        shown.issues.push(issue(
            "The signed VPN probe failed.",
            Some("open-pact-client check"),
        ));
        assert_eq!(headline(&shown).heading, "Fix 2 things · not on VPN");
        shown.issues.truncate(1);
        shown.issues.remove(0);
        shown.issues.push(issue(
            "The signed VPN probe failed.",
            Some("open-pact-client check"),
        ));
        assert_eq!(headline(&shown).heading, "Not on the company VPN");
    }

    #[test]
    fn job_states_read_as_needs_update_or_installation() {
        assert_eq!(job_text("out of date; OS checked now"), "Needs update");
        assert_eq!(job_text("missing; OS checked now"), "Needs installation");
        assert_eq!(
            job_text("installed and current; OS checked now"),
            "Installed"
        );
        assert!(job_needs_install("out of date; OS checked now"));
        assert!(!job_needs_install("installed and current; OS checked now"));
    }
}
