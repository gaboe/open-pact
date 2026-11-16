//! Plain-words wording for CLI and gateway JSON. No UI code lives here.

use crate::client::{Issue, Status};
use chrono::{DateTime, Local, TimeZone};
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
    let count = status.issues.len();
    match status.verdict.as_str() {
        "no_known_problem" => Headline {
            tone: Tone::Good,
            heading: "All good".into(),
            detail: last.unwrap_or_else(|| "No result saved on this device yet.".into()),
        },
        "action_needed" => Headline {
            tone: Tone::Warn,
            heading: match count {
                0 => "Action needed".into(),
                1 => "Fix 1 thing".into(),
                n => format!("Fix {n} things"),
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
        humanize(raw)
    }
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
}
