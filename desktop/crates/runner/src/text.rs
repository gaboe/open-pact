//! Plain-words wording for CLI and gateway JSON. No UI code lives here.

use crate::zone;
use open_pact_core::timestamp::parse_rfc3339;
use serde_json::Value;
use time::OffsetDateTime;
use time::macros::format_description;

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

/// "19 Nov 2026, 13:00": `text` as an RFC 3339 time, moved into the zone `zone` gives. Other text
/// stays as it is.
pub fn readable_time(text: &str, zone: impl Fn(OffsetDateTime) -> OffsetDateTime) -> String {
    parse_rfc3339(text)
        .and_then(|time| {
            zone(time)
                .format(format_description!(
                    "[day padding:none] [month repr:short] [year], [hour]:[minute]"
                ))
                .ok()
        })
        .unwrap_or_else(|| text.to_owned())
}

pub fn readable_local(text: &str) -> String {
    readable_time(text, zone::to_local)
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
    use serde_json::json;
    use time::UtcOffset;

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
        let prague = |time: OffsetDateTime| time.to_offset(UtcOffset::from_hms(1, 0, 0).unwrap());
        assert_eq!(
            readable_time("2026-11-19T12:00:00Z", prague),
            "19 Nov 2026, 13:00"
        );
        assert_eq!(readable_time("10:53", prague), "10:53");
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
    }

    #[test]
    fn join_details_read_plainly() {
        assert_eq!(
            step_detail(Some(&json!({"device_code": "0a1b2c3d"}))),
            "Device code 0a1b2c3d. Send it to IT."
        );
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
