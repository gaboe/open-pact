//! The reasons the company gave for not accepting a check, as rows of plain words. The reasons are
//! the gateway's text, written by the `Reason` Display of the core. No UI code lives here.

use crate::manifest::{builtin, value_label};
use crate::status_text::span_delta;
use crate::text::humanize;
use time::OffsetDateTime;
use time::macros::format_description;

/// Where a failing control stands against its grace period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraceState {
    Ended,
    /// The local time when access ends, such as "17 Nov, 10:10".
    EndsAt(String),
}

impl GraceState {
    pub fn text(&self) -> String {
        match self {
            Self::Ended => "Grace ended".into(),
            Self::EndsAt(when) => format!("Grace ends {when}"),
        }
    }
}

/// One reason. A reason this module cannot read keeps its text as `name` and has no `detail`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReasonRow {
    pub name: String,
    pub detail: Option<String>,
    pub grace: Option<GraceState>,
}

impl ReasonRow {
    fn raw(reason: &str) -> Self {
        Self {
            name: reason.to_owned(),
            detail: None,
            grace: None,
        }
    }
}

/// `sent` is the time of the check: "access ends in 19h" counts from it.
pub fn reason_row(
    reason: &str,
    sent: Option<OffsetDateTime>,
    zone: impl Fn(OffsetDateTime) -> OffsetDateTime,
) -> ReasonRow {
    let (body, grace) = match split_grace(reason, sent, zone) {
        Some(split) => split,
        None => return ReasonRow::raw(reason),
    };
    match body_row(body) {
        Some((name, detail)) => ReasonRow {
            name,
            detail: Some(detail),
            grace,
        },
        None => ReasonRow::raw(reason),
    }
}

/// The reason without its grace tail. `None` when the tail names a time this module cannot read.
fn split_grace(
    reason: &str,
    sent: Option<OffsetDateTime>,
    zone: impl Fn(OffsetDateTime) -> OffsetDateTime,
) -> Option<(&str, Option<GraceState>)> {
    if let Some((body, span)) = reason.rsplit_once(", access ends in ") {
        let deadline = sent?.checked_add(span_delta(span)?)?;
        let when = zone(deadline)
            .format(format_description!(
                "[day padding:none] [month repr:short], [hour]:[minute]"
            ))
            .ok()?;
        return Some((body, Some(GraceState::EndsAt(when))));
    }
    if let Some(head) = reason.strip_suffix(" ended") {
        for marker in [", grace ", ", unknown_grace "] {
            if let Some((body, span)) = head.rsplit_once(marker)
                && !span.contains(' ')
            {
                return Some((body, Some(GraceState::Ended)));
            }
        }
    }
    Some((reason, None))
}

fn control_name(id: &str) -> String {
    builtin(id).map_or_else(|| humanize(id), |known| known.name.to_owned())
}

/// A control id is one word of lowercase letters, digits and underscores.
fn is_id(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn body_row(body: &str) -> Option<(String, String)> {
    if body == "client must be \"open-pact-client <major>.<minor>.<patch>\"" {
        return Some((
            "App version".into(),
            "The company cannot read the version this app sent".into(),
        ));
    }
    if let Some((id, rest)) = body.split_once(" = ")
        && is_id(id)
    {
        let (value, required) = rest.split_once(", ")?;
        let required = required.strip_suffix(" required")?;
        return Some((control_name(id), measured(id, value, required)?));
    }
    if let Some((id, os)) = body.split_once(" missing, required on ")
        && is_id(id)
    {
        return Some((control_name(id), format!("Not reported, required on {os}")));
    }
    if let Some((id, _)) =
        body.split_once(" is required by a new manifest that waits for your acceptance")
        && is_id(id)
    {
        return Some((
            control_name(id),
            "A new rule waits for you. Review the changes and sign them".into(),
        ));
    }
    None
}

/// "6 days old, at most 3 allowed" or "Off, must be on".
fn measured(id: &str, value: &str, required: &str) -> Option<String> {
    if value == "unknown" {
        return Some("Could not be read".into());
    }
    for (prefix, words) in [("<= ", "at most {} allowed"), (">= ", "at least {} needed")] {
        if let Some(limit) = required.strip_prefix(prefix) {
            let limit: i64 = limit.parse().ok()?;
            let amount = match value.parse::<i64>() {
                Ok(number) => amount(id, number),
                Err(_) => value_label(id, value, true),
            };
            return Some(format!(
                "{amount}, {}",
                words.replace("{}", &limit.to_string())
            ));
        }
    }
    let wanted = match required.strip_prefix("one of ") {
        Some(list) => format!(
            "one of {}",
            list.split(", ")
                .map(|one| value_label(id, one, true).to_lowercase())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        None => value_label(id, required, true).to_lowercase(),
    };
    Some(format!(
        "{}, must be {wanted}",
        value_label(id, value, true)
    ))
}

fn amount(id: &str, number: i64) -> String {
    let unit = |one: &str, many: &str| format!("{number} {}", if number == 1 { one } else { many });
    if id.ends_with("_age_days") {
        format!("{} old", unit("day", "days"))
    } else if id.ends_with("_days") {
        unit("day", "days")
    } else if id == "password_min_length" {
        unit("character", "characters")
    } else if id == "screen_lock" {
        unit("minute", "minutes")
    } else {
        number.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use open_pact_core::timestamp::parse_rfc3339;
    use time::UtcOffset;

    fn prague(time: OffsetDateTime) -> OffsetDateTime {
        time.to_offset(UtcOffset::from_hms(1, 0, 0).unwrap())
    }

    fn row(reason: &str) -> ReasonRow {
        reason_row(reason, parse_rfc3339("2026-11-16T14:10:35Z"), prague)
    }

    fn read(name: &str, detail: &str, grace: Option<GraceState>) -> ReasonRow {
        ReasonRow {
            name: name.into(),
            detail: Some(detail.into()),
            grace,
        }
    }

    #[test]
    fn the_reasons_of_a_denied_check_read_as_one_row_each() {
        let reasons = [
            "client must be \"open-pact-client <major>.<minor>.<patch>\"",
            "antimalware_signature_age_days = 6, <= 3 required, grace 1d ended",
            "password_min_length = 4, >= 10 required, grace 1d ended",
        ];
        let rows: Vec<_> = reasons.iter().map(|reason| row(reason)).collect();
        assert_eq!(
            rows,
            [
                read(
                    "App version",
                    "The company cannot read the version this app sent",
                    None
                ),
                read(
                    "Antimalware signatures",
                    "6 days old, at most 3 allowed",
                    Some(GraceState::Ended)
                ),
                read(
                    "Password policy",
                    "4 characters, at least 10 needed",
                    Some(GraceState::Ended)
                ),
            ]
        );
    }

    #[test]
    fn a_single_reason_names_its_value_and_requirement() {
        assert_eq!(
            row("firewall = off, on required"),
            read("Firewall", "Off, must be on", None)
        );
        assert_eq!(
            row("disk_encryption = partial, one of full, none required"),
            read(
                "Disk encryption",
                "Partial, must be one of full, none",
                None
            )
        );
        assert_eq!(
            row("password_set = unknown, yes required, unknown_grace 7d ended"),
            read("Password set", "Could not be read", Some(GraceState::Ended))
        );
    }

    #[test]
    fn a_running_grace_ends_at_a_local_time() {
        assert_eq!(
            row("password_min_length = 4, >= 10 required, access ends in 19h"),
            read(
                "Password policy",
                "4 characters, at least 10 needed",
                Some(GraceState::EndsAt("17 Nov, 10:10".into()))
            )
        );
        assert_eq!(
            GraceState::EndsAt("17 Nov, 10:10".into()).text(),
            "Grace ends 17 Nov, 10:10"
        );
    }

    #[test]
    fn a_reason_it_cannot_read_keeps_its_text() {
        for reason in [
            "claim time 2026-11-16T09:00:00Z is older than claim_max_age 2h",
            "some future reason",
            "firewall = off, on required, access ends in soon",
        ] {
            assert_eq!(row(reason), ReasonRow::raw(reason));
        }
        assert_eq!(
            reason_row(
                "firewall = off, on required, access ends in 2h",
                None,
                prague
            ),
            ReasonRow::raw("firewall = off, on required, access ends in 2h")
        );
    }
}
