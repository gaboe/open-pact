//! The reasons the company gave for not accepting a check, as rows of plain words. The reasons are
//! the gateway's text, written by the `Reason` Display of the core. No UI code lives here.

use crate::manifest::{builtin, value_label};
use crate::status_text::access_deadline;
use crate::text::{Tone, humanize};
use time::macros::format_description;
use time::{Duration, OffsetDateTime};

/// Where a failing control stands against its grace period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraceState {
    Ended,
    /// The end instant, and its local time such as "17 Nov, 11:10" for the label.
    EndsAt {
        when: String,
        at: OffsetDateTime,
    },
}

impl GraceState {
    /// The grace text as of `now`: the time left, and the local end time in brackets.
    pub fn text(&self, now: OffsetDateTime) -> String {
        match self {
            Self::Ended => "Grace ended".into(),
            Self::EndsAt { when, at } => match time_left(*at, now) {
                Some(left) => format!("Grace ends {left} ({when})"),
                None => "Grace ended".into(),
            },
        }
    }

    /// The tone of the grace label as of `now`. It reads the same clock as `text`.
    pub fn tone(&self, now: OffsetDateTime) -> Tone {
        match self {
            Self::Ended => Tone::Bad,
            Self::EndsAt { at, .. } if now >= *at => Tone::Bad,
            Self::EndsAt { .. } => Tone::Warn,
        }
    }
}

/// The time left until `end` as of `now`, in words such as "in 19 h". `None` from the end instant on.
/// The warning rows of an accepted check use these same words.
pub fn time_left(end: OffsetDateTime, now: OffsetDateTime) -> Option<String> {
    let left = end - now;
    if left <= Duration::ZERO {
        return None;
    }
    let days = left.whole_days();
    let hours = left.whole_hours();
    Some(if days >= 2 {
        format!("in {days} days")
    } else if hours >= 24 {
        match hours - 24 {
            0 => "in 1 day".into(),
            rest => format!("in 1 day {rest} h"),
        }
    } else if hours >= 1 {
        format!("in {hours} h")
    } else {
        format!("in {} min", left.whole_minutes().max(1))
    })
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
        None => match grace {
            Some(grace) => ReasonRow {
                name: body.to_owned(),
                detail: None,
                grace: Some(grace),
            },
            None => ReasonRow::raw(reason),
        },
    }
}

/// The reason without its grace tail. `None` when the tail names a time this module cannot read.
fn split_grace(
    reason: &str,
    sent: Option<OffsetDateTime>,
    zone: impl Fn(OffsetDateTime) -> OffsetDateTime,
) -> Option<(&str, Option<GraceState>)> {
    if let Some((body, span)) = reason.rsplit_once(", access ends in ") {
        let deadline = access_deadline(sent?, span)?;
        let when = zone(deadline)
            .format(format_description!(
                "[day padding:none] [month repr:short], [hour]:[minute]"
            ))
            .ok()?;
        return Some((body, Some(GraceState::EndsAt { when, at: deadline })));
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
    // Older gateways end the text after <patch>; newer ones also name the prerelease forms.
    if body.starts_with("client must be \"open-pact-client ") {
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

    fn ends_at() -> OffsetDateTime {
        parse_rfc3339("2026-11-17T10:10:35Z").unwrap()
    }

    /// The grace text when `left` is still to run (negative: already past the end).
    fn grace_left(left: Duration) -> String {
        let at = ends_at();
        GraceState::EndsAt {
            when: "17 Nov, 11:10".into(),
            at,
        }
        .text(at - left)
    }

    fn read(name: &str, detail: &str, grace: Option<GraceState>) -> ReasonRow {
        ReasonRow {
            name: name.into(),
            detail: Some(detail.into()),
            grace,
        }
    }

    #[test]
    fn the_newer_client_version_text_reads_as_the_same_row() {
        let old = row("client must be \"open-pact-client <major>.<minor>.<patch>\"");
        let new = row(
            "client must be \"open-pact-client <major>.<minor>.<patch>\", optionally with -alpha.<n>, -beta.<n> or -rc.<n>",
        );
        assert_eq!(old, new);
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
                Some(GraceState::EndsAt {
                    when: "17 Nov, 10:10".into(),
                    at: parse_rfc3339("2026-11-17T09:10:35Z").unwrap(),
                })
            )
        );
        assert_eq!(
            grace_left(Duration::hours(19)),
            "Grace ends in 19 h (17 Nov, 11:10)"
        );
    }

    #[test]
    fn the_grace_text_counts_down_in_days_hours_and_minutes() {
        assert_eq!(
            grace_left(Duration::days(3)),
            "Grace ends in 3 days (17 Nov, 11:10)"
        );
        assert_eq!(
            grace_left(Duration::days(2)),
            "Grace ends in 2 days (17 Nov, 11:10)"
        );
        assert_eq!(
            grace_left(Duration::seconds(2 * 86_400 - 1)),
            "Grace ends in 1 day 23 h (17 Nov, 11:10)"
        );
        assert_eq!(
            grace_left(Duration::days(1)),
            "Grace ends in 1 day (17 Nov, 11:10)"
        );
        assert_eq!(
            grace_left(Duration::hours(25)),
            "Grace ends in 1 day 1 h (17 Nov, 11:10)"
        );
        assert_eq!(
            grace_left(Duration::hours(23)),
            "Grace ends in 23 h (17 Nov, 11:10)"
        );
        assert_eq!(
            grace_left(Duration::hours(1)),
            "Grace ends in 1 h (17 Nov, 11:10)"
        );
        assert_eq!(
            grace_left(Duration::seconds(3599)),
            "Grace ends in 59 min (17 Nov, 11:10)"
        );
        assert_eq!(
            grace_left(Duration::seconds(59)),
            "Grace ends in 1 min (17 Nov, 11:10)"
        );
    }

    #[test]
    fn the_grace_text_says_ended_from_the_end_instant_on() {
        assert_eq!(grace_left(Duration::ZERO), "Grace ended");
        assert_eq!(grace_left(Duration::seconds(-60)), "Grace ended");
        assert_eq!(GraceState::Ended.text(ends_at()), "Grace ended");
    }

    #[test]
    fn the_band_text_rounds_down_and_never_up() {
        assert_eq!(
            grace_left(Duration::seconds(2 * 86_400 + 23 * 3600)),
            "Grace ends in 2 days (17 Nov, 11:10)"
        );
        assert_eq!(
            grace_left(Duration::seconds(3600 + 59 * 60)),
            "Grace ends in 1 h (17 Nov, 11:10)"
        );
    }

    #[test]
    fn a_rounded_zero_minutes_left_ends_at_the_earliest_instant() {
        let sent = parse_rfc3339("2026-11-17T10:00:00Z");
        let grace = reason_row(
            "firewall = off, on required, access ends in 0m",
            sent,
            prague,
        )
        .grace
        .unwrap();
        let five_seconds_later = parse_rfc3339("2026-11-17T10:00:05Z").unwrap();
        assert_eq!(grace.text(five_seconds_later), "Grace ended");
        assert_eq!(grace.tone(five_seconds_later), Tone::Bad);
    }

    #[test]
    fn the_tone_and_the_text_follow_the_same_clock() {
        let grace = GraceState::EndsAt {
            when: "17 Nov, 11:10".into(),
            at: ends_at(),
        };
        let hour_before = ends_at() - Duration::hours(1);
        assert_eq!(grace.text(hour_before), "Grace ends in 1 h (17 Nov, 11:10)");
        assert_eq!(grace.tone(hour_before), Tone::Warn);
        assert_eq!(grace.text(ends_at()), "Grace ended");
        assert_eq!(grace.tone(ends_at()), Tone::Bad);
    }

    #[test]
    fn a_reason_with_an_unknown_body_still_gets_its_countdown() {
        let reason = "future_rule must hold, access ends in 24h";
        let row = row(reason);
        assert_eq!(row.name, "future_rule must hold");
        assert_eq!(row.detail, None);
        let grace = row.grace.unwrap();
        let hour_later = parse_rfc3339("2026-11-16T15:10:35Z").unwrap();
        assert_eq!(grace.text(hour_later), "Grace ends in 23 h (17 Nov, 15:10)");
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
