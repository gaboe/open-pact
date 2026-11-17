//! Timestamps on the `time` crate, read and written the way the chrono-based code did.
//!
//! The text here is signed (claims), stored (log lines, database rows), printed (JSON, status
//! reports) or shown in errors. Each function reproduces the chrono output byte for byte, and
//! the pins in the evaluate, manifest and client and gateway modules hold these rules.

use std::fmt;

use time::format_description::BorrowedFormatItem;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, UtcOffset};

/// Whole seconds that chrono's `TimeDelta` holds at most: `i64::MAX` milliseconds.
const MAX_SECS: i64 = i64::MAX / 1000;

/// The longest span chrono's `TimeDelta::MAX` stood for. A grace this long shows its whole days and hours.
pub const MAX: Duration = Duration::seconds(MAX_SECS);

/// A span of whole seconds, or `None` past the range chrono's `TimeDelta` held.
pub fn seconds(secs: i64) -> Option<Duration> {
    (-MAX_SECS - 1..=MAX_SECS)
        .contains(&secs)
        .then(|| Duration::seconds(secs))
}

/// The instant `micros` microseconds after the Unix epoch.
pub fn from_unix_micros(micros: i64) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1000).ok()
}

/// The date with these year, month and day numbers, or `None` when they name no day.
pub fn ymd(year: i32, month: u32, day: u32) -> Option<Date> {
    let month = Month::try_from(u8::try_from(month).ok()?).ok()?;
    Date::from_calendar_date(year, month, u8::try_from(day).ok()?).ok()
}

/// Reads `%Y-%m-%d` as chrono did: up to four year digits after an optional sign, and one or
/// two digits for the month and the day.
pub fn parse_date(text: &str) -> Option<Date> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let mut parts = rest.splitn(3, '-');
    let year: i32 = digits(parts.next()?, 4)?.try_into().ok()?;
    let month = digits(parts.next()?, 2)?;
    let day = digits(parts.next()?, 2)?;
    ymd(if negative { -year } else { year }, month, day)
}

fn digits(text: &str, max_len: usize) -> Option<u32> {
    if text.is_empty() || text.len() > max_len || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The year as chrono writes it: four digits at least, and a minus sign before the year zero.
fn year_text(year: i32) -> String {
    if year < 0 {
        format!("-{:04}", -year)
    } else {
        format!("{year:04}")
    }
}

/// The date as chrono's `Display` and `Serialize` write it: `%Y-%m-%d`.
pub fn date_text(date: &Date) -> String {
    format!(
        "{}-{:02}-{:02}",
        year_text(date.year()),
        u8::from(date.month()),
        date.day()
    )
}

/// The year and month as the gateway stores a claim period: `%Y-%m`.
pub fn year_month(date: Date) -> String {
    format!("{}-{:02}", year_text(date.year()), u8::from(date.month()))
}

/// The instant in UTC, as chrono's `DateTime<Utc>` held it.
fn utc(t: OffsetDateTime) -> OffsetDateTime {
    t.to_offset(UtcOffset::UTC)
}

/// The fraction chrono adds to a time: none, or three, six or nine digits, whichever is exact.
fn fraction(nanos: u32) -> String {
    if nanos == 0 {
        String::new()
    } else if nanos.is_multiple_of(1_000_000) {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1_000) {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    }
}

/// RFC 3339 in UTC with whole seconds, as chrono's `to_rfc3339_opts(SecondsFormat::Secs, true)`.
pub fn rfc3339_secs(t: OffsetDateTime) -> String {
    let t = utc(t);
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        date_text(&t.date()),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// RFC 3339 in UTC with the fraction chrono's `SecondsFormat::AutoSi` chooses.
pub fn rfc3339_auto(t: OffsetDateTime) -> String {
    let t = utc(t);
    format!(
        "{}T{:02}:{:02}:{:02}{}Z",
        date_text(&t.date()),
        t.hour(),
        t.minute(),
        t.second(),
        fraction(t.nanosecond())
    )
}

/// Reads RFC 3339 as chrono's `parse_from_rfc3339` did, in UTC. The separator may be `t` or a
/// space, and the zone `z`.
pub fn parse_rfc3339(text: &str) -> Option<OffsetDateTime> {
    let mut bytes = text.as_bytes().to_vec();
    // The time crate has no leap second. chrono kept `23:59:60`, so such a time is refused here.
    if bytes.get(17..19) == Some(b"60".as_slice()) {
        return None;
    }
    if matches!(bytes.get(10), Some(b' ' | b't')) {
        bytes[10] = b'T';
    }
    if let Some(last) = bytes.last_mut().filter(|last| **last == b'z') {
        *last = b'Z';
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    OffsetDateTime::parse(text, &Rfc3339).ok().map(utc)
}

/// Rewrites a trailing `+hh:mm` zone as `+hhmm`, the other spelling chrono's `%z` read.
fn squeeze_offset(text: &str) -> String {
    let bytes = text.as_bytes();
    let n = bytes.len();
    if n >= 6 && bytes[n - 3] == b':' && matches!(bytes[n - 6], b'+' | b'-') {
        format!("{}{}", &text[..n - 3], &text[n - 2..])
    } else {
        text.to_owned()
    }
}

const ISO_WITH_OFFSET: &[BorrowedFormatItem<'static>] = format_description!(
    "[year]-[month padding:none]-[day padding:none] [hour padding:none]:[minute padding:none]:[second padding:none] [offset_hour sign:mandatory][offset_minute]"
);

const DAY_MONTH_YEAR_WITH_OFFSET: &[BorrowedFormatItem<'static>] = format_description!(
    "[day padding:none] [month repr:short case_sensitive:false] [year] [hour padding:none]:[minute padding:none]:[second padding:none] [offset_hour sign:mandatory][offset_minute]"
);

/// Reads `%Y-%m-%d %H:%M:%S %z`, as the macOS security history writes dates, in UTC.
pub fn parse_iso_with_offset(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(&squeeze_offset(text), &ISO_WITH_OFFSET)
        .ok()
        .map(utc)
}

/// Reads `%d %b %Y %H:%M:%S %z`, as APT writes release dates, in UTC.
pub fn parse_day_month_year_with_offset(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(&squeeze_offset(text), &DAY_MONTH_YEAR_WITH_OFFSET)
        .ok()
        .map(utc)
}

/// `checked_add_months` as chrono had it: the same time `months` calendar months later, with the
/// day moved back to the last day of a shorter month. `None` past the calendar.
pub fn add_months(t: OffsetDateTime, months: i64) -> Option<OffsetDateTime> {
    let index = i64::from(t.year()) * 12 + i64::from(u8::from(t.month()) - 1) + months;
    let year = i32::try_from(index.div_euclid(12)).ok()?;
    let month = Month::try_from(u8::try_from(index.rem_euclid(12)).ok()? + 1).ok()?;
    let day = t.day().min(month.length(year));
    let date = Date::from_calendar_date(year, month, day).ok()?;
    Some(PrimitiveDateTime::new(date, t.time()).assume_offset(t.offset()))
}

/// `Display` of a UTC instant as chrono wrote it in errors: `2026-10-12 09:00:00 UTC`, with a
/// fraction when there is one.
pub fn display(t: &OffsetDateTime) -> impl fmt::Display {
    Shown(utc(*t))
}

struct Shown(OffsetDateTime);

impl fmt::Display for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.0;
        write!(
            f,
            "{} {:02}:{:02}:{:02}{} UTC",
            date_text(&t.date()),
            t.hour(),
            t.minute(),
            t.second(),
            fraction(t.nanosecond())
        )
    }
}

/// Whether `text` is RFC 3339 that chrono's `parse_from_rfc3339` read. The time crate has no leap
/// second, so `:60` in the seconds counts as valid here, as it did for chrono. This is only a
/// validity check: the caller keeps the text as written.
pub fn is_rfc3339(text: &str) -> bool {
    let mut bytes = text.as_bytes().to_vec();
    if bytes.get(17..19) == Some(b"60".as_slice()) {
        bytes[17] = b'5';
        bytes[18] = b'9';
    }
    std::str::from_utf8(&bytes).is_ok_and(|text| parse_rfc3339(text).is_some())
}

/// Serde for a UTC instant: RFC 3339 with the fraction `SecondsFormat::AutoSi` gives.
pub mod serde_rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(t: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::rfc3339_auto(*t))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OffsetDateTime, D::Error> {
        let text = String::deserialize(d)?;
        super::parse_rfc3339(&text).ok_or_else(|| {
            serde::de::Error::custom(format!("input is not an RFC 3339 time: {text:?}"))
        })
    }
}

/// Serde for a calendar date: `%Y-%m-%d`.
pub mod serde_date {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::Date;

    pub fn serialize<S: Serializer>(d: &Date, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::date_text(d))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Date, D::Error> {
        let text = String::deserialize(d)?;
        super::parse_date(&text)
            .ok_or_else(|| serde::de::Error::custom(format!("input is not a date: {text:?}")))
    }
}

/// The method chrono's `DateTime::to_rfc3339` had, so the tests can keep comparing with `+00:00`.
#[cfg(test)]
pub trait ToRfc3339 {
    fn to_rfc3339(&self) -> String;
}

#[cfg(test)]
impl ToRfc3339 for OffsetDateTime {
    fn to_rfc3339(&self) -> String {
        rfc3339_auto(*self).replace('Z', "+00:00")
    }
}
