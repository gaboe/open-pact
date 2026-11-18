//! Timestamps on the `time` crate, read and written the way the chrono-based code did.
//!
//! The text here is signed (claims), stored (log lines, database rows), printed (JSON, status
//! reports) or shown in errors. Each function reproduces the chrono output byte for byte, and
//! the pins in the evaluate, manifest and client and gateway modules hold these rules.

use std::fmt;

use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

/// Whole seconds that chrono's `TimeDelta` holds at most: `i64::MAX` milliseconds.
const MAX_SECS: i64 = i64::MAX / 1000;

/// The longest span chrono's `TimeDelta::MAX` stood for. A grace this long shows its whole days and hours.
pub const MAX: Duration = Duration::seconds(MAX_SECS);

/// A span of whole seconds, or `None` past the range chrono's `TimeDelta` held.
pub fn seconds(secs: i64) -> Option<Duration> {
    (-MAX_SECS..=MAX_SECS)
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

/// Reads `%Y-%m-%d` as chrono's `NaiveDate::parse_from_str` did: up to four year digits after an
/// optional sign, one or two digits for the month and the day, and white space before each number.
pub fn parse_date(text: &str) -> Option<Date> {
    date(text, false)
}

/// Reads a date as chrono's `NaiveDate` `FromStr` and serde did: `parse_date`, and white space
/// also before each `-` and after the day.
pub fn parse_date_relaxed(text: &str) -> Option<Date> {
    date(text, true)
}

fn date(text: &str, relaxed: bool) -> Option<Date> {
    let mut text = Cursor(text);
    let year = text.year()?;
    if relaxed {
        text.space();
    }
    text.literal('-')?;
    let month = text.numeric(2)?;
    if relaxed {
        text.space();
    }
    text.literal('-')?;
    let day = text.numeric(2)?;
    if relaxed {
        text.space();
    }
    if !text.0.is_empty() {
        return None;
    }
    ymd(year, u32::try_from(month).ok()?, u32::try_from(day).ok()?)
}

/// A reader that takes text the way chrono's parser did, one item at a time. Each method returns
/// `None` where chrono returned an error.
struct Cursor<'a>(&'a str);

impl Cursor<'_> {
    /// Any run of white space, or none.
    fn space(&mut self) {
        self.0 = self.0.trim_start();
    }

    fn literal(&mut self, expected: char) -> Option<()> {
        self.0 = self.0.strip_prefix(expected)?;
        Some(())
    }

    /// One to `max` ASCII digits.
    fn number(&mut self, max: usize) -> Option<i64> {
        let digits = self
            .0
            .bytes()
            .take(max)
            .take_while(u8::is_ascii_digit)
            .count();
        let mut value = 0i64;
        for digit in &self.0.as_bytes()[..digits] {
            value = value
                .checked_mul(10)?
                .checked_add(i64::from(digit - b'0'))?;
        }
        if digits == 0 {
            return None;
        }
        self.0 = &self.0[digits..];
        Some(value)
    }

    /// A number after any white space.
    fn numeric(&mut self, max: usize) -> Option<i64> {
        self.space();
        self.number(max)
    }

    /// A year after any white space: four digits at most, or any number of digits after a sign.
    fn year(&mut self) -> Option<i32> {
        self.space();
        let year = if let Some(rest) = self.0.strip_prefix('-') {
            self.0 = rest;
            self.number(usize::MAX)?.checked_neg()?
        } else if let Some(rest) = self.0.strip_prefix('+') {
            self.0 = rest;
            self.number(usize::MAX)?
        } else {
            self.number(4)?
        };
        i32::try_from(year).ok()
    }

    /// The nanoseconds of an optional `.` and one or more digits. Digits after the ninth are
    /// dropped.
    fn fraction(&mut self) -> Option<u32> {
        let Some(rest) = self.0.strip_prefix('.') else {
            return Some(0);
        };
        self.0 = rest;
        let before = self.0.len();
        let value = u32::try_from(self.number(9)?).ok()?;
        let digits = before - self.0.len();
        self.0 = self.0.trim_start_matches(|c: char| c.is_ascii_digit());
        value.checked_mul(10u32.pow(u32::try_from(9 - digits).ok()?))
    }

    /// A zone offset in seconds: `+hh:mm`, with a plain or a Unicode minus sign, and `Z` when
    /// `zulu` is set. Without `colon_only` the colon may be white space, more colons or missing.
    /// Hours up to 23 and minutes up to 59.
    fn offset(&mut self, zulu: bool, colon_only: bool) -> Option<i32> {
        if zulu && let Some(rest) = self.0.strip_prefix(['Z', 'z']) {
            self.0 = rest;
            return Some(0);
        }
        let (negative, rest) = match self.0.strip_prefix('+') {
            Some(rest) => (false, rest),
            None => (true, self.0.strip_prefix(['-', '\u{2212}'])?),
        };
        let hours = two_digits(rest.as_bytes(), b'9')?;
        let rest = &rest[2..];
        let rest = if colon_only {
            rest.strip_prefix(':')?
        } else {
            rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace())
        };
        let minutes = two_digits(rest.as_bytes(), b'5')?;
        self.0 = &rest[2..];
        let secs = hours * 3600 + minutes * 60;
        (secs < 86_400).then_some(if negative { -secs } else { secs })
    }

    fn short_month(&mut self) -> Option<u32> {
        let name = self.0.get(..3)?;
        let index = [
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
        ]
        .iter()
        .position(|month| month.eq_ignore_ascii_case(name))?;
        self.0 = &self.0[3..];
        u32::try_from(index + 1).ok()
    }
}

/// Two ASCII digits, the first at most `first_max`.
fn two_digits(bytes: &[u8], first_max: u8) -> Option<i32> {
    match bytes {
        [tens @ b'0'..=b'9', ones @ b'0'..=b'9', ..] if *tens <= first_max => {
            Some(i32::from(tens - b'0') * 10 + i32::from(ones - b'0'))
        }
        _ => None,
    }
}

/// The fields of a date and a time read from text, with the zone offset in seconds.
struct Fields {
    year: i32,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    nanos: u32,
    offset: i32,
}

impl Fields {
    /// The instant in UTC. Second 60 is a leap second, which chrono held: it counts as the first
    /// second of the next minute, as chrono's arithmetic did, when `leap` is set and is refused
    /// otherwise. `None` when the fields name no moment or the instant is past the range of `time`.
    fn instant(&self, leap: bool) -> Option<OffsetDateTime> {
        let (local, is_leap) = self.civil(leap)?;
        let offset = UtcOffset::from_whole_seconds(self.offset).ok()?;
        let at = to_utc(local.assume_offset(offset))?;
        if is_leap {
            at.checked_add(Duration::SECOND)
        } else {
            Some(at)
        }
    }

    /// The local date and time, and whether the second was a leap second, which reads as :59.
    fn civil(&self, leap: bool) -> Option<(PrimitiveDateTime, bool)> {
        let day = ymd(
            self.year,
            u32::try_from(self.month).ok()?,
            u32::try_from(self.day).ok()?,
        )?;
        let is_leap = self.second == 60;
        if is_leap && !leap {
            return None;
        }
        let second = if is_leap { 59 } else { self.second };
        let time = Time::from_hms_nano(
            u8::try_from(self.hour).ok()?,
            u8::try_from(self.minute).ok()?,
            u8::try_from(second).ok()?,
            self.nanos,
        )
        .ok()?;
        Some((PrimitiveDateTime::new(day, time), is_leap))
    }
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

/// The instant in UTC, or `None` when its UTC date is past the range of `time`.
fn to_utc(t: OffsetDateTime) -> Option<OffsetDateTime> {
    t.checked_to_offset(UtcOffset::UTC)
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
/// space, the zone `z` or `Z`, the offset sign a Unicode minus, and a leap second `:60` counts as
/// the first second of the next minute. `None` also when the instant is past the range of `time`.
pub fn parse_rfc3339(text: &str) -> Option<OffsetDateTime> {
    strict(text)?.instant(true)
}

/// The fields of `text` when it is RFC 3339: the fixed layout `YYYY-MM-DDThh:mm:ss`, a fraction
/// of any length, and `Z` or `+hh:mm`.
fn strict(text: &str) -> Option<Fields> {
    let bytes = text.as_bytes();
    let two = |at: usize| -> Option<i64> {
        match bytes.get(at..at + 2)? {
            [tens @ b'0'..=b'9', ones @ b'0'..=b'9'] => {
                Some(i64::from(tens - b'0') * 10 + i64::from(ones - b'0'))
            }
            _ => None,
        }
    };
    let year = two(0)? * 100 + two(2)?;
    let layout = [(4, b'-'), (7, b'-'), (13, b':'), (16, b':')];
    if layout
        .iter()
        .any(|&(at, sign)| bytes.get(at) != Some(&sign))
        || !matches!(bytes.get(10), Some(b't' | b'T' | b' '))
    {
        return None;
    }
    let mut rest = Cursor(text.get(19..)?);
    let nanos = rest.fraction()?;
    let offset = rest.offset(true, true)?;
    if !rest.0.is_empty() {
        return None;
    }
    Some(Fields {
        year: i32::try_from(year).ok()?,
        month: two(5)?,
        day: two(8)?,
        hour: two(11)?,
        minute: two(14)?,
        second: two(17)?,
        nanos,
        offset,
    })
}

/// Reads a time as chrono's `DateTime<Utc>` `FromStr` did, in UTC: the spelling of
/// `parse_rfc3339` and more. The separator may be `t`, `T` or a space, the zone `UTC`, `Z`,
/// `+hhmm`, `+hh mm` or `+hh:mm`, one-digit fields are read, white space may sit between the
/// parts, and the year may carry a sign. A leap second `:60` counts as the first second of the
/// next minute.
pub fn parse_relaxed(text: &str) -> Option<OffsetDateTime> {
    relaxed(text, true)
}

fn relaxed(text: &str, leap: bool) -> Option<OffsetDateTime> {
    let mut text = Cursor(text);
    let year = text.year()?;
    text.space();
    text.literal('-')?;
    let month = text.numeric(2)?;
    text.space();
    text.literal('-')?;
    let day = text.numeric(2)?;
    text.0 = text.0.strip_prefix(['t', 'T', ' '])?;
    let hour = text.numeric(2)?;
    text.space();
    text.literal(':')?;
    let minute = text.numeric(2)?;
    text.space();
    text.literal(':')?;
    let second = text.numeric(2)?;
    let nanos = text.fraction()?;
    text.space();
    let offset = match text.0.get(..3) {
        Some(zone) if zone.eq_ignore_ascii_case("UTC") => {
            text.0 = &text.0[3..];
            0
        }
        _ => text.offset(true, false)?,
    };
    text.space();
    if !text.0.is_empty() {
        return None;
    }
    Fields {
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanos,
        offset,
    }
    .instant(leap)
}

/// Reads `%Y-%m-%d %H:%M:%S %z` as chrono's `DateTime::parse_from_str` did, as the macOS security
/// history writes dates, in UTC.
pub fn parse_iso_with_offset(text: &str) -> Option<OffsetDateTime> {
    let mut text = Cursor(text);
    let year = text.year()?;
    text.literal('-')?;
    let month = text.numeric(2)?;
    text.literal('-')?;
    let day = text.numeric(2)?;
    text.space();
    let hour = text.numeric(2)?;
    text.literal(':')?;
    let minute = text.numeric(2)?;
    text.literal(':')?;
    let second = text.numeric(2)?;
    text.space();
    let offset = text.offset(false, false)?;
    if !text.0.is_empty() {
        return None;
    }
    Fields {
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanos: 0,
        offset,
    }
    .instant(true)
}

/// Reads `%d %b %Y %H:%M:%S %z` as chrono's `DateTime::parse_from_str` did, as APT writes release
/// dates, in UTC.
pub fn parse_day_month_year_with_offset(text: &str) -> Option<OffsetDateTime> {
    let mut text = Cursor(text);
    let day = text.numeric(2)?;
    text.space();
    let month = text.short_month()?;
    text.space();
    let year = text.year()?;
    text.space();
    let hour = text.numeric(2)?;
    text.literal(':')?;
    let minute = text.numeric(2)?;
    text.literal(':')?;
    let second = text.numeric(2)?;
    text.space();
    let offset = text.offset(false, false)?;
    if !text.0.is_empty() {
        return None;
    }
    Fields {
        year,
        month: i64::from(month),
        day,
        hour,
        minute,
        second,
        nanos: 0,
        offset,
    }
    .instant(true)
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

/// Whether `text` is RFC 3339 that chrono's `parse_from_rfc3339` read, a leap second `:60`
/// included. This is only a validity check: the caller keeps the text as written, and the year of
/// its UTC instant may be past the range of `time`.
pub fn is_rfc3339(text: &str) -> bool {
    strict(text).is_some_and(|fields| fields.civil(true).is_some())
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
        super::relaxed(&text, false).ok_or_else(|| {
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
        super::parse_date_relaxed(&text)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// What each reader returned for chrono 0.4.45, as text in UTC; `None` where chrono refused.
    fn shown(t: Option<OffsetDateTime>) -> Option<String> {
        t.map(rfc3339_auto)
    }

    fn check(read: fn(&str) -> Option<OffsetDateTime>, cases: &[(&str, Option<&str>)]) {
        for (text, expected) in cases {
            assert_eq!(shown(read(text)).as_deref(), *expected, "{text:?}");
        }
    }

    #[test]
    fn relaxed_reads_every_spelling_chrono_read_from_str() {
        check(
            parse_relaxed,
            &[
                ("2026-10-12T09:00:00Z", Some("2026-10-12T09:00:00Z")),
                ("2026-10-12T09:00:00+0000", Some("2026-10-12T09:00:00Z")),
                ("2026-10-12 09:00:00 UTC", Some("2026-10-12T09:00:00Z")),
                ("2026-10-12 09:00:00 utc", Some("2026-10-12T09:00:00Z")),
                ("2026-1-2T3:4:5Z", Some("2026-01-02T03:04:05Z")),
                ("2026-10-12T09:00:00Z ", Some("2026-10-12T09:00:00Z")),
                ("2026-10-12T09:00:00 +00 00", Some("2026-10-12T09:00:00Z")),
                ("2026-10-12T09:00:00+02:00", Some("2026-10-12T07:00:00Z")),
                ("2026-10-12T09:00:00 +0200", Some("2026-10-12T07:00:00Z")),
                (
                    "2026-10-12T09:00:00.5 UTC",
                    Some("2026-10-12T09:00:00.500Z"),
                ),
                (
                    "2026-10-12T09:00:00.123456789123Z",
                    Some("2026-10-12T09:00:00.123456789Z"),
                ),
                (
                    "2026 - 10 - 12T 09 : 00 : 00 Z",
                    Some("2026-10-12T09:00:00Z"),
                ),
                ("+2026-10-12T09:00:00Z", Some("2026-10-12T09:00:00Z")),
                (
                    "2026-10-12T09:00:00\u{2212}02:00",
                    Some("2026-10-12T11:00:00Z"),
                ),
                ("2026-10-12T09:00:00-0530", Some("2026-10-12T14:30:00Z")),
                ("2026-10-12t09:00:00z", Some("2026-10-12T09:00:00Z")),
                ("2026-10-12T09:00:00", None),
                ("2026-10-12", None),
                ("2026-10-12T09:00", None),
                ("2026-10-12T09:00:00+24:00", None),
                ("2026-10-12T09:00:00+0260", None),
                ("2026-10-12T09:00:00+02", None),
                ("10000-01-01T00:00:00Z", None),
            ],
        );
    }

    #[test]
    fn relaxed_reads_a_leap_second_as_the_first_second_of_the_next_minute() {
        check(
            parse_relaxed,
            &[
                ("2016-12-31T23:59:60Z", Some("2017-01-01T00:00:00Z")),
                ("2016-12-31T23:59:60.5Z", Some("2017-01-01T00:00:00.500Z")),
                ("2016-12-31T23:59:60+0100", Some("2016-12-31T23:00:00Z")),
                ("2016-12-31 23:59:60 UTC", Some("2017-01-01T00:00:00Z")),
            ],
        );
        // Claim.time refuses a leap second: the time crate holds none, and no client writes one.
        assert_eq!(relaxed("2016-12-31T23:59:60Z", false), None);
        assert!(relaxed("2016-12-31T23:59:59Z", false).is_some());
    }

    #[test]
    fn strict_reads_what_chrono_parse_from_rfc3339_read() {
        check(
            parse_rfc3339,
            &[
                ("2026-10-12T09:00:00Z", Some("2026-10-12T09:00:00Z")),
                ("2026-10-12t09:00:00z", Some("2026-10-12T09:00:00Z")),
                ("2026-10-12 09:00:00+02:00", Some("2026-10-12T07:00:00Z")),
                (
                    "2026-10-12T09:00:00\u{2212}02:00",
                    Some("2026-10-12T11:00:00Z"),
                ),
                (
                    "2026-10-12T09:00:00.1234567891Z",
                    Some("2026-10-12T09:00:00.123456789Z"),
                ),
                ("2016-12-31T23:59:60Z", Some("2017-01-01T00:00:00Z")),
                ("2026-10-12T09:00:60Z", Some("2026-10-12T09:01:00Z")),
                ("2026-10-12T09:00:00+0200", None),
                ("2026-10-12T09:00:00 UTC", None),
                ("2026-10-12Z09:00:00Z", None),
                ("2026-10-12109:00:00Z", None),
                ("2026-10-12T09:00:00.Z", None),
                ("2026-10-12T09:00:00Z ", None),
                ("2026-1-2T3:4:5Z", None),
            ],
        );
    }

    #[test]
    fn an_instant_past_the_range_of_time_is_refused_and_never_panics() {
        // chrono read this as 10000-01-01T23:58:59Z.
        let text = "9999-12-31T23:59:59-23:59";
        assert_eq!(parse_rfc3339(text), None);
        assert_eq!(parse_relaxed(text), None);
        assert!(is_rfc3339(text), "only its UTC instant is out of range");
        check(
            parse_rfc3339,
            &[("0000-01-01T00:00:00+23:59", Some("-0001-12-31T00:01:00Z"))],
        );
        assert_eq!(parse_relaxed("+10000-01-01T00:00:00Z"), None);
        assert_eq!(parse_iso_with_offset("9999-12-31 23:59:59 -2359"), None);
        assert_eq!(
            parse_day_month_year_with_offset("31 Dec 9999 23:59:59 -2359"),
            None
        );
        // The last second of the range, with a leap second pushing past it.
        assert_eq!(parse_relaxed("9999-12-31T23:59:60Z"), None);
        assert_eq!(parse_relaxed("-9999-01-01T00:00:00+0001"), None);
    }

    #[test]
    fn is_rfc3339_matches_the_strict_reader_before_the_range_check() {
        for (text, valid) in [
            ("2026-10-12T23:59:60Z", true),
            ("2026-10-12T09:00:00\u{2212}02:00", true),
            ("2026-10-12Z09:00:00Z", false),
            ("2026-10-12T09:00:00", false),
            ("2026-02-30T09:00:00Z", false),
        ] {
            assert_eq!(is_rfc3339(text), valid, "{text}");
        }
    }

    #[test]
    fn dates_read_as_chrono_read_them_by_serde_and_by_format() {
        // (text, NaiveDate FromStr and serde, NaiveDate::parse_from_str with %Y-%m-%d)
        let cases: &[(&str, Option<&str>, Option<&str>)] = &[
            ("2026-10-01", Some("2026-10-01"), Some("2026-10-01")),
            ("2026-10-01 ", Some("2026-10-01"), None),
            ("2026-10-01\t", Some("2026-10-01"), None),
            (" 2026-10-01", Some("2026-10-01"), Some("2026-10-01")),
            ("2026- 1- 2", Some("2026-01-02"), Some("2026-01-02")),
            ("2026 -10 -01", Some("2026-10-01"), None),
            ("+2026-1-2", Some("2026-01-02"), Some("2026-01-02")),
            ("-0001-01-01", Some("-0001-01-01"), Some("-0001-01-01")),
            ("26-1-2", Some("0026-01-02"), Some("0026-01-02")),
            ("2026-02-30", None, None),
            ("2026-1-2x", None, None),
            ("2026-13-01", None, None),
        ];
        for (text, serde, format) in cases {
            assert_eq!(
                parse_date_relaxed(text).as_ref().map(date_text).as_deref(),
                *serde,
                "serde {text:?}"
            );
            assert_eq!(
                parse_date(text).as_ref().map(date_text).as_deref(),
                *format,
                "format {text:?}"
            );
        }
    }

    #[test]
    fn the_macos_history_date_reads_as_chrono_read_it() {
        check(
            parse_iso_with_offset,
            &[
                ("2026-10-19 23:59:00 +0000", Some("2026-10-19T23:59:00Z")),
                ("2026-10-19  23:59:00 +0000", Some("2026-10-19T23:59:00Z")),
                ("2026-10-19 23:59:00  +0000", Some("2026-10-19T23:59:00Z")),
                ("2026-10-19 23:59:00 +00 00", Some("2026-10-19T23:59:00Z")),
                ("2026-10-19 23:59:00 +00:00", Some("2026-10-19T23:59:00Z")),
                ("2026-10-19 23:59:00+0000", Some("2026-10-19T23:59:00Z")),
                ("2026-10-1923:59:00 +0000", Some("2026-10-19T23:59:00Z")),
                ("2026-10-19 3:4:5 -0530", Some("2026-10-19T08:34:05Z")),
                ("2026-10-19 23:59:60 +0000", Some("2026-10-20T00:00:00Z")),
                ("2026-10-19 23:59:00 +00", None),
                ("2026-10-19 23:59:00 Z", None),
                ("2026-10-19 23:59:00 +0000 ", None),
                ("2026-10-19T23:59:00 +0000", None),
            ],
        );
    }

    #[test]
    fn the_apt_release_date_reads_as_chrono_read_it() {
        check(
            parse_day_month_year_with_offset,
            &[
                ("12 Oct 2026 01:43:41 +0000", Some("2026-10-12T01:43:41Z")),
                ("12 Oct 2026 01:43:60 +0000", Some("2026-10-12T01:44:00Z")),
                ("12 Oct 26 01:43:41 +0000", Some("0026-10-12T01:43:41Z")),
                ("12 Oct 2026 1:3:4 +0000", Some("2026-10-12T01:03:04Z")),
                ("12 oct 2026 01:43:41 +00:00", Some("2026-10-12T01:43:41Z")),
                ("12 OCT 2026 01:43:41 +00 00", Some("2026-10-12T01:43:41Z")),
                (
                    "12  Oct  2026  01:43:41  +0000",
                    Some("2026-10-12T01:43:41Z"),
                ),
                ("1 Jan 2026 00:00:00 -0530", Some("2026-01-01T05:30:00Z")),
                ("12 Foo 2026 01:43:41 +0000", None),
                ("12 Oct 2026 01:43:41 Z", None),
            ],
        );
    }

    #[test]
    fn seconds_hold_the_range_of_chrono_time_delta() {
        assert_eq!(seconds(-9_223_372_036_854_776), None);
        assert!(seconds(-9_223_372_036_854_775).is_some());
        assert!(seconds(9_223_372_036_854_775).is_some());
        assert_eq!(seconds(9_223_372_036_854_776), None);
    }
}
