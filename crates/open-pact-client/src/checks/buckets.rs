#[cfg(any(target_os = "macos", target_os = "linux", test))]
use chrono::NaiveDate;

#[cfg(any(target_os = "linux", test))]
pub fn elapsed_age_days(
    last: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    max: i32,
) -> open_pact_core::ControlValue {
    let days = (now - last).num_days();
    if (0..=i64::from(max)).contains(&days) {
        (days as i32).into()
    } else {
        "unknown".into()
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub fn patch_age(last: NaiveDate, today: NaiveDate) -> open_pact_core::ControlValue {
    match (today - last).num_days() {
        days @ 0..=3650 => open_pact_core::ControlValue::Integer(days as i32),
        _ => "unknown".into(),
    }
}

pub fn lock_delay(seconds: u64) -> &'static str {
    match seconds {
        s if s <= 300 => "le_5min",
        s if s <= 900 => "le_15min",
        _ => "gt_15min",
    }
}

/// What a reader found about the time until the screen locks. `screen_lock@1` reports it in
/// buckets and `screen_lock@2` in whole minutes, so both read the setting once and convert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lock {
    /// No automatic lock, or a lock that needs no password.
    None,
    /// The setting cannot be read, or is not understood.
    Unknown,
    /// The total time from the last input to a locked screen.
    Seconds(u64),
}

impl Lock {
    /// The `screen_lock@1` value.
    pub fn bucket(self) -> &'static str {
        match self {
            Lock::None => "none",
            Lock::Unknown => "unknown",
            Lock::Seconds(seconds) => lock_delay(seconds),
        }
    }

    /// The `screen_lock@2` value: whole minutes, rounded up. `unknown` when the total does not fit.
    pub fn minutes(self) -> open_pact_core::ControlValue {
        match self {
            Lock::None => "none".into(),
            Lock::Unknown => "unknown".into(),
            Lock::Seconds(seconds) => i32::try_from(seconds.div_ceil(60))
                .map_or_else(|_| "unknown".into(), open_pact_core::ControlValue::Integer),
        }
    }

    /// The weaker of two locks: a missing or longer lock wins, and an unreadable one decides.
    #[cfg(any(target_os = "windows", target_os = "macos", test))]
    pub fn weaker(self, other: Lock) -> Lock {
        match (self, other) {
            (Lock::Unknown, _) | (_, Lock::Unknown) => Lock::Unknown,
            (Lock::None, _) | (_, Lock::None) => Lock::None,
            (Lock::Seconds(a), Lock::Seconds(b)) => Lock::Seconds(a.max(b)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn patch_age_day_edges() {
        let today = d(2026, 10, 31);
        assert_eq!(
            patch_age(d(2026, 10, 17), today),
            open_pact_core::ControlValue::Integer(14)
        );
        assert_eq!(
            patch_age(d(2026, 10, 16), today),
            open_pact_core::ControlValue::Integer(15)
        );
        assert_eq!(
            patch_age(d(2026, 10, 1), today),
            open_pact_core::ControlValue::Integer(30)
        );
        assert_eq!(
            patch_age(d(2026, 9, 30), today),
            open_pact_core::ControlValue::Integer(31)
        );
    }

    #[test]
    fn patch_age_rejects_future_and_excessive_dates() {
        let today = d(2026, 10, 31);
        for days in [0, 3650] {
            assert_eq!(
                patch_age(today - chrono::TimeDelta::days(days), today),
                open_pact_core::ControlValue::Integer(days as i32)
            );
        }
        for days in [-1, 3651] {
            assert_eq!(
                patch_age(today - chrono::TimeDelta::days(days), today),
                "unknown"
            );
        }
    }

    #[test]
    fn a_lock_converts_to_buckets_and_whole_minutes_rounded_up() {
        use open_pact_core::ControlValue::Integer;
        for (lock, bucket, minutes) in [
            (Lock::Seconds(0), "le_5min", Integer(0)),
            (Lock::Seconds(1), "le_5min", Integer(1)),
            (Lock::Seconds(60), "le_5min", Integer(1)),
            (Lock::Seconds(61), "le_5min", Integer(2)),
            (Lock::Seconds(300), "le_5min", Integer(5)),
            (Lock::Seconds(301), "le_15min", Integer(6)),
            (Lock::Seconds(900), "le_15min", Integer(15)),
            (Lock::Seconds(901), "gt_15min", Integer(16)),
            (Lock::Seconds(u64::MAX), "gt_15min", "unknown".into()),
            (Lock::None, "none", "none".into()),
            (Lock::Unknown, "unknown", "unknown".into()),
        ] {
            assert_eq!(lock.bucket(), bucket, "{lock:?}");
            assert_eq!(lock.minutes(), minutes, "{lock:?}");
        }
    }

    #[test]
    fn the_weaker_lock_is_the_longer_one_and_unknown_decides() {
        let (a, b) = (Lock::Seconds(300), Lock::Seconds(600));
        assert_eq!(a.weaker(b), b);
        assert_eq!(b.weaker(a), b);
        assert_eq!(a.weaker(Lock::None), Lock::None);
        assert_eq!(Lock::None.weaker(Lock::Unknown), Lock::Unknown);
        assert_eq!(a.weaker(Lock::Unknown), Lock::Unknown);
    }

    #[test]
    fn lock_delay_bucket_edges() {
        assert_eq!(lock_delay(0), "le_5min");
        assert_eq!(lock_delay(300), "le_5min");
        assert_eq!(lock_delay(301), "le_15min");
        assert_eq!(lock_delay(900), "le_15min");
        assert_eq!(lock_delay(901), "gt_15min");
    }
}
