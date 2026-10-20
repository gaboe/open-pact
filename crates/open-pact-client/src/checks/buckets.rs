use chrono::NaiveDate;

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
    fn lock_delay_bucket_edges() {
        assert_eq!(lock_delay(0), "le_5min");
        assert_eq!(lock_delay(300), "le_5min");
        assert_eq!(lock_delay(301), "le_15min");
        assert_eq!(lock_delay(900), "le_15min");
        assert_eq!(lock_delay(901), "gt_15min");
    }
}
