use chrono::NaiveDate;

pub fn patch_age(last: NaiveDate, today: NaiveDate) -> &'static str {
    match (today - last).num_days() {
        d if d <= 14 => "le_14d",
        d if d <= 30 => "le_30d",
        _ => "gt_30d",
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
    fn patch_age_bucket_edges() {
        let today = d(2026, 10, 31);
        assert_eq!(patch_age(d(2026, 10, 17), today), "le_14d");
        assert_eq!(patch_age(d(2026, 10, 16), today), "le_30d");
        assert_eq!(patch_age(d(2026, 10, 1), today), "le_30d");
        assert_eq!(patch_age(d(2026, 9, 30), today), "gt_30d");
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
