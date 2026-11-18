//! The time zone of this computer. `time` reads it per instant, so summer time counts, but on
//! Unix it refuses once the process runs several threads. The apps read the offset once, first in
//! `main`, and the cache serves every later call that `time` refuses.

use std::sync::OnceLock;
use time::{OffsetDateTime, UtcOffset};

static AT_START: OnceLock<UtcOffset> = OnceLock::new();

/// Reads the offset of this computer. Call it first in `main`, before any thread starts.
pub fn read_start_offset() {
    start_offset();
}

fn start_offset() -> UtcOffset {
    *AT_START.get_or_init(|| UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC))
}

/// The same instant in the time zone of this computer.
pub fn to_local(time: OffsetDateTime) -> OffsetDateTime {
    let offset = UtcOffset::local_offset_at(time).unwrap_or_else(|_| start_offset());
    in_offset(time, offset)
}

/// The same instant at `offset`. Near the end of the range the shifted date does not exist, so
/// the instant keeps its own offset there instead of panicking.
fn in_offset(time: OffsetDateTime, offset: UtcOffset) -> OffsetDateTime {
    time.checked_to_offset(offset).unwrap_or(time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn a_time_near_the_top_of_the_range_stays_put_when_its_offset_moves_it_out() {
        let plus_one = UtcOffset::from_hms(1, 0, 0).unwrap();
        let last = datetime!(9999-12-31 23:59:59 UTC);
        assert_eq!(in_offset(last, plus_one), last);
    }

    #[test]
    fn an_ordinary_time_moves_to_a_fixed_offset() {
        let plus_one = UtcOffset::from_hms(1, 0, 0).unwrap();
        let noon = datetime!(2026-11-19 12:00 UTC);
        let shifted = in_offset(noon, plus_one);
        assert_eq!(shifted.hour(), 13);
        assert_eq!(shifted.offset(), plus_one);
    }
}
