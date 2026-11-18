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
    time.to_offset(offset)
}
