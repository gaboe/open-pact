use super::*;
use crate::checks::contracts::Case;
use open_pact_core::ControlValue;

pub(crate) fn run(id: &str, case: &Case) -> ControlValue {
    let text = case.text(0);
    match id {
        "disk_encryption" => parse_fdesetup(text).into(),
        "firewall" => parse_firewall(text).into(),
        "screen_lock" => parse_screen_lock(text).into(),
        "os_supported" => parse_os_supported(text).into(),
        "auto_login" => parse_auto_login(text).into(),
        "os_patch_age_days" => parse_last_macos_update(text).map_or_else(
            || "unknown".into(),
            |date| buckets::patch_age(date, case.now().date_naive()),
        ),
        _ => panic!("unsupported macOS contract {id}"),
    }
}
