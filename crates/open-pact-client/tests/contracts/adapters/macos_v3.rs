use super::*;
use crate::checks::contracts::Case;
use open_pact_core::ControlValue;

pub(crate) fn run(id: &str, case: &Case) -> ControlValue {
    let text = case.text(0);
    match id {
        "os_auto_updates" => parse_update_flags(
            case.optional(0)
                .map_or(UpdateSetting::Unknown, parse_update_value),
            case.optional(1)
                .map_or(UpdateSetting::Unknown, parse_update_value),
        ),
        "antimalware_realtime" => parse_realtime(text),
        "work_account" => parse_groups(text, &[80]),
        "uptime_days" => parse_boot_time(text, case.now().timestamp()),
        "preboot_auth" => parse_preboot(text).into(),
        "antimalware_active" => parse_xprotect(text, case.optional(1)).into(),
        "antimalware_signature_age_days" => parse_signature_age(text, case.text(1), case.now()),
        "remote_wipe" => {
            if case.code == Some(0) {
                parse_activation_lock(text)
            } else {
                "unknown".into()
            }
        }
        _ => panic!("unsupported macOS V3 contract {id}"),
    }
}
