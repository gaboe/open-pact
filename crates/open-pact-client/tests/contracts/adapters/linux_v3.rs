use super::*;
use crate::checks::contracts::Case;
use open_pact_core::ControlValue;

pub(crate) fn run(id: &str, case: &Case) -> ControlValue {
    let text = case.text(0);
    match id {
        "os_auto_updates" => parse_update_units(&case.input),
        "antimalware_realtime" => parse_on_access(case.code, text),
        "work_account" => {
            let Some(admins) = parse_admin_gids(case.text(1)) else {
                return "unknown".into();
            };
            crate::checks::macos_v3::parse_groups(text, &admins)
        }
        "uptime_days" => parse_uptime(text),
        "preboot_auth" => parse_preboot(text).into(),
        "antimalware_signature_age_days" => parse_cvd_header(text.as_bytes()).map_or_else(
            || "unknown".into(),
            |date| bounded_age((case.now() - date).num_days(), 3650),
        ),
        "log_oldest_record_days" => {
            if case.code == Some(0) {
                parse_journal_age(text, case.now())
            } else {
                "unknown".into()
            }
        }
        _ => panic!("unsupported Linux V3 contract {id}"),
    }
}
