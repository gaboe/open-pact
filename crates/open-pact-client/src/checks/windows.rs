use chrono::{NaiveDate, Utc};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

use super::buckets;
use super::exec::run_with_timeout;
use open_pact_core::ControlValue;
const POWERSHELL: &str = include_str!("windows.ps1");

static VALUES: OnceLock<BTreeMap<String, String>> = OnceLock::new();

pub fn disk_encryption() -> ControlValue {
    value("bitlocker").map_or("unknown", parse_bitlocker).into()
}

pub fn firewall() -> ControlValue {
    value("firewall").map_or("unknown", parse_firewall).into()
}

/// A lock timeout set by policy wins over the user's secure screen saver.
pub fn screen_lock() -> ControlValue {
    match value("lock_policy") {
        Some("!") | None => return "unknown".into(),
        Some(value) if !value.is_empty() => match parse_dword(value) {
            Some(seconds) if seconds > 0 => return buckets::lock_delay(u64::from(seconds)).into(),
            Some(_) => {}
            None => return "unknown".into(),
        },
        _ => {}
    }
    parse_screen_saver(
        value("screen_active"),
        value("screen_secure"),
        value("screen_timeout"),
    )
    .into()
}

pub fn os_supported() -> ControlValue {
    value("os")
        .map_or("unknown", |data| {
            parse_os_supported(data, Utc::now().date_naive())
        })
        .into()
}

pub fn os_patch_age_days() -> ControlValue {
    parse_patch_age(
        value("patch_date").unwrap_or_default(),
        Utc::now().date_naive(),
    )
}

fn parse_patch_age(text: &str, today: NaiveDate) -> ControlValue {
    parse_last_update(text)
        .and_then(|date| {
            let days = today.signed_duration_since(date).num_days();
            i32::try_from(days)
                .ok()
                .filter(|days| *days >= 0)
                .map(ControlValue::Integer)
        })
        .unwrap_or_else(|| "unknown".into())
}

pub fn auto_login() -> ControlValue {
    value("autologin")
        .map_or("unknown", |value| {
            if value == "!" {
                "unknown"
            } else {
                parse_auto_login(value)
            }
        })
        .into()
}

pub fn secure_boot() -> ControlValue {
    value("secure_boot")
        .filter(|v| *v != "!")
        .and_then(parse_dword)
        .map_or("unknown", |v| match v {
            0 => "off",
            1 => "on",
            _ => "unknown",
        })
        .into()
}

pub fn antimalware_active() -> ControlValue {
    value("antimalware")
        .map_or("unknown", parse_antimalware)
        .into()
}

pub fn preboot_auth() -> ControlValue {
    parse_preboot(value("preboot").unwrap_or_default()).into()
}

pub fn antimalware_signature_age_days() -> ControlValue {
    number("signature_days", 3650, false)
}

pub fn antimalware_full_scan_age_days() -> ControlValue {
    number("full_scan_days", 3650, false)
}

pub fn antimalware_detections_7d() -> ControlValue {
    number("detections_7d", 10000, false)
}

pub fn antimalware_last_detection_hours() -> ControlValue {
    number("last_detection_hours", 8760, true)
}

pub fn local_log_retention_days() -> ControlValue {
    parse_retention(value("log_retention").unwrap_or_default())
}

pub fn process_audit() -> ControlValue {
    parse_process_audit(value("process_audit").unwrap_or_default()).into()
}

pub fn powershell_logging() -> ControlValue {
    parse_logging(value("powershell_logging").unwrap_or_default()).into()
}

pub fn log_cleared_hours() -> ControlValue {
    number("log_cleared", 8760, true)
}

fn number(key: &str, max: i32, none: bool) -> ControlValue {
    parse_number(value(key).unwrap_or_default(), max, none)
}

fn parse_number(text: &str, max: i32, none: bool) -> ControlValue {
    if none && text == "none" {
        return "none".into();
    }
    if text.is_empty() || !text.bytes().all(|c| c.is_ascii_digit()) {
        return "unknown".into();
    }
    text.parse::<i32>()
        .ok()
        .filter(|v| *v <= max)
        .map(ControlValue::Integer)
        .unwrap_or_else(|| "unknown".into())
}

fn parse_preboot(text: &str) -> &'static str {
    let Some((status, types)) = text.split_once('|') else {
        return "unknown";
    };
    if status == "0" && types.is_empty() {
        return "none";
    }
    if status != "1" {
        return "unknown";
    }
    let types: Option<Vec<u32>> = types.split(',').map(|t| t.parse().ok()).collect();
    let Some(types) = types else {
        return "unknown";
    };
    // Recovery passwords do not establish the normal startup unlock method.
    if types.iter().any(|t| !matches!(t, 1..=10)) {
        return "unknown";
    }
    if types.contains(&1) {
        return "hardware_only";
    }
    if types.iter().any(|t| matches!(t, 2 | 5 | 7 | 9 | 10)) {
        return "unknown";
    }
    if types.iter().any(|t| matches!(t, 4 | 6 | 8)) {
        "user_secret"
    } else {
        "unknown"
    }
}

fn parse_retention(text: &str) -> ControlValue {
    let Some((security, system)) = text.split_once('|') else {
        return "unknown".into();
    };
    match (
        parse_number(security, i32::MAX, false),
        parse_number(system, i32::MAX, false),
    ) {
        (ControlValue::Integer(a), ControlValue::Integer(b)) => ControlValue::Integer(a.min(b)),
        _ => "unknown".into(),
    }
}

fn parse_process_audit(text: &str) -> &'static str {
    let Some((flags, command_line)) = text.split_once('|') else {
        return "unknown";
    };
    let Some(flags) = parse_dword(flags).filter(|f| *f <= 7) else {
        return "unknown";
    };
    if !matches!(command_line, "" | "0" | "1") {
        return "unknown";
    }
    if flags & 1 != 0 && command_line == "1" {
        "on"
    } else {
        "off"
    }
}

fn parse_logging(text: &str) -> &'static str {
    let Some((machine, user)) = text.split_once('|') else {
        return "unknown";
    };
    let effective = if machine.is_empty() { user } else { machine };
    match effective {
        "1" => "on",
        "" | "0" => "off",
        _ => "unknown",
    }
}

fn value(name: &str) -> Option<&'static str> {
    let values = VALUES.get_or_init(|| {
        let out = run_with_timeout(
            "powershell.exe",
            &[
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                POWERSHELL,
            ],
            Duration::from_secs(20),
        )
        .unwrap_or_default();
        parse_values(&out)
    });
    values.get(name).map(String::as_str)
}

fn parse_values(out: &str) -> BTreeMap<String, String> {
    out.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('\t')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

pub fn parse_dword(value: &str) -> Option<u32> {
    let value = value.trim();
    value
        .strip_prefix("0x")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .or_else(|| value.parse().ok())
}

pub fn parse_last_update(value: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(value.trim(), "%Y-%m-%d").ok()
}

/// The Shell property has no official value table, so unrecognized values stay unknown.
pub fn parse_bitlocker(out: &str) -> &'static str {
    match out.trim() {
        "1" => "full",
        "3" | "4" | "5" | "8" => "partial",
        "2" | "7" => "none",
        _ => "unknown",
    }
}

pub fn parse_firewall(out: &str) -> &'static str {
    let profiles: Vec<&str> = out.split_whitespace().collect();
    if profiles.len() != 3 || !profiles.iter().all(|p| matches!(*p, "True" | "False")) {
        "unknown"
    } else if profiles.iter().all(|p| *p == "True") {
        "on"
    } else {
        "off"
    }
}

pub fn parse_screen_saver(
    active: Option<&str>,
    secure: Option<&str>,
    timeout: Option<&str>,
) -> &'static str {
    match (active, secure) {
        (Some("0"), _) | (Some("1"), Some("0")) => "none",
        (Some("1"), Some("1")) => timeout
            .and_then(|t| t.trim().parse::<u64>().ok())
            .map_or("unknown", buckets::lock_delay),
        _ => "unknown",
    }
}

pub fn parse_os_supported(data: &str, today: NaiveDate) -> &'static str {
    let mut fields = data.split('|');
    let (Some(build), Some(version), Some(edition), Some(install_type)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return "unknown";
    };
    let Ok(build) = build.parse::<u32>() else {
        return "unknown";
    };
    if !install_type.eq_ignore_ascii_case("Client") {
        return "no";
    }
    if !is_known_client_edition(edition) {
        return "unknown";
    }
    let supported_until = match (build, version, edition) {
        (14393, "1607", "EnterpriseS") => Some((2026, 10, 13)),
        (14393, "1607", "IoTEnterpriseS") => Some((2032, 1, 13)),
        (17763, "1809", "EnterpriseS" | "IoTEnterpriseS") => Some((2029, 1, 9)),
        (19044, "21H2", "EnterpriseS") => Some((2027, 1, 12)),
        (19044, "21H2", "IoTEnterpriseS") => Some((2032, 1, 13)),
        (22631, "23H2", "Enterprise" | "Education") => Some((2026, 11, 10)),
        (26100, "24H2", "EnterpriseS") => Some((2029, 10, 9)),
        (26100, "24H2", "IoTEnterpriseS") => Some((2034, 10, 10)),
        (26100, "24H2", "Enterprise" | "Education") => Some((2027, 10, 12)),
        (
            26100,
            "24H2",
            "Core"
            | "CoreSingleLanguage"
            | "Professional"
            | "ProfessionalEducation"
            | "ProfessionalWorkstation",
        ) => Some((2026, 10, 13)),
        (
            26200,
            "25H2",
            "Core"
            | "CoreSingleLanguage"
            | "Professional"
            | "ProfessionalEducation"
            | "ProfessionalWorkstation",
        ) => Some((2027, 10, 12)),
        (26200, "25H2", "Enterprise" | "Education") => Some((2028, 10, 11)),
        (build, "26H1", edition) if build >= 28000 && is_consumer_edition(edition) => {
            Some((2028, 3, 15))
        }
        (build, "26H1", "Enterprise" | "Education") if build >= 28000 => Some((2029, 3, 14)),
        (build, "26H2", edition) if build >= 26300 && is_consumer_edition(edition) => {
            Some((2028, 10, 9))
        }
        (build, "26H2", "Enterprise" | "Education") if build >= 26300 => Some((2029, 10, 9)),
        (19045, "22H2", _) => return "unknown",
        (_, _, edition) if edition.ends_with('S') => return "unknown",
        _ => None,
    };
    supported_until
        .and_then(|(y, m, d)| NaiveDate::from_ymd_opt(y, m, d))
        .map_or("no", |end| if today <= end { "yes" } else { "no" })
}

fn is_consumer_edition(edition: &str) -> bool {
    matches!(
        edition,
        "Core"
            | "CoreSingleLanguage"
            | "Professional"
            | "ProfessionalEducation"
            | "ProfessionalWorkstation"
    )
}

fn is_known_client_edition(edition: &str) -> bool {
    is_consumer_edition(edition)
        || matches!(
            edition,
            "Enterprise" | "Education" | "EnterpriseS" | "IoTEnterprise" | "IoTEnterpriseS"
        )
}

pub fn parse_auto_login(value: &str) -> &'static str {
    match value.trim() {
        "1" => "on",
        "0" | "" => "off",
        _ => "unknown",
    }
}

/// Security Center does not document `productState`; its bit layout is community-derived.
pub fn parse_antimalware(out: &str) -> &'static str {
    if out.trim() == "defender=yes" {
        return "yes";
    }
    let states: Vec<u32> = out
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    if states.is_empty() {
        "unknown"
    } else if states.iter().any(|s| (s >> 12) & 0xF == 1) {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn native_batch_emits_every_non_browser_metric() {
        for key in [
            "preboot",
            "signature_days",
            "full_scan_days",
            "detections_7d",
            "last_detection_hours",
            "log_retention",
            "log_cleared",
            "process_audit",
            "powershell_logging",
        ] {
            assert!(value(key).is_some(), "batch did not emit {key}");
        }
    }

    #[test]
    fn preboot_protectors_exclude_recovery_and_weak_unlock_paths() {
        for (raw, expected) in [
            ("0|", "none"),
            ("1|1,3", "hardware_only"),
            ("1|4,3", "user_secret"),
            ("1|6,3", "user_secret"),
            ("1|8,3", "user_secret"),
            ("1|1,4,3", "hardware_only"),
            ("1|3", "unknown"),
            ("1|2,4", "unknown"),
            ("1|0,4", "unknown"),
            ("1|", "unknown"),
            ("unknown", "unknown"),
            ("Access denied", "unknown"),
        ] {
            assert_eq!(parse_preboot(raw), expected, "{raw}");
        }
    }

    #[test]
    fn numeric_metrics_reject_missing_localized_and_out_of_range_values() {
        for (raw, expected) in [("0", 0), ("3", 3), ("3650", 3650)] {
            assert_eq!(
                parse_number(raw, 3650, false),
                ControlValue::Integer(expected)
            );
        }
        for raw in [
            "",
            "unknown",
            "!",
            "-1",
            "+1",
            "3.0",
            "3,0",
            "3651",
            "18446744073709551616",
            "none",
            "n/a",
        ] {
            assert_eq!(parse_number(raw, 3650, false), "unknown", "{raw}");
        }
        assert_eq!(
            parse_number("10000", 10000, false),
            ControlValue::Integer(10000)
        );
        assert_eq!(parse_number("10001", 10000, false), "unknown");
        assert_eq!(
            parse_number("8760", 8760, true),
            ControlValue::Integer(8760)
        );
        assert_eq!(parse_number("8761", 8760, true), "unknown");
        assert_eq!(parse_number("none", 8760, true), "none");
    }

    #[test]
    fn retention_needs_both_logs_and_reports_the_shorter_history() {
        assert_eq!(parse_retention("12|30"), ControlValue::Integer(12));
        assert_eq!(parse_retention("31|0"), ControlValue::Integer(0));
        assert_eq!(parse_retention("4000|5000"), ControlValue::Integer(4000));
        for raw in ["12|unknown", "unknown|12", "12|", "12", "12|30|40", "!"] {
            assert_eq!(parse_retention(raw), "unknown", "{raw}");
        }
    }

    #[test]
    fn process_creation_requires_success_audit_and_command_line() {
        for (raw, expected) in [
            ("1|1", "on"),
            ("3|1", "on"),
            ("0|1", "off"),
            ("2|1", "off"),
            ("4|1", "off"),
            ("1|0", "off"),
            ("1|", "off"),
            ("1|!", "unknown"),
            ("!|1", "unknown"),
            ("8|1", "unknown"),
            ("unknown", "unknown"),
        ] {
            assert_eq!(parse_process_audit(raw), expected, "{raw}");
        }
    }

    #[test]
    fn script_block_logging_uses_machine_policy_before_user_policy() {
        for (raw, expected) in [
            ("1|0", "on"),
            ("0|1", "off"),
            ("|1", "on"),
            ("|0", "off"),
            ("|", "off"),
            ("!|1", "unknown"),
            ("|!", "unknown"),
            ("2|", "unknown"),
            ("unknown", "unknown"),
        ] {
            assert_eq!(parse_logging(raw), expected, "{raw}");
        }
    }

    #[test]
    fn patch_age_returns_integer_days_and_rejects_future_dates() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
        assert_eq!(
            parse_patch_age("2026-10-13", today),
            ControlValue::Integer(7)
        );
        assert_eq!(
            parse_patch_age("2026-10-20", today),
            ControlValue::Integer(0)
        );
        assert_eq!(parse_patch_age("2026-10-21", today), "unknown");
    }

    #[test]
    fn dword() {
        assert_eq!(parse_dword("0x1"), Some(1));
        assert_eq!(parse_dword("0x384"), Some(900));
        assert_eq!(parse_dword("900"), Some(900));
        assert_eq!(parse_dword("bad"), None);
    }

    #[test]
    fn values_use_tagged_lines() {
        let out = "bitlocker\t1\r\nfirewall\tTrue False True\r\nwarning text\r\n";
        let values = parse_values(out);
        assert_eq!(values.get("bitlocker").map(String::as_str), Some("1"));
        assert_eq!(
            values.get("firewall").map(String::as_str),
            Some("True False True")
        );
        assert!(!values.contains_key("warning text"));
    }

    #[test]
    fn bitlocker() {
        assert_eq!(parse_bitlocker("1\r\n"), "full");
        assert_eq!(parse_bitlocker("2"), "none");
        assert_eq!(parse_bitlocker("3"), "partial");
        assert_eq!(parse_bitlocker("4"), "partial");
        assert_eq!(parse_bitlocker("5"), "partial");
        assert_eq!(parse_bitlocker("6"), "unknown");
        assert_eq!(parse_bitlocker("7"), "none");
        assert_eq!(parse_bitlocker("8"), "partial");
        assert_eq!(parse_bitlocker("0"), "unknown");
        assert_eq!(parse_bitlocker(""), "unknown");
    }

    #[test]
    fn firewall() {
        assert_eq!(parse_firewall("True\r\nTrue\r\nTrue\r\n"), "on");
        assert_eq!(parse_firewall("True\r\nFalse\r\nTrue\r\n"), "off");
        assert_eq!(parse_firewall("True\r\nTrue\r\n"), "unknown");
        assert_eq!(
            parse_firewall("Get-NetFirewallProfile : Access denied"),
            "unknown"
        );
    }

    #[test]
    fn screen_saver() {
        let saver = |t| parse_screen_saver(Some("1"), Some("1"), Some(t));
        assert_eq!(saver("300"), "le_5min");
        assert_eq!(saver("900"), "le_15min");
        assert_eq!(saver("1200"), "gt_15min");
        assert_eq!(
            parse_screen_saver(Some("1"), Some("0"), Some("300")),
            "none"
        );
        assert_eq!(
            parse_screen_saver(Some("0"), Some("1"), Some("300")),
            "none"
        );
        assert_eq!(parse_screen_saver(None, None, None), "unknown");
    }

    #[test]
    fn os_supported() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
        assert_eq!(
            parse_os_supported("26200|25H2|Professional|Client", today),
            "yes"
        );
        assert_eq!(
            parse_os_supported("26100|24H2|Professional|Client", today),
            "no"
        );
        assert_eq!(
            parse_os_supported("19045|22H2|Professional|Client", today),
            "unknown"
        );
        assert_eq!(
            parse_os_supported("19044|21H2|EnterpriseS|Client", today),
            "yes"
        );
        assert_eq!(
            parse_os_supported("19044|21H2|IoTEnterpriseS|Client", today),
            "yes"
        );
        assert_eq!(
            parse_os_supported(
                "19044|21H2|EnterpriseS|Client",
                NaiveDate::from_ymd_opt(2027, 1, 13).unwrap()
            ),
            "no"
        );
        assert_eq!(parse_os_supported("bad", today), "unknown");
    }

    #[test]
    fn patch_age_is_unknown_without_lcu_evidence() {
        assert_eq!(
            parse_last_update("2026-10-13\r\n"),
            NaiveDate::from_ymd_opt(2026, 10, 13)
        );
        assert_eq!(parse_last_update("October 13, 2026"), None);
        assert_eq!(
            parse_patch_age("", NaiveDate::from_ymd_opt(2026, 10, 20).unwrap()),
            "unknown"
        );
    }

    #[test]
    fn auto_login() {
        assert_eq!(parse_auto_login("1"), "on");
        assert_eq!(parse_auto_login("0"), "off");
        assert_eq!(parse_auto_login(""), "off");
        assert_eq!(parse_auto_login("enabled"), "unknown");
    }

    #[test]
    fn antimalware() {
        assert_eq!(parse_antimalware("397568\r\n"), "yes");
        assert_eq!(parse_antimalware("393472\r\n"), "no");
        assert_eq!(parse_antimalware("393472\r\n397568\r\n"), "yes");
        assert_eq!(parse_antimalware(""), "unknown");
        assert_eq!(parse_antimalware("defender=yes"), "yes");
    }
}
