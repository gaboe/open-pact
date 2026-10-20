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
    parse_screen_savers(value("screen_savers").unwrap_or_default()).into()
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
                .filter(|days| (0..=3650).contains(days))
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

pub fn web_protection() -> ControlValue {
    super::browsers::windows(
        value("smartscreen").unwrap_or_default(),
        value("browsers").unwrap_or_default(),
    )
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

#[cfg(target_os = "windows")]
pub(super) fn event_markers() -> super::EventMarkerReads {
    super::EventMarkerReads {
        security_log_cleared: event_marker_read("security_log_cleared_epoch"),
        antimalware_detection: event_marker_read("antimalware_detection_epoch"),
    }
}

#[cfg(target_os = "windows")]
fn event_marker_read(key: &str) -> super::EventMarkerRead {
    parse_event_marker_read(value(key))
}

#[cfg(any(target_os = "windows", test))]
fn parse_event_marker_read(value: Option<&str>) -> super::EventMarkerRead {
    value
        .and_then(parse_event_marker)
        .map(super::EventMarkerRead::Read)
        .unwrap_or_default()
}

#[cfg(any(target_os = "windows", test))]
fn parse_event_marker(value: &str) -> Option<Option<i64>> {
    if value == "none" {
        Some(None)
    } else {
        value.parse().ok().map(Some)
    }
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
    if !machine.is_empty() {
        return match machine {
            "1" => "on",
            "0" => "off",
            _ => "unknown",
        };
    }
    let users = user.split(';').collect::<Vec<_>>();
    if users.iter().any(|value| matches!(*value, "" | "0")) {
        "off"
    } else if users.iter().all(|value| *value == "1") {
        "on"
    } else {
        "unknown"
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
        (Some("1"), Some("1")) => {
            timeout
                .and_then(|t| t.trim().parse::<u64>().ok())
                .map_or("unknown", |seconds| {
                    if seconds == 0 {
                        "none"
                    } else {
                        buckets::lock_delay(seconds)
                    }
                })
        }
        _ => "unknown",
    }
}

fn parse_screen_savers(data: &str) -> &'static str {
    let mut weakest = "le_5min";
    if data.is_empty() {
        return "unknown";
    }
    for user in data.split(';') {
        let fields: Vec<_> = user.split('|').collect();
        let [active, secure, timeout, executable] = fields.as_slice() else {
            return "unknown";
        };
        let state = parse_screen_saver(Some(active), Some(secure), Some(timeout));
        let state = match (state, *executable) {
            ("none" | "unknown", _) => state,
            (_, "valid") => state,
            (_, "missing") => "none",
            _ => "unknown",
        };
        if state == "unknown" {
            return "unknown";
        }
        let rank = |value| match value {
            "none" => 3,
            "gt_15min" => 2,
            "le_15min" => 1,
            _ => 0,
        };
        if rank(state) > rank(weakest) {
            weakest = state;
        }
    }
    weakest
}

struct Lifecycle {
    build: u32,
    version: &'static str,
    editions: &'static [&'static str],
    server: bool,
    end: (i32, u32, u32),
}

const CONSUMER: &[&str] = &[
    "Core",
    "CoreSingleLanguage",
    "Professional",
    "ProfessionalEducation",
    "ProfessionalWorkstation",
];
const ENTERPRISE: &[&str] = &["Enterprise", "Education", "ServerRdsh"];
const ENTERPRISE_IOT: &[&str] = &["Enterprise", "Education", "ServerRdsh", "IoTEnterprise"];
const LTSC: &[&str] = &["EnterpriseS"];
const IOT_LTSC: &[&str] = &["IoTEnterpriseS"];
const LTSC_IOT: &[&str] = &["EnterpriseS", "IoTEnterpriseS"];
const SERVER: &[&str] = &[
    "ServerStandard",
    "ServerDatacenter",
    "ServerStandardEval",
    "ServerDatacenterEval",
    "ServerAzureCor",
    "ServerDatacenterAzureEdition",
    "ServerSolution",
];

const LIFECYCLES: &[Lifecycle] = &[
    Lifecycle {
        build: 10240,
        version: "1507",
        editions: LTSC_IOT,
        server: false,
        end: (2025, 10, 14),
    },
    Lifecycle {
        build: 14393,
        version: "1607",
        editions: LTSC_IOT,
        server: false,
        end: (2026, 10, 13),
    },
    Lifecycle {
        build: 17763,
        version: "1809",
        editions: LTSC_IOT,
        server: false,
        end: (2029, 1, 9),
    },
    Lifecycle {
        build: 19044,
        version: "21H2",
        editions: LTSC,
        server: false,
        end: (2027, 1, 12),
    },
    Lifecycle {
        build: 19044,
        version: "21H2",
        editions: IOT_LTSC,
        server: false,
        end: (2032, 1, 13),
    },
    Lifecycle {
        build: 26100,
        version: "24H2",
        editions: LTSC,
        server: false,
        end: (2029, 10, 9),
    },
    Lifecycle {
        build: 26100,
        version: "24H2",
        editions: IOT_LTSC,
        server: false,
        end: (2034, 10, 10),
    },
    Lifecycle {
        build: 22000,
        version: "21H2",
        editions: CONSUMER,
        server: false,
        end: (2023, 10, 10),
    },
    Lifecycle {
        build: 22000,
        version: "21H2",
        editions: ENTERPRISE_IOT,
        server: false,
        end: (2024, 10, 8),
    },
    Lifecycle {
        build: 22621,
        version: "22H2",
        editions: CONSUMER,
        server: false,
        end: (2024, 10, 8),
    },
    Lifecycle {
        build: 22621,
        version: "22H2",
        editions: ENTERPRISE_IOT,
        server: false,
        end: (2025, 10, 14),
    },
    Lifecycle {
        build: 22631,
        version: "23H2",
        editions: CONSUMER,
        server: false,
        end: (2025, 11, 11),
    },
    Lifecycle {
        build: 22631,
        version: "23H2",
        editions: ENTERPRISE_IOT,
        server: false,
        end: (2026, 11, 10),
    },
    Lifecycle {
        build: 26100,
        version: "24H2",
        editions: CONSUMER,
        server: false,
        end: (2026, 10, 13),
    },
    Lifecycle {
        build: 26100,
        version: "24H2",
        editions: ENTERPRISE_IOT,
        server: false,
        end: (2027, 10, 12),
    },
    Lifecycle {
        build: 26200,
        version: "25H2",
        editions: CONSUMER,
        server: false,
        end: (2027, 10, 12),
    },
    Lifecycle {
        build: 26200,
        version: "25H2",
        editions: ENTERPRISE_IOT,
        server: false,
        end: (2028, 10, 10),
    },
    Lifecycle {
        build: 26300,
        version: "26H2",
        editions: CONSUMER,
        server: false,
        end: (2028, 10, 10),
    },
    Lifecycle {
        build: 26300,
        version: "26H2",
        editions: ENTERPRISE_IOT,
        server: false,
        end: (2029, 10, 9),
    },
    Lifecycle {
        build: 28000,
        version: "26H1",
        editions: CONSUMER,
        server: false,
        end: (2028, 3, 14),
    },
    Lifecycle {
        build: 28000,
        version: "26H1",
        editions: ENTERPRISE,
        server: false,
        end: (2029, 3, 13),
    },
    Lifecycle {
        build: 14393,
        version: "",
        editions: SERVER,
        server: true,
        end: (2027, 1, 12),
    },
    Lifecycle {
        build: 17763,
        version: "",
        editions: SERVER,
        server: true,
        end: (2029, 1, 9),
    },
    Lifecycle {
        build: 20348,
        version: "",
        editions: SERVER,
        server: true,
        end: (2031, 10, 14),
    },
    Lifecycle {
        build: 26100,
        version: "",
        editions: SERVER,
        server: true,
        end: (2034, 11, 14),
    },
];

pub fn parse_os_supported(data: &str, today: NaiveDate) -> &'static str {
    let fields: Vec<_> = data.split('|').collect();
    let [build, version, edition, install_type] = fields.as_slice() else {
        return "unknown";
    };
    let Ok(build) = build.parse::<u32>() else {
        return "unknown";
    };
    let server = match *install_type {
        "Client" => false,
        "Server" | "Server Core" => true,
        _ => return "unknown",
    };
    LIFECYCLES
        .iter()
        .find(|row| {
            row.build == build
                && row.server == server
                && row.editions.contains(edition)
                && (server || version.is_empty() || row.version == *version)
        })
        .and_then(|row| NaiveDate::from_ymd_opt(row.end.0, row.end.1, row.end.2))
        .map_or("unknown", |end| if today <= end { "yes" } else { "no" })
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
    use crate::checks::{EventMarkerRead, EventMarkerReads};

    #[test]
    #[cfg(windows)]
    fn native_batch_emits_every_metric() {
        for key in [
            "screen_savers",
            "lock_policy",
            "os",
            "patch_date",
            "preboot",
            "signature_days",
            "full_scan_days",
            "detections_7d",
            "last_detection_hours",
            "security_log_cleared_epoch",
            "antimalware_detection_epoch",
            "log_retention",
            "log_cleared",
            "process_audit",
            "powershell_logging",
            "smartscreen",
            "browsers",
        ] {
            assert!(value(key).is_some(), "batch did not emit {key}");
        }
    }

    #[test]
    fn captured_windows_admin_batch_values() {
        let values = parse_values(concat!(
            "preboot\t0|\r\n",
            "signature_days\t0\r\n",
            "full_scan_days\tunknown\r\n",
            "detections_7d\t0\r\n",
            "last_detection_hours\tnone\r\n",
            "security_log_cleared_epoch\t1792500000\r\n",
            "antimalware_detection_epoch\tnone\r\n",
            "log_retention\t12|12\r\n",
            "log_cleared\t296\r\n",
            "process_audit\t1|\r\n",
            "powershell_logging\t|\r\n",
        ));
        assert_eq!(parse_preboot(&values["preboot"]), "none");
        assert_eq!(
            parse_number(&values["signature_days"], 3650, false),
            ControlValue::Integer(0)
        );
        assert_eq!(
            parse_number(&values["full_scan_days"], 3650, false),
            "unknown"
        );
        assert_eq!(
            parse_number(&values["detections_7d"], 10000, false),
            ControlValue::Integer(0)
        );
        assert_eq!(
            parse_number(&values["last_detection_hours"], 8760, true),
            "none"
        );
        assert_eq!(
            parse_event_marker(&values["security_log_cleared_epoch"]),
            Some(Some(1_792_500_000))
        );
        assert_eq!(
            parse_event_marker(&values["antimalware_detection_epoch"]),
            Some(None)
        );
        assert_eq!(parse_event_marker("unknown"), None);
        assert_eq!(
            parse_retention(&values["log_retention"]),
            ControlValue::Integer(12)
        );
        assert_eq!(
            parse_number(&values["log_cleared"], 8760, true),
            ControlValue::Integer(296)
        );
        assert_eq!(parse_process_audit(&values["process_audit"]), "off");
        assert_eq!(parse_logging(&values["powershell_logging"]), "off");
    }

    #[test]
    fn event_marker_reads_keep_sources_independent() {
        assert_eq!(
            parse_event_marker_read(Some("1792500000")),
            EventMarkerRead::Read(Some(1_792_500_000))
        );
        assert_eq!(
            parse_event_marker_read(Some("none")),
            EventMarkerRead::Read(None)
        );
        assert_eq!(
            parse_event_marker_read(Some("unknown")),
            EventMarkerRead::Unknown
        );
        assert_eq!(parse_event_marker_read(None), EventMarkerRead::Unknown);
        let reads = EventMarkerReads {
            security_log_cleared: parse_event_marker_read(Some("1792500000")),
            antimalware_detection: parse_event_marker_read(Some("unknown")),
        };
        assert_eq!(
            reads.security_log_cleared,
            EventMarkerRead::Read(Some(1_792_500_000))
        );
        assert_eq!(reads.antimalware_detection, EventMarkerRead::Unknown);
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
            ("|1;0", "off"),
            ("|1;!", "unknown"),
            ("|1;1", "on"),
            ("1|!;0", "on"),
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
        assert_eq!(parse_patch_age("2000-01-01", today), "unknown");
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
    fn screen_savers_require_executable_evidence_and_all_users() {
        for (data, expected) in [
            ("1|1|300|valid", "le_5min"),
            ("1|1|300|missing", "none"),
            ("1|1|300|unknown", "unknown"),
            ("1|1|0|valid", "none"),
            ("0|||unknown", "none"),
            ("1|0||unknown", "none"),
            ("1|1|300|valid;1|1|1200|valid", "gt_15min"),
            ("1|1|300|valid;0|||unknown", "none"),
            ("1|1|300|valid;!|!|!|unknown", "unknown"),
            ("!|!|!|unknown;0|||unknown", "unknown"),
            ("1|1|300|valid;", "unknown"),
            ("", "unknown"),
            ("unknown", "unknown"),
        ] {
            assert_eq!(parse_screen_savers(data), expected, "{data}");
        }
    }

    #[test]
    fn lifecycle_dates_match_published_release_dates() {
        for (raw, end) in [
            ("10240|1507|EnterpriseS|Client", "2025-10-14"),
            ("14393|1607|IoTEnterpriseS|Client", "2026-10-13"),
            ("17763|1809|EnterpriseS|Client", "2029-01-09"),
            ("19044|21H2|EnterpriseS|Client", "2027-01-12"),
            ("19044|21H2|IoTEnterpriseS|Client", "2032-01-13"),
            ("26100|24H2|EnterpriseS|Client", "2029-10-09"),
            ("26100|24H2|IoTEnterpriseS|Client", "2034-10-10"),
            ("22000|21H2|Professional|Client", "2023-10-10"),
            ("22000|21H2|IoTEnterprise|Client", "2024-10-08"),
            ("22621|22H2|Professional|Client", "2024-10-08"),
            ("22621|22H2|IoTEnterprise|Client", "2025-10-14"),
            ("22631|23H2|Professional|Client", "2025-11-11"),
            ("22631|23H2|IoTEnterprise|Client", "2026-11-10"),
            ("26100|24H2|Professional|Client", "2026-10-13"),
            ("26100|24H2|IoTEnterprise|Client", "2027-10-12"),
            ("26200|25H2|Professional|Client", "2027-10-12"),
            ("26200|25H2|IoTEnterprise|Client", "2028-10-10"),
            ("26300|26H2|Professional|Client", "2028-10-10"),
            ("26300|26H2|IoTEnterprise|Client", "2029-10-09"),
            ("28000|26H1|Professional|Client", "2028-03-14"),
            ("28000|26H1|Enterprise|Client", "2029-03-13"),
            ("14393|1607|ServerStandard|Server", "2027-01-12"),
            ("17763|1809|ServerStandard|Server", "2029-01-09"),
            ("20348|21H2|ServerStandard|Server", "2031-10-14"),
            ("26100|24H2|ServerStandard|Server", "2034-11-14"),
        ] {
            let end = NaiveDate::parse_from_str(end, "%Y-%m-%d").unwrap();
            assert_eq!(parse_os_supported(raw, end), "yes", "{raw}");
            assert_eq!(
                parse_os_supported(raw, end.succ_opt().unwrap()),
                "no",
                "{raw}"
            );
        }
    }

    #[test]
    fn every_lifecycle_row_and_edition_is_reachable_at_its_boundary() {
        for row in LIFECYCLES {
            let last = NaiveDate::from_ymd_opt(row.end.0, row.end.1, row.end.2).unwrap();
            for edition in row.editions {
                for install in if row.server {
                    &["Server", "Server Core"][..]
                } else {
                    &["Client"][..]
                } {
                    for version in [row.version, ""] {
                        let raw = format!("{}|{version}|{edition}|{install}", row.build);
                        assert_eq!(parse_os_supported(&raw, last), "yes", "{raw}");
                        assert_eq!(
                            parse_os_supported(&raw, last.succ_opt().unwrap()),
                            "no",
                            "{raw}"
                        );
                    }
                }
            }
        }
        let today = NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
        for raw in [
            "26100|24H2|UnknownEdition|Client",
            "26100|24H2|Professional|Server",
            "28001|26H1|Professional|Client",
            "26100|future|Professional|Client",
            "26100|24H2|Professional|Other",
            "26100|24H2|Professional|Client|extra",
        ] {
            assert_eq!(parse_os_supported(raw, today), "unknown", "{raw}");
        }
    }

    #[test]
    fn disabled_screen_saver_timer_is_not_a_lock() {
        assert_eq!(parse_screen_saver(Some("1"), Some("1"), Some("0")), "none");
    }

    #[test]
    fn windows_iot_releases_have_their_own_lifecycle() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
        for data in [
            "22631|23H2|IoTEnterprise|Client",
            "26100|24H2|IoTEnterprise|Client",
            "26200|25H2|IoTEnterprise|Client",
        ] {
            assert_eq!(parse_os_supported(data, today), "yes", "{data}");
        }
        assert_eq!(
            parse_os_supported("14393|1607|IoTEnterpriseS|Client", today),
            "no"
        );
    }

    #[test]
    fn supported_servers_use_server_lifecycle() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
        for data in [
            "14393|1607|ServerStandard|Server",
            "17763|1809|ServerDatacenter|Server Core",
            "20348|21H2|ServerStandard|Server",
            "26100|24H2|ServerDatacenter|Server",
        ] {
            assert_eq!(parse_os_supported(data, today), "yes", "{data}");
        }
        assert_eq!(
            parse_os_supported("99999|future|ServerStandard|Server", today),
            "unknown"
        );
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
