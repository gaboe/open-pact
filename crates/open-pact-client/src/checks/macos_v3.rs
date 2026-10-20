use std::fs;

use chrono::{DateTime, Utc};
use open_pact_core::ControlValue;
use serde_json::Value;

use super::exec::{run_status, run_with_timeout};

const XPROTECT: &str =
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist";
const REMEDIATOR: &str =
    "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect";
const HISTORY: &str = "/Library/Receipts/InstallHistory.plist";
const SCAN_SERVICE: &str = "com.apple.XProtect.daemon.scan";

fn command(program: &str, args: &[&str]) -> Option<String> {
    run_status(program, args)
        .filter(|r| r.success)
        .map(|r| r.text)
}

pub fn preboot_auth() -> ControlValue {
    command("/usr/bin/fdesetup", &["status"])
        .map_or("unknown", |s| parse_preboot(&s))
        .into()
}

fn parse_preboot(text: &str) -> &'static str {
    match text.trim() {
        "FileVault is On." => "user_secret",
        "FileVault is Off." => "none",
        _ => "unknown",
    }
}

pub fn antimalware_active() -> &'static str {
    let bundle = fs::metadata(XPROTECT);
    let remediator = fs::metadata(REMEDIATOR);
    if [&bundle, &remediator].iter().any(|m| {
        m.as_ref()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    }) {
        return "no";
    }
    if bundle.is_err() || remediator.is_err() {
        return "unknown";
    }
    let Some(disabled) = command("/bin/launchctl", &["print-disabled", "system"]) else {
        return "unknown";
    };
    let service = command(
        "/bin/launchctl",
        &["print", "system/com.apple.XProtect.daemon.scan"],
    );
    parse_xprotect(&disabled, service.as_deref())
}

fn parse_xprotect(disabled: &str, service: Option<&str>) -> &'static str {
    if !disabled.contains("disabled services = {") || !disabled.trim_end().ends_with('}') {
        return "unknown";
    }
    for line in disabled.lines().map(str::trim) {
        if let Some((name, value)) = line.split_once(" => ")
            && name
                .trim_matches('"')
                .to_ascii_lowercase()
                .starts_with("com.apple.xprotect")
        {
            match value {
                "true" | "disabled" => return "no",
                "false" | "enabled" => (),
                _ => return "unknown",
            }
        }
    }
    match service {
        // An on-demand daemon can be idle between scans. It must still be registered.
        Some(text)
            if text.contains(SCAN_SERVICE)
                && text.contains("program = ")
                && !text.lines().map(str::trim).any(|line| {
                    line.strip_prefix("last exit code = ")
                        .is_some_and(|code| code.parse::<i32>() != Ok(0))
                        || line == "state = spawn scheduled"
                }) =>
        {
            "yes"
        }
        _ => "unknown",
    }
}

pub fn antimalware_signature_age_days() -> ControlValue {
    let Some(version) = command(
        "/usr/bin/plutil",
        &[
            "-extract",
            "CFBundleShortVersionString",
            "raw",
            "-o",
            "-",
            XPROTECT,
        ],
    ) else {
        return "unknown".into();
    };
    let Some(history) = command("/usr/bin/plutil", &["-p", HISTORY]) else {
        return "unknown".into();
    };
    parse_signature_age(&history, version.trim(), Utc::now())
}

fn parse_signature_age(history: &str, installed_version: &str, now: DateTime<Utc>) -> ControlValue {
    if !history.trim_start().starts_with('[') || !history.trim_end().ends_with(']') {
        return "unknown".into();
    }
    let mut date = None;
    let mut name = "";
    let mut version = "";
    let mut last = None;
    for line in history.lines().map(str::trim) {
        if line.ends_with("=> {") {
            date = None;
            name = "";
            version = "";
        } else if let Some(value) = line.strip_prefix("\"date\" => ") {
            date = DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S %z")
                .ok()
                .map(|date| date.with_timezone(&Utc));
        } else if let Some(value) = line.strip_prefix("\"displayName\" => ") {
            name = value.trim_matches('"');
        } else if let Some(value) = line.strip_prefix("\"displayVersion\" => ") {
            version = value.trim_matches('"');
        } else if line == "}" && name == "XProtectPlistConfigData" && version == installed_version {
            last = last.max(date);
        }
    }
    last.map_or_else(
        || "unknown".into(),
        |date| bounded_age((now - date).num_days(), 3650),
    )
}

pub(super) fn bounded_age(age: i64, max: i32) -> ControlValue {
    if (0..=i64::from(max)).contains(&age) {
        (age as i32).into()
    } else {
        "unknown".into()
    }
}

pub fn not_applicable() -> ControlValue {
    "n/a".into()
}
pub fn unknown() -> ControlValue {
    "unknown".into()
}

pub fn antimalware_detections_7d() -> ControlValue {
    detection_log()
}
pub fn antimalware_last_detection_hours() -> ControlValue {
    detection_log()
}

fn detection_log() -> ControlValue {
    let output = run_with_timeout(
        "/usr/bin/log",
        &[
            "show",
            "--style",
            "json",
            "--last",
            "7d",
            "--info",
            "--predicate",
            "subsystem BEGINSWITH \"com.apple.XProtect\" OR process BEGINSWITH \"XProtectRemediator\"",
        ],
        std::time::Duration::from_secs(20),
    );
    parse_detection_log(output.as_deref())
}

fn parse_detection_log(output: Option<&str>) -> ControlValue {
    // Apple does not publish a stable detection-event schema or guarantee seven days of
    // retention. Empty, redacted, partial or unrecognized output cannot establish zero.
    let _ = output.and_then(|s| serde_json::from_str::<Value>(s).ok());
    "unknown".into()
}

pub fn web_protection() -> ControlValue {
    super::browsers::macos().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filevault_preboot() {
        assert_eq!(parse_preboot("FileVault is On.\n"), "user_secret");
        assert_eq!(parse_preboot("FileVault is Off.\n"), "none");
        assert_eq!(
            parse_preboot("FileVault is On.\nEncryption in progress"),
            "unknown"
        );
    }
    #[test]
    fn registered_xprotect_can_be_idle_but_not_disabled() {
        let service = "system/com.apple.XProtect.daemon.scan = {\n program = /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect\n state = not running\n}";
        assert_eq!(
            parse_xprotect("disabled services = {\n}\n", Some(service)),
            "yes"
        );
        assert_eq!(
            parse_xprotect(
                "disabled services = {\n \"com.apple.XProtect.daemon.scan\" => true\n}",
                Some(service)
            ),
            "no"
        );
        assert_eq!(
            parse_xprotect("disabled services = {\n}\n", None),
            "unknown"
        );
        assert_eq!(
            parse_xprotect("Operation not permitted", Some(service)),
            "unknown"
        );
    }

    #[test]
    fn failed_xprotect_scan_is_not_healthy() {
        let service = "system/com.apple.XProtect.daemon.scan = {\n program = /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect\n state = spawn scheduled\n last exit code = 78\n}";
        assert_eq!(
            parse_xprotect("disabled services = {\n}\n", Some(service)),
            "unknown"
        );
    }
    #[test]
    fn signature_receipt_must_match_installed_definitions() {
        let history = r#"[
  0 => {
    "date" => 2026-10-14 17:16:24 +0000
    "displayName" => "XProtectPlistConfigData"
    "displayVersion" => "5367"
  }
  1 => {
    "date" => 2026-10-19 01:00:00 +0000
    "displayName" => "XProtectPayloads"
    "displayVersion" => "163"
  }
]"#;
        let now = DateTime::parse_from_rfc3339("2026-10-20T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            parse_signature_age(history, "5367", now),
            ControlValue::Integer(5)
        );
        assert_eq!(parse_signature_age(history, "5366", now), "unknown");
        assert_eq!(
            parse_signature_age(
                history,
                "5367",
                DateTime::parse_from_rfc3339("2026-10-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc)
            ),
            "unknown"
        );
    }

    #[test]
    fn signature_age_counts_completed_elapsed_days() {
        let history = "[\n 0 => {\n \"date\" => 2026-10-19 23:59:00 +0000\n \"displayName\" => \"XProtectPlistConfigData\"\n \"displayVersion\" => \"5367\"\n }\n]";
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-20T00:01:00Z").unwrap();
        assert_eq!(
            parse_signature_age(history, "5367", now.with_timezone(&Utc)),
            ControlValue::Integer(0)
        );
    }
    #[test]
    fn log_absence_and_unverified_events_never_mean_zero() {
        for out in [
            None,
            Some("[]"),
            Some("log: Operation not permitted"),
            Some(r#"[{"eventMessage":"<private>"}]"#),
        ] {
            assert_eq!(parse_detection_log(out), "unknown");
        }
    }
    #[test]
    fn explicit_platform_sentinels() {
        assert_eq!(not_applicable(), "n/a");
    }
}
