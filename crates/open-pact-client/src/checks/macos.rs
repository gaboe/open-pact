use chrono::{NaiveDate, Utc};

use super::buckets;
use super::exec::run;

const SOCKETFILTERFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
const INSTALL_HISTORY: &str = "/Library/Receipts/InstallHistory.plist";
const RELEASED_MAJORS: &[u32] = &[11, 12, 13, 14, 15, 26];

pub fn disk_encryption() -> &'static str {
    run("fdesetup", &["status"]).map_or("unknown", |t| parse_fdesetup(&t))
}

pub fn firewall() -> &'static str {
    run(SOCKETFILTERFW, &["--getglobalstate"]).map_or("unknown", |t| parse_firewall(&t))
}

pub fn screen_lock() -> &'static str {
    run("sysadminctl", &["-screenLock", "status"]).map_or("unknown", |t| parse_screen_lock(&t))
}

pub fn os_supported() -> &'static str {
    run("sw_vers", &["-productVersion"]).map_or("unknown", |t| parse_os_supported(&t))
}

pub fn os_patch_age_days() -> open_pact_core::ControlValue {
    run("plutil", &["-p", INSTALL_HISTORY])
        .and_then(|t| parse_last_macos_update(&t))
        .map_or_else(
            || "unknown".into(),
            |last| buckets::patch_age(last, Utc::now().date_naive()),
        )
}

pub fn auto_login() -> &'static str {
    run(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "autoLoginUser",
        ],
    )
    .map_or("unknown", |t| parse_auto_login(&t))
}

pub fn antimalware_active() -> &'static str {
    super::macos_v3::antimalware_active()
}

pub fn parse_fdesetup(out: &str) -> &'static str {
    if out.contains("FileVault is On") {
        "full"
    } else if out.contains("FileVault is Off") {
        "none"
    } else {
        "unknown"
    }
}

pub fn parse_firewall(out: &str) -> &'static str {
    if out.contains("is enabled") {
        "on"
    } else if out.contains("is disabled") {
        "off"
    } else {
        "unknown"
    }
}

pub fn parse_screen_lock(out: &str) -> &'static str {
    if out.contains("screenLock is off") {
        return "none";
    }
    if out.contains("delay is immediate") {
        return "le_5min";
    }
    let mut words = out
        .split("delay is ")
        .nth(1)
        .map(|rest| rest.split_whitespace())
        .into_iter()
        .flatten();
    let Some(n) = words.next().and_then(|n| n.parse::<u64>().ok()) else {
        return "unknown";
    };
    let seconds = match words.next() {
        Some(unit) if unit.starts_with("min") => n.saturating_mul(60),
        _ => n,
    };
    buckets::lock_delay(seconds)
}

pub fn parse_os_supported(version: &str) -> &'static str {
    let Some(major) = version
        .trim()
        .split('.')
        .next()
        .and_then(|m| m.parse::<u32>().ok())
    else {
        return "unknown";
    };
    let supported = &RELEASED_MAJORS[RELEASED_MAJORS.len() - 3..];
    if supported.contains(&major) || major > RELEASED_MAJORS[RELEASED_MAJORS.len() - 1] {
        "yes"
    } else {
        "no"
    }
}

pub fn parse_last_macos_update(plist: &str) -> Option<NaiveDate> {
    let mut date = None;
    let mut latest = None;
    for line in plist.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("\"date\" => ") {
            date = rest
                .split_whitespace()
                .next()
                .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok());
        } else if let Some(name) = line.strip_prefix("\"displayName\" => \"") {
            let is_release = name.starts_with("macOS ") && name.chars().any(|c| c.is_ascii_digit());
            if is_release {
                latest = latest.max(date);
            }
            date = None;
        }
    }
    latest
}

pub fn parse_auto_login(out: &str) -> &'static str {
    if out.contains("does not exist") {
        "off"
    } else if out.trim().is_empty() {
        "unknown"
    } else {
        "on"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fdesetup() {
        assert_eq!(parse_fdesetup("FileVault is On.\n"), "full");
        assert_eq!(parse_fdesetup("FileVault is Off.\n"), "none");
        assert_eq!(parse_fdesetup("Error: unexpected"), "unknown");
    }

    #[test]
    fn firewall() {
        assert_eq!(parse_firewall("Firewall is enabled. (State = 1)"), "on");
        assert_eq!(parse_firewall("Firewall is disabled. (State = 0)"), "off");
        assert_eq!(parse_firewall(""), "unknown");
    }

    #[test]
    fn screen_lock() {
        let line = |s: &str| format!("2026-01-01 09:00:00.000 sysadminctl[1234:1] screenLock {s}");
        assert_eq!(parse_screen_lock(&line("delay is immediate")), "le_5min");
        assert_eq!(parse_screen_lock(&line("delay is 300 seconds")), "le_5min");
        assert_eq!(parse_screen_lock(&line("delay is 600 seconds")), "le_15min");
        assert_eq!(parse_screen_lock(&line("delay is 15 minutes")), "le_15min");
        assert_eq!(
            parse_screen_lock(&line("delay is 3600 seconds")),
            "gt_15min"
        );
        assert_eq!(parse_screen_lock(&line("is off")), "none");
        assert_eq!(parse_screen_lock("garbage"), "unknown");
    }

    #[test]
    fn os_supported() {
        assert_eq!(parse_os_supported("26.0.1\n"), "yes");
        assert_eq!(parse_os_supported("15.8\n"), "yes");
        assert_eq!(parse_os_supported("14.6.1"), "yes");
        assert_eq!(parse_os_supported("13.7"), "no");
        assert_eq!(parse_os_supported("10.15.7"), "no");
        assert_eq!(parse_os_supported(""), "unknown");
    }

    #[test]
    fn last_update_ignores_non_os_entries() {
        let plist = r#"[
  0 => {
    "date" => 2025-03-01 10:00:00 +0000
    "displayName" => "macOS 15.3"
    "displayVersion" => "15.3"
    "processName" => "softwareupdated"
  }
  1 => {
    "date" => 2025-09-01 10:00:00 +0000
    "displayName" => "Command Line Tools for Xcode"
    "displayVersion" => "16.0"
    "processName" => "softwareupdated"
  }
  2 => {
    "date" => 2025-06-10 10:00:00 +0000
    "displayName" => "macOS Sequoia 15.5"
    "displayVersion" => "15.5"
    "processName" => "softwareupdated"
  }
  3 => {
    "date" => 2025-12-01 10:00:00 +0000
    "displayName" => "Setup macOS Recovery Dependencies"
    "displayVersion" => ""
    "processName" => "installer"
  }
]"#;
        assert_eq!(
            parse_last_macos_update(plist),
            NaiveDate::from_ymd_opt(2025, 6, 10)
        );
        assert_eq!(parse_last_macos_update("[]"), None);
    }

    #[test]
    fn auto_login() {
        let absent = "2026-01-01 09:00:00.000 defaults[1234:1] \nThe domain/default pair of (/Library/Preferences/com.apple.loginwindow, autoLoginUser) does not exist\n";
        assert_eq!(parse_auto_login(absent), "off");
        assert_eq!(parse_auto_login("alice\n"), "on");
        assert_eq!(parse_auto_login(""), "unknown");
    }
}
