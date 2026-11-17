use chrono::{NaiveDate, Utc};

use super::buckets::{self, Lock};
use super::exec::run;

const SOCKETFILTERFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
const INSTALL_HISTORY: &str = "/Library/Receipts/InstallHistory.plist";
/// The screen saver idle time the installed macOS uses when the user and a profile set none.
const SAVER_ENGINE_DEFAULTS: &str =
    "/System/Library/Frameworks/ScreenSaver.framework/Versions/A/Resources/EngineDefaults.plist";
const RELEASED_MAJORS: &[u32] = &[11, 12, 13, 14, 15, 26];

pub fn disk_encryption() -> &'static str {
    run("fdesetup", &["status"]).map_or("unknown", |t| parse_fdesetup(&t))
}

pub fn firewall() -> &'static str {
    run(SOCKETFILTERFW, &["--getglobalstate"]).map_or("unknown", |t| parse_firewall(&t))
}

/// `screen_lock@1`: the password delay only, as `sysadminctl -screenLock` reports it. It does not
/// read what starts the screen saver or turns the display off.
pub fn screen_lock() -> &'static str {
    password_delay().bucket()
}

/// `screen_lock@2`: the time from the last input to a locked screen, in whole minutes. That is
/// the shorter of the screen saver idle time and the display sleep time, plus the password delay.
pub fn screen_lock_minutes() -> open_pact_core::ControlValue {
    let configured = run(
        "defaults",
        &["-currentHost", "read", "com.apple.screensaver", "idleTime"],
    )
    .map_or(Lock::Unknown, |text| parse_saver_idle(&text));
    let saver = saver_idle(configured, || {
        run(
            "plutil",
            &[
                "-extract",
                "idleTime",
                "raw",
                "-o",
                "-",
                SAVER_ENGINE_DEFAULTS,
            ],
        )
        .map_or(Lock::Unknown, |text| parse_saver_idle(&text))
    });
    let display =
        run("pmset", &["-g", "custom"]).map_or(Lock::Unknown, |text| parse_display_sleep(&text));
    total_lock(password_delay(), first_idle_trigger(saver, display)).minutes()
}

fn password_delay() -> Lock {
    run("sysadminctl", &["-screenLock", "status"])
        .map_or(Lock::Unknown, |t| parse_password_delay(&t))
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

#[cfg(test)]
pub fn parse_screen_lock(out: &str) -> &'static str {
    parse_password_delay(out).bucket()
}

/// The password delay in `sysadminctl -screenLock status`. `None` when no password is required.
pub fn parse_password_delay(out: &str) -> Lock {
    if out.contains("screenLock is off") {
        return Lock::None;
    }
    if out.contains("delay is immediate") {
        return Lock::Seconds(0);
    }
    let mut words = out
        .split("delay is ")
        .nth(1)
        .map(|rest| rest.split_whitespace())
        .into_iter()
        .flatten();
    let Some(n) = words.next().and_then(|n| n.parse::<u64>().ok()) else {
        return Lock::Unknown;
    };
    let seconds = match words.next() {
        Some(unit) if unit.starts_with("min") => n.saturating_mul(60),
        _ => n,
    };
    Lock::Seconds(seconds)
}

/// The screen saver idle time in seconds, from `defaults read com.apple.screensaver idleTime`.
/// Zero means the screen saver never starts. A key that is not set cannot be read here; see
/// `saver_idle`.
pub fn parse_saver_idle(out: &str) -> Lock {
    match out.trim().parse::<u64>() {
        Ok(0) => Lock::None,
        Ok(seconds) => Lock::Seconds(seconds),
        Err(_) => Lock::Unknown,
    }
}

/// The screen saver idle time that applies: the one the user or a profile set, else the default of
/// the installed macOS. Unknown only when neither can be read. The default is read only when the
/// setting is missing.
pub fn saver_idle(configured: Lock, installed_default: impl FnOnce() -> Lock) -> Lock {
    match configured {
        Lock::Unknown => installed_default(),
        set => set,
    }
}

/// The display sleep time from `pmset -g custom`, which lists minutes for each power source.
/// Zero means never. The longest source decides, because the device can run on any of them.
pub fn parse_display_sleep(out: &str) -> Lock {
    let mut found: Option<Lock> = None;
    for line in out.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("displaysleep") {
            continue;
        }
        let lock = match words.next().and_then(|n| n.parse::<u64>().ok()) {
            Some(0) => Lock::None,
            Some(minutes) => Lock::Seconds(minutes.saturating_mul(60)),
            None => Lock::Unknown,
        };
        found = Some(found.map_or(lock, |earlier| earlier.weaker(lock)));
    }
    found.unwrap_or(Lock::Unknown)
}

/// Whichever of the two idle triggers fires first. One that is off leaves the other.
pub fn first_idle_trigger(saver: Lock, display: Lock) -> Lock {
    match (saver, display) {
        (Lock::Unknown, _) | (_, Lock::Unknown) => Lock::Unknown,
        (Lock::None, other) | (other, Lock::None) => other,
        (Lock::Seconds(a), Lock::Seconds(b)) => Lock::Seconds(a.min(b)),
    }
}

/// The time from the last input to a locked screen. Without a trigger or without a password
/// requirement nothing locks the screen. An unreadable part makes the total unknown.
pub fn total_lock(password: Lock, idle: Lock) -> Lock {
    match (password, idle) {
        (Lock::None, _) | (_, Lock::None) => Lock::None,
        (Lock::Unknown, _) | (_, Lock::Unknown) => Lock::Unknown,
        (Lock::Seconds(delay), Lock::Seconds(idle)) => Lock::Seconds(idle.saturating_add(delay)),
    }
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
    fn the_saver_idle_time_is_seconds_and_zero_means_never() {
        assert_eq!(parse_saver_idle("600\n"), Lock::Seconds(600));
        assert_eq!(parse_saver_idle("0\n"), Lock::None);
        for text in [
            "",
            "The domain/default pair of (com.apple.screensaver, idleTime) does not exist",
            "-5",
        ] {
            assert_eq!(parse_saver_idle(text), Lock::Unknown, "{text}");
        }
    }

    #[test]
    fn an_unset_saver_idle_time_uses_the_default_of_the_installed_macos() {
        let unset = parse_saver_idle(
            "The domain/default pair of (com.apple.screensaver, idleTime) does not exist",
        );
        // `plutil -extract idleTime raw -o -` on the installed EngineDefaults.plist.
        let engine_default = || parse_saver_idle("1200\n");
        assert_eq!(saver_idle(unset, engine_default), Lock::Seconds(1200));
        // A set value, even zero, is never replaced by the default.
        assert_eq!(
            saver_idle(Lock::Seconds(300), || panic!("not read")),
            Lock::Seconds(300)
        );
        assert_eq!(saver_idle(Lock::None, || panic!("not read")), Lock::None);
        // Neither can be read.
        assert_eq!(saver_idle(unset, || Lock::Unknown), Lock::Unknown);
        // With display sleep of 10 minutes and a password at once: 600 seconds, so 10 minutes.
        let display = parse_display_sleep(" displaysleep 10\n");
        let total = total_lock(
            parse_password_delay("delay is immediate"),
            first_idle_trigger(saver_idle(unset, engine_default), display),
        );
        assert_eq!(total, Lock::Seconds(600));
        assert_eq!(total.minutes(), open_pact_core::ControlValue::from(10));
    }

    #[test]
    fn the_display_sleep_time_is_the_longest_of_the_power_sources() {
        let pmset = |battery: &str, ac: &str| {
            format!(
                "Battery Power:\n sleep                1\n displaysleep         {battery}\nAC Power:\n sleep                0\n displaysleep         {ac} (display sleep prevented by powerd)\n"
            )
        };
        assert_eq!(parse_display_sleep(&pmset("2", "10")), Lock::Seconds(600));
        assert_eq!(parse_display_sleep(&pmset("2", "0")), Lock::None);
        assert_eq!(parse_display_sleep(&pmset("x", "10")), Lock::Unknown);
        assert_eq!(parse_display_sleep("sleep 1\n"), Lock::Unknown);
        assert_eq!(parse_display_sleep(""), Lock::Unknown);
    }

    #[test]
    fn the_total_lock_is_the_first_idle_trigger_plus_the_password_delay() {
        use Lock::{None as Off, Seconds, Unknown};
        for (saver, display, idle) in [
            (Seconds(600), Seconds(300), Seconds(300)),
            (Seconds(120), Seconds(300), Seconds(120)),
            (Off, Seconds(300), Seconds(300)),
            (Seconds(300), Off, Seconds(300)),
            (Off, Off, Off),
            (Unknown, Seconds(300), Unknown),
            (Seconds(300), Unknown, Unknown),
        ] {
            assert_eq!(first_idle_trigger(saver, display), idle);
        }
        for (password, idle, total) in [
            (Seconds(0), Seconds(300), Seconds(300)),
            (Seconds(60), Seconds(300), Seconds(360)),
            (Off, Seconds(300), Off),
            (Seconds(60), Off, Off),
            (Unknown, Off, Off),
            (Off, Unknown, Off),
            (Unknown, Seconds(300), Unknown),
            (Seconds(60), Unknown, Unknown),
        ] {
            assert_eq!(total_lock(password, idle), total, "{password:?} {idle:?}");
        }
        assert_eq!(
            total_lock(Seconds(1), Seconds(300)).minutes(),
            open_pact_core::ControlValue::Integer(6),
            "301 seconds round up to 6 minutes"
        );
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

#[cfg(test)]
#[path = "../../tests/contracts/adapters/macos.rs"]
pub(super) mod contract_adapter;
