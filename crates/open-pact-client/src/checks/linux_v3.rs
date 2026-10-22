use std::fs::File;
use std::io::Read;

use chrono::{DateTime, Utc};
use open_pact_core::ControlValue;
use serde_json::Value;

use super::exec::run_status;
use super::macos_v3::bounded_age;

pub fn os_auto_updates() -> ControlValue {
    let units = [
        "apt-daily-upgrade.timer",
        "dnf-automatic.timer",
        "dnf-automatic-install.timer",
    ];
    let states: Vec<_> = units
        .iter()
        .map(|unit| {
            let result = run_status(
                "systemctl",
                &[
                    "show",
                    unit,
                    "--property=LoadState,UnitFileState,ActiveState",
                    "--no-pager",
                ],
            );
            result.filter(|r| r.success).map(|r| r.text)
        })
        .collect();
    let installation = [
        run_status(
            "apt-config",
            &["shell", "AUTO", "APT::Periodic::Unattended-Upgrade"],
        )
        .filter(|r| r.success)
        .map(|r| parse_apt_auto(&r.text)),
        std::fs::read_to_string("/etc/dnf/automatic.conf")
            .ok()
            .map(|s| parse_dnf_auto(&s)),
        Some("on".into()),
    ];
    let effective: Vec<_> = states
        .into_iter()
        .zip(installation)
        .map(|(state, install)| {
            state.map(|s| {
                format!(
                    "{s}\nInstallUpdates={}",
                    install.unwrap_or_else(|| "unknown".into())
                )
            })
        })
        .collect();
    parse_update_units(&effective)
}
fn parse_apt_auto(text: &str) -> ControlValue {
    match text.trim() {
        "AUTO='0'" | "" => "off".into(),
        value
            if value
                .strip_prefix("AUTO='")
                .and_then(|s| s.strip_suffix('\''))
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|n| n > 0) =>
        {
            "on".into()
        }
        _ => "unknown".into(),
    }
}
fn parse_dnf_auto(text: &str) -> ControlValue {
    let mut commands = false;
    let mut value = None;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
    {
        if line.starts_with('[') {
            commands = line == "[commands]";
        } else if commands
            && let Some((key, v)) = line.split_once('=')
            && key.trim() == "apply_updates"
        {
            value = Some(v.trim());
        }
    }
    match value {
        Some("yes" | "true" | "1") => "on",
        Some("no" | "false" | "0") | None => "off",
        _ => "unknown",
    }
    .into()
}
fn parse_update_units(states: &[Option<String>]) -> ControlValue {
    let mut unknown = false;
    for state in states {
        let Some(state) = state else {
            unknown = true;
            continue;
        };
        let fields: std::collections::BTreeMap<_, _> =
            state.lines().filter_map(|l| l.split_once('=')).collect();
        if fields.get("LoadState") == Some(&"not-found") {
            continue;
        }
        if fields.get("LoadState") != Some(&"loaded") {
            unknown = true;
            continue;
        }
        match (fields.get("UnitFileState"), fields.get("ActiveState")) {
            (Some(&"enabled"), Some(&"active")) => match fields.get("InstallUpdates") {
                Some(&"on") => return "on".into(),
                Some(&"off") => (),
                _ => unknown = true,
            },
            (Some(&"disabled" | &"masked"), _) | (_, Some(&"inactive" | &"failed")) => (),
            _ => unknown = true,
        }
    }
    if unknown { "unknown" } else { "off" }.into()
}
pub fn antimalware_realtime() -> ControlValue {
    super::exec::capture("pgrep", &["-x", "clamonacc"], super::exec::TIMEOUT)
        .ok()
        .filter(|r| !r.timed_out && r.stderr.is_empty())
        .map_or_else(
            || "unknown".into(),
            |r| parse_on_access(r.status.and_then(|s| s.code()), &r.stdout),
        )
}
fn parse_on_access(code: Option<i32>, text: &str) -> ControlValue {
    match code {
        Some(0)
            if !text.trim().is_empty()
                && text.split_whitespace().all(|p| p.parse::<u32>().is_ok()) =>
        {
            "on"
        }
        Some(1) if text.trim().is_empty() => "off",
        _ => "unknown",
    }
    .into()
}
pub fn work_account() -> ControlValue {
    run_status("id", &["-Gn"])
        .filter(|r| r.success)
        .map_or_else(
            || "unknown".into(),
            |r| super::macos_v3::parse_groups(&r.text, &["sudo", "wheel", "root"]),
        )
}
pub fn uptime_days() -> ControlValue {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .map_or_else(|| "unknown".into(), |s| parse_uptime(&s))
}
fn parse_uptime(text: &str) -> ControlValue {
    text.split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|n| n.is_finite() && *n >= 0.0 && *n / 86400.0 <= f64::from(i32::MAX))
        .map_or_else(
            || "unknown".into(),
            |n| ((n / 86400.0).floor() as i32).into(),
        )
}

pub fn preboot_auth() -> ControlValue {
    let output = run_status(
        "lsblk",
        &["-s", "-n", "-o", "NAME,TYPE,RO,RM,FSTYPE,MOUNTPOINT"],
    );
    output
        .filter(|r| r.success)
        .map_or("unknown", |r| parse_preboot(&r.text))
        .into()
}

fn parse_preboot(text: &str) -> &'static str {
    match super::linux::parse_lsblk_inverse(text) {
        "none" => "none",
        // LUKS keyslots do not distinguish passwords from keyfiles. A standard user
        // cannot reliably inspect the root volume metadata to establish its unlock method.
        _ => "unknown",
    }
}

pub fn antimalware_signature_age_days() -> ControlValue {
    for root in ["/var/lib/clamav", "/usr/local/share/clamav"] {
        let mut dates = vec![];
        for extension in ["cld", "cvd"] {
            let path = format!("{root}/daily.{extension}");
            let mut file = match File::open(path) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return "unknown".into(),
            };
            let mut header = [0; 512];
            if file.read_exact(&mut header).is_err() {
                return "unknown".into();
            }
            let Some(date) = parse_cvd_header(&header) else {
                return "unknown".into();
            };
            dates.push(date);
        }
        if let Some(last) = dates.into_iter().max() {
            return bounded_age((Utc::now() - last).num_days(), 3650);
        }
    }
    "unknown".into()
}

fn parse_cvd_header(bytes: &[u8]) -> Option<DateTime<Utc>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let fields: Vec<_> = text.trim().split(':').collect();
    if fields.first() != Some(&"ClamAV-VDB") || fields.len() != 9 {
        return None;
    }
    DateTime::from_timestamp(fields[8].trim().parse().ok()?, 0)
}

pub fn log_oldest_record_days() -> ControlValue {
    let Some(output) = run_status(
        "journalctl",
        &[
            "--system",
            "--no-pager",
            "--output=json",
            "--output-fields=__REALTIME_TIMESTAMP",
            "--lines=+1",
        ],
    )
    .filter(|r| r.success) else {
        return "unknown".into();
    };
    parse_journal_age(&output.text, Utc::now())
}

fn parse_journal_age(text: &str, now: DateTime<Utc>) -> ControlValue {
    // Do not suppress journalctl warnings: a permission warning means partial visibility.
    let Some(micros) = serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v["__REALTIME_TIMESTAMP"].as_str()?.parse::<i64>().ok())
    else {
        return "unknown".into();
    };
    let Some(oldest) = DateTime::from_timestamp_micros(micros) else {
        return "unknown".into();
    };
    if oldest > now {
        return "unknown".into();
    }
    bounded_age((now - oldest).num_days(), i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn luks_without_verified_unlock_method_is_unknown() {
        assert_eq!(
            parse_preboot("sda2 part 0 0 ext4 /\n sda disk 0 0\n"),
            "none"
        );
        assert_eq!(
            parse_preboot(
                "cryptroot crypt 0 0 ext4 /\n sda2 part 0 0 crypto_LUKS\n sda disk 0 0\n"
            ),
            "unknown"
        );
        assert_eq!(parse_preboot(""), "unknown");
    }
    #[test]
    fn daily_database_uses_embedded_timestamp_not_file_mtime() {
        let text = "ClamAV-VDB:14 Oct 2026 08-00 +0000:28000:3000000:90:00000000000000000000000000000000:fictional-signature:fictional-builder:1791964800";
        assert_eq!(
            parse_cvd_header(text.as_bytes()).unwrap().timestamp(),
            1791964800
        );
        assert!(parse_cvd_header(b"not a database").is_none());
        assert!(parse_cvd_header(b"ClamAV-VDB:date:1:2:3:hash:sig:builder:no-date").is_none());
    }
    #[test]
    fn oldest_readable_system_entry_and_permission_warnings() {
        let now = DateTime::from_timestamp(1791964800, 0).unwrap();
        let text = format!(
            "{{\"__REALTIME_TIMESTAMP\":\"{}\"}}\n",
            (now.timestamp() - 10 * 86400) * 1_000_000
        );
        assert_eq!(parse_journal_age(&text, now), ControlValue::Integer(10));
        assert_eq!(
            parse_journal_age(
                &(text.clone() + "Hint: You are currently not seeing messages from other users.\n"),
                now
            ),
            "unknown"
        );
        assert_eq!(parse_journal_age("-- No entries --", now), "unknown");
        assert_eq!(
            parse_journal_age(&text, now - chrono::Duration::days(11)),
            "unknown"
        );
    }
}

#[cfg(test)]
mod v31_tests {
    use super::*;
    #[test]
    fn automatic_installation_needs_enabled_active_timer_and_config() {
        for (state, expected) in [
            (
                "LoadState=loaded\nUnitFileState=enabled\nActiveState=active\nInstallUpdates=on",
                "on",
            ),
            (
                "LoadState=loaded\nUnitFileState=disabled\nActiveState=active\nInstallUpdates=on",
                "off",
            ),
            (
                "LoadState=loaded\nUnitFileState=enabled\nActiveState=inactive\nInstallUpdates=on",
                "off",
            ),
            (
                "LoadState=loaded\nUnitFileState=enabled\nActiveState=active\nInstallUpdates=off",
                "off",
            ),
            ("LoadState=not-found", "off"),
            ("Permission denied", "unknown"),
        ] {
            assert_eq!(parse_update_units(&[Some(state.into())]), expected);
        }
        assert_eq!(parse_update_units(&[None]), "unknown");
        assert_eq!(parse_apt_auto("AUTO='1'\n"), "on");
        assert_eq!(parse_apt_auto("AUTO='0'"), "off");
        assert_eq!(parse_apt_auto("bad"), "unknown");
        assert_eq!(parse_dnf_auto("[commands]\napply_updates = yes"), "on");
        assert_eq!(parse_dnf_auto("[commands]\napply_updates = no"), "off");
        assert_eq!(parse_dnf_auto("[commands]\napply_updates = bad"), "unknown");
    }
    #[test]
    fn on_access_process_fixtures() {
        assert_eq!(parse_on_access(Some(0), "123\n"), "on");
        assert_eq!(parse_on_access(Some(1), ""), "off");
        for (code, text) in [(Some(2), ""), (None, ""), (Some(0), "bad")] {
            assert_eq!(parse_on_access(code, text), "unknown");
        }
    }
    #[test]
    fn account_and_uptime_fixtures() {
        for (groups, expected) in [
            ("users sudo", "admin"),
            ("users wheel", "admin"),
            ("users", "standard"),
            ("", "unknown"),
        ] {
            assert_eq!(
                super::super::macos_v3::parse_groups(groups, &["sudo", "wheel"]),
                expected
            );
        }
        assert_eq!(
            parse_uptime("172800.50 100000.25"),
            ControlValue::Integer(2)
        );
        assert_eq!(parse_uptime("0.5 0"), ControlValue::Integer(0));
        for text in ["unknown", "", "-1 0", "NaN", "inf"] {
            assert_eq!(parse_uptime(text), "unknown");
        }
    }
}
