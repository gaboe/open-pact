mod browsers;
mod buckets;
mod exec;
mod hints;
mod linux;
mod linux_v3;
mod macos;
mod macos_v3;
mod windows;

use std::collections::BTreeMap;

use open_pact_core::{Control, ControlValue, Manifest, Os};
use serde::{Deserialize, Serialize};

pub use hints::fix_hint;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct EventMarkers {
    pub(crate) security_log_cleared: Option<i64>,
    pub(crate) antimalware_detection: Option<i64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) enum EventMarkerRead {
    #[default]
    Unknown,
    Read(Option<i64>),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EventMarkerReads {
    pub(crate) security_log_cleared: EventMarkerRead,
    pub(crate) antimalware_detection: EventMarkerRead,
}

pub(crate) fn event_markers() -> EventMarkerReads {
    #[cfg(target_os = "windows")]
    {
        windows::event_markers()
    }
    #[cfg(not(target_os = "windows"))]
    {
        EventMarkerReads::default()
    }
}

/// The builtins compiled into this client, by control id and version. A manifest control runs only if
/// its `check` is exactly `builtin:<id>@<version>` from this table.
const BUILTINS: &[(&str, u32)] = &[
    ("disk_encryption", 1),
    ("firewall", 1),
    ("screen_lock", 1),
    ("os_supported", 1),
    ("os_patch_age_days", 1),
    ("password_set", 1),
    ("auto_login", 1),
    ("secure_boot", 1),
    ("antimalware_active", 1),
    ("preboot_auth", 1),
    ("antimalware_signature_age_days", 1),
    ("antimalware_full_scan_age_days", 1),
    ("antimalware_detections_7d", 1),
    ("antimalware_last_detection_hours", 1),
    ("web_protection", 1),
    ("local_log_retention_days", 1),
    ("process_audit", 1),
    ("powershell_logging", 1),
    ("log_cleared_hours", 1),
];

fn implements(control: &Control) -> bool {
    BUILTINS
        .iter()
        .any(|(id, v)| control.id == *id && control.check == format!("builtin:{id}@{v}"))
}

/// Refuses a manifest with a control this client cannot run exactly as signed.
pub fn check_supported(manifest: &Manifest) -> Result<(), String> {
    let unsupported: Vec<String> = manifest
        .body()
        .controls
        .iter()
        .filter(|c| !implements(c))
        .map(|c| format!("{} ({})", c.id, c.check))
        .collect();
    if unsupported.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "this client does not implement {}",
            unsupported.join(", ")
        ))
    }
}

type CheckFn = fn() -> ControlValue;
type Registry = &'static [(&'static str, CheckFn)];

const MACOS: Registry = &[
    ("disk_encryption", || macos::disk_encryption().into()),
    ("firewall", || macos::firewall().into()),
    ("screen_lock", || macos::screen_lock().into()),
    ("os_supported", || macos::os_supported().into()),
    ("os_patch_age_days", macos::os_patch_age_days),
    ("password_set", macos_v3::unknown),
    ("auto_login", || macos::auto_login().into()),
    ("secure_boot", macos_v3::unknown),
    ("antimalware_active", || macos::antimalware_active().into()),
    ("preboot_auth", macos_v3::preboot_auth),
    (
        "antimalware_signature_age_days",
        macos_v3::antimalware_signature_age_days,
    ),
    ("antimalware_full_scan_age_days", macos_v3::not_applicable),
    ("antimalware_detections_7d", macos_v3::not_applicable),
    ("antimalware_last_detection_hours", macos_v3::not_applicable),
    ("web_protection", macos_v3::web_protection),
    ("local_log_retention_days", macos_v3::not_applicable),
    ("process_audit", macos_v3::not_applicable),
    ("powershell_logging", macos_v3::not_applicable),
    ("log_cleared_hours", macos_v3::not_applicable),
];

const LINUX: Registry = &[
    ("disk_encryption", || linux::disk_encryption().into()),
    ("firewall", || linux::firewall().into()),
    ("screen_lock", || linux::screen_lock().into()),
    ("os_supported", || linux::os_supported().into()),
    ("os_patch_age_days", linux::os_patch_age_days),
    ("password_set", macos_v3::unknown),
    ("auto_login", || linux::auto_login().into()),
    ("secure_boot", || linux::secure_boot().into()),
    ("antimalware_active", || linux::antimalware_active().into()),
    ("preboot_auth", linux_v3::preboot_auth),
    (
        "antimalware_signature_age_days",
        linux_v3::antimalware_signature_age_days,
    ),
    ("antimalware_full_scan_age_days", macos_v3::unknown),
    ("antimalware_detections_7d", macos_v3::unknown),
    ("antimalware_last_detection_hours", macos_v3::unknown),
    ("web_protection", macos_v3::unknown),
    (
        "local_log_retention_days",
        linux_v3::local_log_retention_days,
    ),
    ("process_audit", macos_v3::not_applicable),
    ("powershell_logging", macos_v3::not_applicable),
    ("log_cleared_hours", macos_v3::not_applicable),
];

const WINDOWS: Registry = &[
    ("disk_encryption", windows::disk_encryption),
    ("firewall", windows::firewall),
    ("screen_lock", windows::screen_lock),
    ("os_supported", windows::os_supported),
    ("os_patch_age_days", windows::os_patch_age_days),
    ("password_set", macos_v3::unknown),
    ("auto_login", windows::auto_login),
    ("secure_boot", windows::secure_boot),
    ("antimalware_active", windows::antimalware_active),
    ("preboot_auth", windows::preboot_auth),
    (
        "antimalware_signature_age_days",
        windows::antimalware_signature_age_days,
    ),
    (
        "antimalware_full_scan_age_days",
        windows::antimalware_full_scan_age_days,
    ),
    (
        "antimalware_detections_7d",
        windows::antimalware_detections_7d,
    ),
    (
        "antimalware_last_detection_hours",
        windows::antimalware_last_detection_hours,
    ),
    ("web_protection", windows::web_protection),
    (
        "local_log_retention_days",
        windows::local_log_retention_days,
    ),
    ("process_audit", windows::process_audit),
    ("powershell_logging", windows::powershell_logging),
    ("log_cleared_hours", windows::log_cleared_hours),
];

fn registry(os: Os) -> Registry {
    match os {
        Os::Macos => MACOS,
        Os::Linux => LINUX,
        Os::Windows => WINDOWS,
    }
}

/// Runs the registered checks whose id is in `ids`, and no other.
pub fn run(os: Os, ids: &[&str]) -> BTreeMap<String, ControlValue> {
    registry(os)
        .iter()
        .filter(|(id, _)| ids.contains(id))
        .map(|(id, check)| {
            let value = std::panic::catch_unwind(check).unwrap_or_else(|_| "unknown".into());
            ((*id).to_string(), value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_all(os: Os) -> BTreeMap<String, ControlValue> {
        let ids: Vec<&str> = BUILTINS.iter().map(|(id, _)| *id).collect();
        run(os, &ids)
    }

    #[test]
    fn every_builtin_has_a_check_on_every_os() {
        for os in Os::ALL {
            let ids: Vec<&str> = registry(os).iter().map(|(id, _)| *id).collect();
            let builtins: Vec<&str> = BUILTINS.iter().map(|(id, _)| *id).collect();
            assert_eq!(ids, builtins, "{os}");
        }
    }

    #[test]
    fn runs_only_the_requested_checks() {
        let ran = run(Os::Windows, &["firewall", "not_a_check"]);
        assert_eq!(ran.into_keys().collect::<Vec<_>>(), ["firewall"]);
    }

    #[test]
    fn macos_detection_history_is_not_available() {
        let values = run(
            Os::Macos,
            &[
                "antimalware_detections_7d",
                "antimalware_last_detection_hours",
            ],
        );
        assert_eq!(values["antimalware_detections_7d"], "n/a");
        assert_eq!(values["antimalware_last_detection_hours"], "n/a");
    }

    #[test]
    fn accepts_only_compiled_builtins_at_their_exact_version() {
        let demo = include_str!("../../../../examples/manifest.toml");
        let parse = |toml: &str| Manifest::parse(toml.as_bytes()).unwrap();
        assert_eq!(check_supported(&parse(demo)), Ok(()));
        for (from, to) in [
            ("builtin:firewall@1", "builtin:firewall@2"),
            ("builtin:firewall@1", "builtin:screen_lock@1"),
            ("builtin:firewall@1", "builtin:firewall@1 "),
            (r#"id = "firewall""#, r#"id = "installed_apps""#),
        ] {
            let error = check_supported(&parse(&demo.replace(from, to))).unwrap_err();
            assert!(
                error.starts_with("this client does not implement"),
                "{to}: {error}"
            );
        }
    }

    #[test]
    fn every_os_registers_the_same_checks() {
        let ids = |os| -> Vec<&str> { registry(os).iter().map(|(id, _)| *id).collect() };
        assert_eq!(ids(Os::Macos), ids(Os::Linux));
        assert_eq!(ids(Os::Macos), ids(Os::Windows));
        assert_eq!(ids(Os::Macos).len(), BUILTINS.len());
    }

    #[test]
    #[cfg(not(windows))]
    fn windows_checks_report_unknown_off_windows() {
        let all = run_all(Os::Windows);
        assert_eq!(all.len(), BUILTINS.len());
        assert!(all.values().all(|v| v == "unknown"));
    }

    #[test]
    fn values_are_enumerated_outputs() {
        let manifest =
            Manifest::parse(include_bytes!("../../../../examples/manifest.toml")).unwrap();
        for os in Os::ALL {
            for (id, value) in run_all(os) {
                let control = manifest.body().control(&id).unwrap();
                assert!(
                    value == "unknown" || control.output.contains(&value),
                    "{os:?} {id} = {value}"
                );
            }
        }
    }

    #[test]
    #[ignore]
    fn print_run_all_on_this_machine() {
        let os = match std::env::consts::OS {
            "macos" => Os::Macos,
            "windows" => Os::Windows,
            _ => Os::Linux,
        };
        let started = std::time::Instant::now();
        for (id, value) in run_all(os) {
            println!("{id} = {value}");
        }
        println!("elapsed {:?}", started.elapsed());
    }
}
