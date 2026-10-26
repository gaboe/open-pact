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

use crate::folders::ManagedFolders;

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
    ("os_auto_updates", 1),
    ("antimalware_realtime", 1),
    ("antimalware_active_threats", 1),
    ("work_account", 1),
    ("uptime_days", 1),
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
    ("web_protection", 1),
    ("log_oldest_record_days", 1),
    ("process_audit", 1),
    ("powershell_logging", 1),
    ("log_cleared", 1),
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

#[allow(dead_code)]
pub(crate) struct CheckInput<'a> {
    pub(crate) control: &'a Control,
    pub(crate) folders: &'a ManagedFolders,
}

type CheckFn = for<'a> fn(&CheckInput<'a>) -> ControlValue;
type Registry = &'static [(&'static str, CheckFn)];

macro_rules! ignore_input {
    ($check:expr) => {
        |_: &CheckInput<'_>| ($check)()
    };
}

const MACOS: Registry = &[
    ("os_auto_updates", ignore_input!(macos_v3::os_auto_updates)),
    (
        "antimalware_realtime",
        ignore_input!(macos_v3::antimalware_realtime),
    ),
    (
        "antimalware_active_threats",
        ignore_input!(macos_v3::not_applicable),
    ),
    ("work_account", ignore_input!(macos_v3::work_account)),
    ("uptime_days", ignore_input!(macos_v3::uptime_days)),
    (
        "disk_encryption",
        ignore_input!(|| macos::disk_encryption().into()),
    ),
    ("firewall", ignore_input!(|| macos::firewall().into())),
    ("screen_lock", ignore_input!(|| macos::screen_lock().into())),
    (
        "os_supported",
        ignore_input!(|| macos::os_supported().into()),
    ),
    ("os_patch_age_days", ignore_input!(macos::os_patch_age_days)),
    ("password_set", ignore_input!(macos_v3::unknown)),
    ("auto_login", ignore_input!(|| macos::auto_login().into())),
    ("secure_boot", ignore_input!(macos_v3::unknown)),
    (
        "antimalware_active",
        ignore_input!(|| macos::antimalware_active().into()),
    ),
    ("preboot_auth", ignore_input!(macos_v3::preboot_auth)),
    (
        "antimalware_signature_age_days",
        ignore_input!(macos_v3::antimalware_signature_age_days),
    ),
    (
        "antimalware_full_scan_age_days",
        ignore_input!(macos_v3::not_applicable),
    ),
    ("web_protection", ignore_input!(macos_v3::web_protection)),
    (
        "log_oldest_record_days",
        ignore_input!(macos_v3::not_applicable),
    ),
    ("process_audit", ignore_input!(macos_v3::not_applicable)),
    (
        "powershell_logging",
        ignore_input!(macos_v3::not_applicable),
    ),
    ("log_cleared", ignore_input!(macos_v3::not_applicable)),
];

const LINUX: Registry = &[
    ("os_auto_updates", ignore_input!(linux_v3::os_auto_updates)),
    (
        "antimalware_realtime",
        ignore_input!(linux_v3::antimalware_realtime),
    ),
    (
        "antimalware_active_threats",
        ignore_input!(macos_v3::unknown),
    ),
    ("work_account", ignore_input!(linux_v3::work_account)),
    ("uptime_days", ignore_input!(linux_v3::uptime_days)),
    (
        "disk_encryption",
        ignore_input!(|| linux::disk_encryption().into()),
    ),
    ("firewall", ignore_input!(|| linux::firewall().into())),
    ("screen_lock", ignore_input!(|| linux::screen_lock().into())),
    (
        "os_supported",
        ignore_input!(|| linux::os_supported().into()),
    ),
    ("os_patch_age_days", ignore_input!(linux::os_patch_age_days)),
    ("password_set", ignore_input!(macos_v3::unknown)),
    ("auto_login", ignore_input!(|| linux::auto_login().into())),
    ("secure_boot", ignore_input!(|| linux::secure_boot().into())),
    (
        "antimalware_active",
        ignore_input!(|| linux::antimalware_active().into()),
    ),
    ("preboot_auth", ignore_input!(linux_v3::preboot_auth)),
    (
        "antimalware_signature_age_days",
        ignore_input!(linux_v3::antimalware_signature_age_days),
    ),
    (
        "antimalware_full_scan_age_days",
        ignore_input!(macos_v3::unknown),
    ),
    ("web_protection", ignore_input!(macos_v3::unknown)),
    (
        "log_oldest_record_days",
        ignore_input!(linux_v3::log_oldest_record_days),
    ),
    ("process_audit", ignore_input!(macos_v3::not_applicable)),
    (
        "powershell_logging",
        ignore_input!(macos_v3::not_applicable),
    ),
    ("log_cleared", ignore_input!(macos_v3::not_applicable)),
];

const WINDOWS: Registry = &[
    ("os_auto_updates", ignore_input!(windows::os_auto_updates)),
    (
        "antimalware_realtime",
        ignore_input!(windows::antimalware_realtime),
    ),
    (
        "antimalware_active_threats",
        ignore_input!(windows::antimalware_active_threats),
    ),
    ("work_account", ignore_input!(windows::work_account)),
    ("uptime_days", ignore_input!(windows::uptime_days)),
    ("disk_encryption", ignore_input!(windows::disk_encryption)),
    ("firewall", ignore_input!(windows::firewall)),
    ("screen_lock", ignore_input!(windows::screen_lock)),
    ("os_supported", ignore_input!(windows::os_supported)),
    (
        "os_patch_age_days",
        ignore_input!(windows::os_patch_age_days),
    ),
    ("password_set", ignore_input!(macos_v3::unknown)),
    ("auto_login", ignore_input!(windows::auto_login)),
    ("secure_boot", ignore_input!(windows::secure_boot)),
    (
        "antimalware_active",
        ignore_input!(windows::antimalware_active),
    ),
    ("preboot_auth", ignore_input!(windows::preboot_auth)),
    (
        "antimalware_signature_age_days",
        ignore_input!(windows::antimalware_signature_age_days),
    ),
    (
        "antimalware_full_scan_age_days",
        ignore_input!(windows::antimalware_full_scan_age_days),
    ),
    ("web_protection", ignore_input!(windows::web_protection)),
    (
        "log_oldest_record_days",
        ignore_input!(windows::log_oldest_record_days),
    ),
    ("process_audit", ignore_input!(windows::process_audit)),
    (
        "powershell_logging",
        ignore_input!(windows::powershell_logging),
    ),
    ("log_cleared", ignore_input!(windows::log_cleared)),
];

fn registry(os: Os) -> Registry {
    match os {
        Os::Macos => MACOS,
        Os::Linux => LINUX,
        Os::Windows => WINDOWS,
    }
}

/// Runs the registered checks whose id is in `ids`, and no other.
pub fn run(
    os: Os,
    controls: &[Control],
    folders: &ManagedFolders,
) -> BTreeMap<String, ControlValue> {
    registry(os)
        .iter()
        .filter_map(|(id, check)| {
            let control = controls.iter().find(|control| control.id == *id)?;
            let input = CheckInput { control, folders };
            let value =
                std::panic::catch_unwind(|| check(&input)).unwrap_or_else(|_| "unknown".into());
            Some(((*id).to_string(), value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::folders::ManagedFolders;

    fn run_all(os: Os) -> BTreeMap<String, ControlValue> {
        let manifest =
            Manifest::parse(include_bytes!("../../../../examples/manifest.toml")).unwrap();
        let mut controls = manifest.body().controls.clone();
        for (id, _) in BUILTINS {
            if !controls.iter().any(|control| control.id == *id) {
                let mut control = controls[0].clone();
                control.id = (*id).to_string();
                controls.push(control);
            }
        }
        run(os, &controls, &ManagedFolders::default())
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
        let manifest =
            Manifest::parse(include_bytes!("../../../../examples/manifest.toml")).unwrap();
        let controls = manifest
            .body()
            .controls
            .iter()
            .filter(|control| control.id == "firewall")
            .cloned()
            .collect::<Vec<_>>();
        let ran = run(Os::Windows, &controls, &ManagedFolders::default());
        assert_eq!(ran.into_keys().collect::<Vec<_>>(), ["firewall"]);
    }

    #[test]
    fn registries_ignore_check_input_for_the_same_control_ids() {
        let manifest =
            Manifest::parse(include_bytes!("../../../../examples/manifest.toml")).unwrap();
        let folders = ManagedFolders::default();
        for os in Os::ALL {
            let controls = &manifest.body().controls;
            let first = run(os, controls, &folders);
            let second = run(os, controls, &folders);
            assert_eq!(first, second, "{os}");
        }
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
                let Some(control) = manifest.body().control(&id) else {
                    continue;
                };
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
