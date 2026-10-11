#![allow(dead_code, unused_imports)]

mod buckets;
mod exec;
mod hints;
mod linux;
mod macos;
mod windows;

use std::collections::BTreeMap;

use open_pact_core::Os;

pub use hints::fix_hint;

type CheckFn = fn() -> &'static str;
type Registry = &'static [(&'static str, CheckFn)];

const MACOS: Registry = &[
    ("disk_encryption", macos::disk_encryption),
    ("firewall", macos::firewall),
    ("screen_lock", macos::screen_lock),
    ("os_supported", macos::os_supported),
    ("os_patch_age", macos::os_patch_age),
    ("password_set", windows::unknown),
    ("auto_login", macos::auto_login),
    ("secure_boot", windows::unknown),
    ("antimalware_active", macos::antimalware_active),
];

const LINUX: Registry = &[
    ("disk_encryption", linux::disk_encryption),
    ("firewall", linux::firewall),
    ("screen_lock", linux::screen_lock),
    ("os_supported", linux::os_supported),
    ("os_patch_age", linux::os_patch_age),
    ("password_set", windows::unknown),
    ("auto_login", linux::auto_login),
    ("secure_boot", linux::secure_boot),
    ("antimalware_active", linux::antimalware_active),
];

const WINDOWS: Registry = &[
    ("disk_encryption", windows::unknown),
    ("firewall", windows::unknown),
    ("screen_lock", windows::unknown),
    ("os_supported", windows::unknown),
    ("os_patch_age", windows::unknown),
    ("password_set", windows::unknown),
    ("auto_login", windows::unknown),
    ("secure_boot", windows::unknown),
    ("antimalware_active", windows::unknown),
];

fn registry(os: Os) -> Registry {
    match os {
        Os::Macos => MACOS,
        Os::Linux => LINUX,
        Os::Windows => WINDOWS,
    }
}

pub fn run_all(os: Os) -> BTreeMap<String, String> {
    registry(os)
        .iter()
        .map(|(id, check)| {
            let value = std::panic::catch_unwind(check).unwrap_or("unknown");
            ((*id).to_string(), value.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_os_registers_the_same_checks() {
        let ids = |os| -> Vec<&str> { registry(os).iter().map(|(id, _)| *id).collect() };
        assert_eq!(ids(Os::Macos), ids(Os::Linux));
        assert_eq!(ids(Os::Macos), ids(Os::Windows));
        assert_eq!(ids(Os::Macos).len(), 9);
    }

    #[test]
    fn windows_stubs_report_unknown() {
        let all = run_all(Os::Windows);
        assert_eq!(all.len(), 9);
        assert!(all.values().all(|v| v == "unknown"));
    }

    #[test]
    fn values_are_enumerated_outputs() {
        let allowed: &[(&str, &[&str])] = &[
            ("disk_encryption", &["full", "partial", "none", "unknown"]),
            ("firewall", &["on", "off", "unknown"]),
            (
                "screen_lock",
                &["le_5min", "le_15min", "gt_15min", "off", "unknown"],
            ),
            ("os_supported", &["yes", "no", "unknown"]),
            ("os_patch_age", &["le_14d", "le_30d", "gt_30d", "unknown"]),
            ("password_set", &["yes", "no", "unknown"]),
            ("auto_login", &["off", "on", "unknown"]),
            ("secure_boot", &["on", "off", "unknown"]),
            ("antimalware_active", &["yes", "no", "unknown"]),
        ];
        for os in Os::ALL {
            let results = run_all(os);
            for (id, values) in allowed {
                assert!(values.contains(&results[*id].as_str()), "{os:?} {id}");
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
