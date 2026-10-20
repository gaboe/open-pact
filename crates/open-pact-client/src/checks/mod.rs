mod buckets;
mod exec;
mod hints;
mod linux;
mod macos;
mod windows;

use std::collections::BTreeMap;

use open_pact_core::{Control, Manifest, Os};

pub use hints::fix_hint;

fn unknown() -> &'static str {
    "unknown"
}

/// The builtins compiled into this client, by control id and version. A manifest control runs only if
/// its `check` is exactly `builtin:<id>@<version>` from this table.
const BUILTINS: &[(&str, u32)] = &[
    ("disk_encryption", 1),
    ("firewall", 1),
    ("screen_lock", 1),
    ("os_supported", 1),
    ("os_patch_age", 1),
    ("password_set", 1),
    ("auto_login", 1),
    ("secure_boot", 1),
    ("antimalware_active", 1),
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

type CheckFn = fn() -> &'static str;
type Registry = &'static [(&'static str, CheckFn)];

const MACOS: Registry = &[
    ("disk_encryption", macos::disk_encryption),
    ("firewall", macos::firewall),
    ("screen_lock", macos::screen_lock),
    ("os_supported", macos::os_supported),
    ("os_patch_age", macos::os_patch_age),
    ("password_set", unknown),
    ("auto_login", macos::auto_login),
    ("secure_boot", unknown),
    ("antimalware_active", macos::antimalware_active),
];

const LINUX: Registry = &[
    ("disk_encryption", linux::disk_encryption),
    ("firewall", linux::firewall),
    ("screen_lock", linux::screen_lock),
    ("os_supported", linux::os_supported),
    ("os_patch_age", linux::os_patch_age),
    ("password_set", unknown),
    ("auto_login", linux::auto_login),
    ("secure_boot", linux::secure_boot),
    ("antimalware_active", linux::antimalware_active),
];

const WINDOWS: Registry = &[
    ("disk_encryption", windows::disk_encryption),
    ("firewall", windows::firewall),
    ("screen_lock", windows::screen_lock),
    ("os_supported", windows::os_supported),
    ("os_patch_age", windows::os_patch_age),
    ("password_set", unknown),
    ("auto_login", windows::auto_login),
    ("secure_boot", windows::secure_boot),
    ("antimalware_active", windows::antimalware_active),
];

fn registry(os: Os) -> Registry {
    match os {
        Os::Macos => MACOS,
        Os::Linux => LINUX,
        Os::Windows => WINDOWS,
    }
}

/// Runs the registered checks whose id is in `ids`, and no other.
pub fn run(os: Os, ids: &[&str]) -> BTreeMap<String, String> {
    registry(os)
        .iter()
        .filter(|(id, _)| ids.contains(id))
        .map(|(id, check)| {
            let value = std::panic::catch_unwind(check).unwrap_or("unknown");
            ((*id).to_string(), value.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_all(os: Os) -> BTreeMap<String, String> {
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
        assert_eq!(ids(Os::Macos).len(), 9);
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_checks_report_unknown_off_windows() {
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
