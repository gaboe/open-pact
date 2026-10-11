use open_pact_core::Os;

const COMPLIANT: &[(&str, &[&str])] = &[
    ("disk_encryption", &["full"]),
    ("firewall", &["on"]),
    ("screen_lock", &["le_5min"]),
    ("os_supported", &["yes"]),
    ("os_patch_age", &["le_14d"]),
    ("password_set", &["yes"]),
    ("auto_login", &["off"]),
    ("secure_boot", &["on"]),
    ("antimalware_active", &["yes"]),
];

pub fn fix_hint(check: &str, value: &str, os: Os) -> Option<&'static str> {
    let (_, good) = COMPLIANT.iter().find(|(id, _)| *id == check)?;
    if good.contains(&value) {
        return None;
    }
    if value == "unknown" {
        return Some(
            "This check could not read the setting. Make sure the system tool it uses is installed and run the check again.",
        );
    }
    match (check, os) {
        ("disk_encryption", Os::Macos) => {
            Some("Enable FileVault: System Settings > Privacy & Security > FileVault.")
        }
        ("disk_encryption", Os::Windows) => {
            Some("Turn on BitLocker: Settings > Privacy & security > Device encryption.")
        }
        ("disk_encryption", Os::Linux) => Some(
            "Encrypt the root volume with LUKS. This usually needs a reinstall or a supported conversion tool.",
        ),
        ("firewall", Os::Macos) => {
            Some("Turn on the firewall: System Settings > Network > Firewall.")
        }
        ("firewall", Os::Windows) => Some(
            "Turn on Windows Defender Firewall: Settings > Privacy & security > Windows Security > Firewall & network protection.",
        ),
        ("firewall", Os::Linux) => Some(
            "Enable a firewall: run 'sudo ufw enable' or 'sudo systemctl enable --now firewalld'.",
        ),
        ("screen_lock", Os::Macos) => Some(
            "Set the lock delay: System Settings > Lock Screen > Require password after screen saver begins or display is turned off > Immediately or 5 minutes.",
        ),
        ("screen_lock", Os::Windows) => Some(
            "Set a lock timeout: Settings > Accounts > Sign-in options > If you've been away, when should Windows require you to sign in again.",
        ),
        ("screen_lock", Os::Linux) => Some(
            "Set automatic screen lock to 5 minutes or less: Settings > Privacy > Screen Lock (GNOME) or System Settings > Screen Locking (KDE).",
        ),
        ("os_supported", Os::Macos) => {
            Some("Upgrade macOS: System Settings > General > Software Update.")
        }
        ("os_supported", Os::Windows) => {
            Some("Upgrade to a supported Windows version: Settings > Windows Update.")
        }
        ("os_supported", Os::Linux) => {
            Some("Upgrade to a release that still receives security updates.")
        }
        ("os_patch_age", Os::Macos) => {
            Some("Install updates: System Settings > General > Software Update.")
        }
        ("os_patch_age", Os::Windows) => Some("Install updates: Settings > Windows Update."),
        ("os_patch_age", Os::Linux) => Some(
            "Install updates: run 'sudo apt update && sudo apt upgrade' or 'sudo dnf upgrade'.",
        ),
        ("password_set", Os::Macos) => {
            Some("Set a login password: System Settings > Users & Groups > Change Password.")
        }
        ("password_set", Os::Windows) => {
            Some("Set a sign-in password: Settings > Accounts > Sign-in options > Password.")
        }
        ("password_set", Os::Linux) => Some("Set a login password: run 'passwd'."),
        ("auto_login", Os::Macos) => Some(
            "Turn off automatic login: System Settings > Users & Groups > Automatically log in as > Off.",
        ),
        ("auto_login", Os::Windows) => {
            Some("Turn off automatic sign-in: Settings > Accounts > Sign-in options.")
        }
        ("auto_login", Os::Linux) => Some(
            "Turn off automatic login: Settings > Users > Automatic Login (GNOME) or System Settings > Login Screen (KDE).",
        ),
        ("secure_boot", Os::Macos) => None,
        ("secure_boot", Os::Windows) => Some("Enable Secure Boot in the UEFI firmware settings."),
        ("secure_boot", Os::Linux) => {
            Some("Enable Secure Boot in the UEFI firmware settings and use a signed bootloader.")
        }
        ("antimalware_active", Os::Macos) => Some(
            "Turn on Gatekeeper: run 'sudo spctl --global-enable' or System Settings > Privacy & Security > Allow applications from.",
        ),
        ("antimalware_active", Os::Windows) => {
            Some("Turn on real-time protection: Windows Security > Virus & threat protection.")
        }
        ("antimalware_active", Os::Linux) => {
            Some("Install and start an antimalware service such as ClamAV (clamav-daemon).")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliant_values_need_no_hint() {
        assert_eq!(fix_hint("disk_encryption", "full", Os::Macos), None);
        assert_eq!(fix_hint("auto_login", "off", Os::Linux), None);
    }

    #[test]
    fn failing_values_get_owner_instructions() {
        let hint = fix_hint("disk_encryption", "none", Os::Macos).unwrap();
        assert!(hint.contains("FileVault"));
    }

    #[test]
    fn unknown_check_has_no_hint() {
        assert_eq!(fix_hint("nonsense", "none", Os::Macos), None);
    }

    #[test]
    fn every_failing_value_has_a_hint_on_every_os() {
        for (check, good) in COMPLIANT {
            for os in Os::ALL {
                for value in ["none", "off", "on", "no", "gt_30d", "unknown"] {
                    if good.contains(&value) || (*check == "secure_boot" && os == Os::Macos) {
                        continue;
                    }
                    assert!(
                        fix_hint(check, value, os).is_some(),
                        "{check} {value} {os:?}"
                    );
                }
            }
        }
    }
}
