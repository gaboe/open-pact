use open_pact_core::Os;

const COMPLIANT: &[(&str, &[&str])] = &[
    ("disk_encryption", &["full"]),
    ("firewall", &["on"]),
    ("screen_lock", &["le_5min"]),
    ("os_supported", &["yes"]),
    ("os_patch_age_days", &[]),
    ("password_set", &["yes"]),
    ("auto_login", &["off"]),
    ("secure_boot", &["on"]),
    ("antimalware_active", &["yes"]),
    ("preboot_auth", &["user_secret"]),
    ("antimalware_signature_age_days", &[]),
    ("antimalware_full_scan_age_days", &["n/a"]),
    ("antimalware_detections_7d", &[]),
    ("antimalware_last_detection_hours", &["none"]),
    ("web_protection", &["on"]),
    ("local_log_retention_days", &["n/a"]),
    ("process_audit", &["on", "n/a"]),
    ("powershell_logging", &["on", "n/a"]),
    ("log_cleared_hours", &["none", "n/a"]),
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
        ("os_patch_age_days", Os::Macos) => {
            Some("Install updates: System Settings > General > Software Update.")
        }
        ("os_patch_age_days", Os::Windows) => Some("Install updates: Settings > Windows Update."),
        ("os_patch_age_days", Os::Linux) => Some(
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
            "Install macOS security updates and restore the XProtect scan service if it was disabled.",
        ),
        ("antimalware_active", Os::Windows) => {
            Some("Turn on real-time protection: Windows Security > Virus & threat protection.")
        }
        ("antimalware_active", Os::Linux) => {
            Some("Install and start an antimalware service such as ClamAV (clamav-daemon).")
        }
        ("preboot_auth", Os::Macos) => {
            Some("Enable FileVault in System Settings > Privacy & Security > FileVault.")
        }
        ("preboot_auth", Os::Linux) => {
            Some("Use a passphrase to unlock the LUKS root volume before boot.")
        }
        ("preboot_auth", Os::Windows) => Some("Require a BitLocker startup PIN."),
        ("antimalware_signature_age_days", Os::Macos) => Some(
            "Install security data updates in System Settings > General > Software Update > Automatic Updates.",
        ),
        ("antimalware_signature_age_days", Os::Linux) => {
            Some("Update the ClamAV daily database with freshclam.")
        }
        ("web_protection", _) => Some(
            "Enable fraudulent website warnings or Safe Browsing in every installed browser. Check managed policies too.",
        ),
        ("local_log_retention_days", Os::Linux) => {
            Some("Review journald storage limits and access to the system journal.")
        }
        ("antimalware_full_scan_age_days", _) => {
            Some("Review the antivirus scan history. XProtect has no user-requested full scan.")
        }
        ("antimalware_detections_7d" | "antimalware_last_detection_hours", _) => {
            Some("Review detections in the antivirus history and resolve active threats.")
        }
        ("process_audit" | "powershell_logging" | "log_cleared_hours", _) => {
            Some("Review Windows audit and PowerShell logging policy and event history.")
        }
        ("antimalware_signature_age_days", _) => Some("Update antivirus security intelligence."),
        ("local_log_retention_days", _) => {
            Some("Review the system log storage policy. macOS unified log retention is size-based.")
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
                for value in ["none", "off", "on", "no", "31", "unknown"] {
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
