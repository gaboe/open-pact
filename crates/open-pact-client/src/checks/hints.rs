use open_pact_core::Os;

const COMPLIANT: &[(&str, &[&str])] = &[
    ("os_auto_updates", &["on"]),
    ("antimalware_realtime", &["on"]),
    ("antimalware_active_threats", &["0", "n/a"]),
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
    ("web_protection", &["on", "n/a"]),
    ("log_oldest_record_days", &["n/a"]),
    ("process_audit", &["on", "n/a"]),
    ("powershell_logging", &["on", "n/a"]),
    ("log_cleared", &["null", "n/a"]),
];

pub fn fix_hint(check: &str, value: &str, os: Os) -> Option<&'static str> {
    let (_, good) = COMPLIANT.iter().find(|(id, _)| *id == check)?;
    if good.contains(&value) {
        return None;
    }
    if value == "unknown"
        && os == Os::Windows
        && matches!(
            check,
            "preboot_auth"
                | "antimalware_active_threats"
                | "log_oldest_record_days"
                | "process_audit"
                | "log_cleared"
        )
    {
        return Some(
            "Run the client as a SYSTEM scheduled task or an administrator. Check that the Windows security provider and event logs are available.",
        );
    }
    if value == "unknown" {
        return Some(
            "This check could not read the setting. Make sure the system tool it uses is installed and run the check again.",
        );
    }
    match (check, os) {
        ("os_auto_updates", _) => {
            Some("Enable automatic security updates in the operating system update settings.")
        }
        ("antimalware_realtime", _) => Some(
            "Enable real-time or on-access protection in the operating system antivirus settings.",
        ),
        ("antimalware_active_threats", _) => {
            Some("Review antivirus threats and complete their remediation.")
        }
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
        ("web_protection", Os::Macos) => Some(
            "Enable Safe Browsing in every installed Chrome, Edge, Brave, or Firefox browser. Safari is not checked because its settings need Full Disk Access.",
        ),
        ("antimalware_signature_age_days", Os::Windows) => Some(
            "Update Microsoft Defender security intelligence in Windows Security > Virus & threat protection.",
        ),
        ("antimalware_full_scan_age_days", Os::Windows) => Some(
            "Run a Microsoft Defender full scan in Windows Security > Virus & threat protection > Scan options.",
        ),
        ("log_oldest_record_days", Os::Windows) => Some(
            "Increase the Security and System event log sizes in Event Viewer. Keep enough history for the required number of days.",
        ),
        ("process_audit", Os::Windows) => Some(
            "Enable successful Audit Process Creation and Include command line in process creation events in Group Policy.",
        ),
        ("powershell_logging", Os::Windows) => Some(
            "Enable Turn on PowerShell Script Block Logging in Group Policy > Windows Components > Windows PowerShell.",
        ),
        ("log_cleared", Os::Windows) => Some(
            "Review Security event 1102 and System event 104 in Event Viewer. Investigate why the logs were cleared.",
        ),
        ("web_protection", Os::Windows) => Some(
            "Turn on Check apps and files in Windows Security > App & browser control. Enable SmartScreen or Safe Browsing in Chrome, Edge, Brave, and Firefox. Check managed browser policies too.",
        ),
        ("web_protection", _) => Some(
            "Enable fraudulent website warnings or Safe Browsing in every installed browser. Check managed policies too.",
        ),
        ("log_oldest_record_days", Os::Linux) => {
            Some("Review journald storage limits and access to the system journal.")
        }
        ("antimalware_full_scan_age_days", _) => {
            Some("Review the antivirus scan history. XProtect has no user-requested full scan.")
        }
        ("process_audit" | "powershell_logging" | "log_cleared", _) => {
            Some("Review Windows audit and PowerShell logging policy and event history.")
        }
        ("log_oldest_record_days", _) => {
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
