//! The built-in check catalog: which `builtin:<id>@<version>` checks exist and what each one means.
//! A client runs the checks; this module owns the list, so every app reads it from one place.

use crate::manifest::{Control, Manifest};

/// The builtins a client can run, by control id and version. A manifest control runs only if its
/// `check` is exactly `builtin:<id>@<version>` from this table or from `LATER_VERSIONS`.
pub const BUILTINS: &[(&str, u32)] = &[
    ("os_auto_updates", 1),
    ("antimalware_realtime", 1),
    ("antimalware_active_threats", 1),
    ("work_account", 1),
    ("uptime_days", 1),
    ("disk_encryption", 1),
    ("firewall", 1),
    ("sip_enabled", 1),
    ("gatekeeper", 1),
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
    ("remote_wipe", 1),
    ("powershell_logging", 1),
    ("log_cleared", 1),
    ("managed_repos_outside", 1),
    ("managed_repos_total", 1),
    ("password_min_length", 1),
];

/// The default text of each builtin, as (id, version, text), in BUILTINS order. A control's
/// `description` in the manifest replaces it. This is the one copy that the apps read through
/// `manifest builtins --json`.
const BUILTIN_ABOUT: &[(&str, u32, &str)] = &[
    (
        "os_auto_updates",
        1,
        "Updates that need a manual click often wait for weeks. On macOS the \
            client reads AutomaticCheckEnabled, ConfigDataInstall and \
            CriticalUpdateInstall in the SoftwareUpdate preferences. On Windows it reads the Windows Update mode, \
            the pause state and the NoAutoUpdate policy, and on Linux the apt \
            unattended-upgrade settings and the apt-daily-upgrade or dnf-automatic \
            timer.",
    ),
    (
        "antimalware_realtime",
        1,
        "Without real-time scanning, malware is found only when someone starts a \
            scan. On macOS the client gives the same result as Antimalware active \
            (the XProtect check). On Windows it reads RealTimeProtectionEnabled from \
            Microsoft Defender, and on Linux it checks whether the ClamAV on-access \
            scanner clamonacc is running.",
    ),
    (
        "antimalware_active_threats",
        1,
        "A threat that the antimalware program found and did not remove is still \
            a risk. On Windows the client counts the Microsoft Defender threats \
            marked active (Get-MpThreat). On macOS it reports n/a and on Linux it \
            reports unknown, because the client has no threat list to read there.",
    ),
    (
        "antimalware_active_threats",
        2,
        "A threat that the antimalware program found and did not remove is still \
            a risk. On Windows the client counts the Microsoft Defender threats \
            marked active. On macOS it reads the XProtect Remediator events of the \
            last 7 days in the unified log. It reports 0 when there is at least one \
            event and every event is a clean result, and unknown when an event is \
            not clean, the log has no event, or any part of the read cannot be \
            classified. On Linux the result is the same as version 1.",
    ),
    (
        "work_account",
        1,
        "A work account with administrator rights lets malware change the system. \
            On macOS the client checks whether the user is in the admin group. On \
            Windows it checks the Administrators group in the user's token, and on \
            Linux it checks the sudo, wheel and root groups.",
    ),
    (
        "uptime_days",
        1,
        "A device that never restarts misses the updates that need a restart. On \
            macOS the client reads kern.boottime with sysctl. On Windows it reads \
            LastBootUpTime from Win32_OperatingSystem, and on Linux the first value \
            in /proc/uptime.",
    ),
    (
        "disk_encryption",
        1,
        "A lost or stolen device gives away its files when the disk is not \
            encrypted. On macOS the client runs fdesetup status to see whether \
            FileVault is on, and on Windows it reads the BitLocker protection state \
            of the system drive. On Linux it runs lsblk -s and counts a disk as \
            encrypted only when every path from it to its physical devices crosses \
            an active encryption layer; it checks each writable, non-removable disk \
            that is mounted or used as swap, and skips the boot mounts /boot, \
            /boot/efi and /efi, loop, optical and RAM-backed devices, and \
            non-persistent filesystems such as tmpfs and overlay.",
    ),
    (
        "firewall",
        1,
        "A device without a firewall accepts network connections that it should \
            refuse. On macOS the client runs socketfilterfw --getglobalstate. On \
            Windows it reads the Domain, Private and Public profiles with \
            Get-NetFirewallProfile (all three must be on), and on Linux it asks \
            firewalld (firewall-cmd --state) and reads the UFW configuration.",
    ),
    (
        "sip_enabled",
        1,
        "Without System Integrity Protection, software can change the protected parts of \
            macOS. On macOS the client runs csrutil status and reads whether the \
            protection is enabled. A custom configuration that turns off any \
            protection counts as off. On Windows and Linux the control does not \
            apply and reports n/a.",
    ),
    (
        "gatekeeper",
        1,
        "Gatekeeper checks that an app from the internet is signed by a known \
            developer and notarized by Apple before it first starts; the user can still allow \
            one app with Open Anyway. On macOS the client runs spctl --status \
            and reads whether assessments are enabled. On Windows and Linux the \
            control does not apply and reports n/a.",
    ),
    (
        "screen_lock",
        1,
        "A device that stays unlocked gives access to anyone nearby. On macOS \
            the client runs sysadminctl -screenLock status and reads only the password \
            delay that applies after the screen saver starts or the display turns off; \
            on Windows it reads the machine inactivity limit, else the secure screen \
            saver of each signed-in user; on Linux it reads the GNOME settings with \
            gsettings or the KDE kscreenlockerrc file. The macOS result does not show \
            the idle time that starts the screen saver or turns off the display.",
    ),
    (
        "screen_lock",
        2,
        "A device that stays unlocked gives access to anyone nearby. The client \
            reports whole minutes, or none when the screen never locks. On macOS it \
            adds the password delay from sysadminctl -screenLock status to the shorter of \
            the screen saver idle time and the display sleep time from pmset, rounded up \
            to whole minutes; on Windows it reads the machine inactivity limit, \
            else the secure screen saver of each signed-in user; on Linux it reads the \
            GNOME settings with gsettings or the KDE kscreenlockerrc file.",
    ),
    (
        "os_supported",
        1,
        "An OS that no longer gets vendor updates collects security holes that \
            nobody fixes. The client compares the OS version with end-of-support \
            dates built into it. On macOS it runs sw_vers (the latest three major \
            versions count as supported), on Windows it reads the build, edition and \
            version from the registry, and on Linux it reads /etc/os-release (only \
            Ubuntu and Fedora are known, other distributions report unknown).",
    ),
    (
        "os_patch_age_days",
        1,
        "A device that has not been updated for a long time lacks recent security \
            fixes. On macOS the client reads the newest macOS entry in \
            /Library/Receipts/InstallHistory.plist. On Windows it reads the install \
            date of the newest cumulative update package, and on Linux the last full \
            upgrade in the apt history or dnf history, counted only when no security \
            update is waiting.",
    ),
    (
        "password_set",
        1,
        "An account with no password lets anyone who holds the device sign in. \
            The client has no reader for this setting yet, so it reports unknown on \
            macOS, Windows and Linux. Use Password policy to ask for a minimum \
            length instead.",
    ),
    (
        "auto_login",
        1,
        "Automatic login lets anyone who starts the device reach the user's files \
            without a password. On macOS the client reads autoLoginUser in the login \
            window preferences. On Windows it reads AutoAdminLogon in the Winlogon \
            registry key, and on Linux it reads the GDM, SDDM and LightDM \
            configuration files.",
    ),
    (
        "secure_boot",
        1,
        "Without Secure Boot, malware can replace the start-up software before \
            the system loads. On Windows the client reads the UEFISecureBootEnabled \
            value in the registry, and on Linux it runs mokutil --sb-state and falls \
            back to the SecureBoot EFI variable. On macOS it always reports unknown.",
    ),
    (
        "antimalware_active",
        1,
        "A device with no working antimalware program has no defence against \
            known malware. On macOS the client checks that the XProtect files exist \
            and that its scan service is registered and not disabled in launchctl. \
            On Windows it asks Windows Security Center for an antivirus product that \
            is on (else it reads the Defender status), and on Linux it checks \
            whether the ClamAV service clamav-daemon or clamd@scan is active.",
    ),
    (
        "preboot_auth",
        1,
        "A disk that unlocks by itself protects nothing when someone else holds \
            the device, so a secret should be needed before the disk unlocks. On \
            macOS the client reads the FileVault state with fdesetup. On Windows it \
            lists the BitLocker key protectors of the system drive (a PIN or \
            passphrase counts, TPM alone does not), and on Linux it reads \
            /etc/crypttab and the LUKS key slots with cryptsetup.",
    ),
    (
        "antimalware_signature_age_days",
        1,
        "Old signatures cannot spot new malware. On macOS the client takes the \
            age of the installed XProtect version from the install history. On \
            Windows it reads AntivirusSignatureLastUpdated from Microsoft Defender, \
            and on Linux the date in the header of the ClamAV daily.cvd or daily.cld \
            database.",
    ),
    (
        "antimalware_full_scan_age_days",
        1,
        "A full scan can find malware that real-time protection missed. On \
            Windows the client reads FullScanEndTime from Microsoft Defender. On \
            macOS it reports n/a and on Linux it reports unknown, because the client \
            has no scan history to read there.",
    ),
    (
        "antimalware_full_scan_age_days",
        2,
        "A full scan can find malware that real-time protection missed. On \
            Windows the client reads the Windows Defender full scan time, \
            FullScanEndTime. On macOS it reports the whole days since the last \
            XProtect Remediator scan in the unified log; canceled runs do not count \
            and that scan is not a full-device scan. The log keeps these events for \
            a short time, so an old scan reads unknown, as does a read with any \
            part that cannot be classified. On Linux the result is the same as \
            version 1.",
    ),
    (
        "web_protection",
        1,
        "A browser that does not block known bad sites lets phishing and malware \
            pages load. The client reads the safe browsing setting of Chrome, Edge, \
            Brave and Firefox on macOS and Windows, and of Chrome, Chromium and \
            Firefox on Linux, policy first and then the user's profile. On Windows \
            it also reads the Windows SmartScreen setting; Safari is not read.",
    ),
    (
        "log_oldest_record_days",
        1,
        "A short log history hides what happened before an incident. On Windows \
            the client reads the age of the oldest event in the Security and the \
            System log and keeps the smaller one (this needs administrator rights), \
            and on Linux it reads the oldest entry of the system journal with \
            journalctl --system. macOS reports n/a.",
    ),
    (
        "process_audit",
        1,
        "Windows writes a log entry each time a program starts, so after an \
            incident you can see what ran. The client reads the Process Creation \
            audit policy. The check is on only when the entry also includes the \
            command line; it needs administrator rights, and macOS and Linux report \
            n/a.",
    ),
    (
        "remote_wipe",
        1,
        "A lost device can be erased from a distance only when remote management \
            is set up. On macOS the client runs system_profiler to see whether \
            Activation Lock (Find My Mac) is on. Windows and Linux report n/a, \
            because the client reads no remote erase setting there.",
    ),
    (
        "powershell_logging",
        1,
        "PowerShell scripts are a common way to run malware, so a record of them \
            helps after an incident. On Windows the client reads the Script Block \
            Logging policy (EnableScriptBlockLogging), the machine policy first and \
            then the policy of each signed-in user. macOS and Linux report n/a.",
    ),
    (
        "log_cleared",
        1,
        "An attacker who clears the event log hides what was done. On Windows the \
            client reads the newest clear event (event 1102 in the Security log, \
            event 104 in the System log) and reports its time, or none when no such \
            event exists; this needs administrator rights. macOS and Linux report \
            n/a.",
    ),
    (
        "managed_repos_outside",
        1,
        "Work code outside the agreed folders is harder to find and to protect. \
            The client scans the user's home folder, down to 8 levels, for Git \
            repositories whose remote matches the manifest patterns, and counts \
            those outside the listed folders. It reads the Git configuration files \
            and does not run git; a missing or old scan (over 48 hours) gives \
            unknown.",
    ),
    (
        "managed_repos_total",
        1,
        "The count shows how much company code sits on the device. The client \
            scans the user's home folder, down to 8 levels, for Git repositories \
            whose remote matches the manifest patterns, and counts all of them. It \
            reads the Git configuration files and does not run git; a missing or old \
            scan (over 48 hours) gives unknown.",
    ),
    (
        "password_min_length",
        1,
        "Short passwords are easy to guess. On macOS the client runs pwpolicy \
            getaccountpolicies and takes the longest length rule. On Windows it \
            reads the minimum password length of the local account database (a \
            domain policy is not read), and on Linux it reads minlen from \
            /etc/security/pwquality.conf and the files in pwquality.conf.d.",
    ),
];

/// Every builtin with its default text, in BUILTINS order.
pub fn builtin_defaults() -> impl Iterator<Item = (&'static str, u32, &'static str)> {
    BUILTIN_ABOUT.iter().copied()
}

/// The default text of the builtin that `check` names, such as `builtin:firewall@1`. None for any other check.
pub fn builtin_about(check: &str) -> Option<&'static str> {
    BUILTIN_ABOUT
        .iter()
        .find(|(id, version, _)| check == format!("builtin:{id}@{version}"))
        .map(|(_, _, about)| *about)
}

/// Later versions of a builtin. The registry runs one check per id and picks the version from the
/// control's `check`.
pub const LATER_VERSIONS: &[(&str, u32)] = &[
    ("screen_lock", 2),
    ("antimalware_active_threats", 2),
    ("antimalware_full_scan_age_days", 2),
];

fn implements(control: &Control) -> bool {
    BUILTINS
        .iter()
        .chain(LATER_VERSIONS)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_compiled_builtins_at_their_exact_version() {
        let demo = include_str!("../../../examples/manifest.toml");
        let parse = |toml: &str| Manifest::parse(toml.as_bytes()).unwrap();
        assert_eq!(check_supported(&parse(demo)), Ok(()));
        for (from, to) in [
            ("builtin:firewall@1", "builtin:firewall@2"),
            ("builtin:firewall@1", "builtin:screen_lock@1"),
            ("builtin:firewall@1", "builtin:screen_lock@3"),
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
    fn every_builtin_has_a_non_empty_default_text() {
        for (id, version) in BUILTINS.iter().chain(LATER_VERSIONS) {
            let check = format!("builtin:{id}@{version}");
            assert!(
                builtin_about(&check).is_some_and(|text| !text.trim().is_empty()),
                "{check}"
            );
        }
    }

    #[test]
    fn default_texts_cover_exactly_the_builtins() {
        let mut keys: Vec<(&str, u32)> = builtin_defaults()
            .map(|(id, version, _)| (id, version))
            .collect();
        let mut builtins: Vec<(&str, u32)> =
            BUILTINS.iter().chain(LATER_VERSIONS).copied().collect();
        keys.sort_unstable();
        builtins.sort_unstable();
        assert_eq!(keys, builtins);
        assert!(builtin_about("builtin:screen_lock@2").is_some());
    }

    #[test]
    fn builtin_about_matches_only_an_exact_builtin_check() {
        let firewall = builtin_about("builtin:firewall@1").unwrap();
        assert!(firewall.starts_with("A device without a firewall accepts network connections"));
        assert_eq!(builtin_about("builtin:firewall@2"), None);
        assert_eq!(builtin_about("builtin:firewall@1 "), None);
        assert_eq!(builtin_about("firewall"), None);
    }
}
