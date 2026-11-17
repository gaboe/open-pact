mod browsers;
mod buckets;
mod common;
mod exec;
mod hints;
#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(any(target_os = "linux", test))]
mod linux_luks;
#[cfg(any(target_os = "linux", test))]
mod linux_v3;
#[cfg(any(target_os = "macos", test))]
mod macos;
#[cfg(any(target_os = "macos", test))]
mod macos_v3;
pub(crate) mod repos;
#[cfg(any(target_os = "windows", test))]
mod windows;

use std::collections::BTreeMap;

use open_pact_core::{Control, ControlValue, Manifest, Os};
use serde::{Deserialize, Serialize};

use crate::device_config::DeviceConfig;

pub use hints::fix_hint;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct EventMarkers {
    pub(crate) security_log_cleared: Option<i64>,
    pub(crate) antimalware_detection: Option<i64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(not(any(target_os = "windows", target_os = "linux")), allow(dead_code))]
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
    #[cfg(target_os = "linux")]
    {
        linux_v3::event_markers()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
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
            client reads ConfigDataInstall and CriticalUpdateInstall in the \
            SoftwareUpdate preferences. On Windows it reads the Windows Update mode, \
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
const LATER_VERSIONS: &[(&str, u32)] = &[("screen_lock", 2)];

fn implements(control: &Control) -> bool {
    BUILTINS
        .iter()
        .chain(LATER_VERSIONS)
        .any(|(id, v)| control.id == *id && control.check == format!("builtin:{id}@{v}"))
}

/// `screen_lock@2` reports whole minutes. `screen_lock@1` keeps its buckets.
fn screen_lock_version(input: &CheckInput<'_>) -> u32 {
    if input.control.check == "builtin:screen_lock@2" {
        2
    } else {
        1
    }
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
pub(crate) fn can_check(os: Os, id: &str) -> bool {
    let registry = registry(os);
    registry
        .checks
        .iter()
        .any(|(registered_id, _)| *registered_id == id)
        && !registry.not_applicable.contains(&id)
}

#[allow(dead_code)]
pub(crate) struct CheckInput<'a> {
    pub(crate) control: &'a Control,
    pub(crate) device_config: Option<&'a DeviceConfig>,
    pub(crate) repo_scan: Option<&'a repos::RepoScan>,
}

type CheckFn = for<'a> fn(&CheckInput<'a>) -> ControlValue;
type Registry = &'static [(&'static str, CheckFn)];

struct OsRegistry {
    checks: Registry,
    #[cfg(test)]
    not_applicable: &'static [&'static str],
}

fn managed_repo_value(input: &CheckInput<'_>, outside: bool) -> ControlValue {
    let Some(scan) = input.repo_scan else {
        return "unknown".into();
    };
    if scan.partial {
        return "unknown".into();
    }
    if outside {
        scan.managed_repos_outside.into()
    } else {
        scan.managed_repos_total.into()
    }
}

macro_rules! ignore_input {
    ($check:expr) => {
        |_: &CheckInput<'_>| ($check)()
    };
}

#[cfg(any(target_os = "macos", test))]
const MACOS: Registry = &[
    ("os_auto_updates", ignore_input!(macos_v3::os_auto_updates)),
    (
        "antimalware_realtime",
        ignore_input!(macos_v3::antimalware_realtime),
    ),
    (
        "antimalware_active_threats",
        ignore_input!(common::not_applicable),
    ),
    ("work_account", ignore_input!(macos_v3::work_account)),
    ("uptime_days", ignore_input!(macos_v3::uptime_days)),
    (
        "disk_encryption",
        ignore_input!(|| macos::disk_encryption().into()),
    ),
    ("firewall", ignore_input!(|| macos::firewall().into())),
    ("screen_lock", |input| match screen_lock_version(input) {
        2 => macos::screen_lock_minutes(),
        _ => macos::screen_lock().into(),
    }),
    (
        "os_supported",
        ignore_input!(|| macos::os_supported().into()),
    ),
    ("os_patch_age_days", ignore_input!(macos::os_patch_age_days)),
    ("password_set", ignore_input!(common::unknown)),
    ("auto_login", ignore_input!(|| macos::auto_login().into())),
    ("secure_boot", ignore_input!(common::unknown)),
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
        ignore_input!(common::not_applicable),
    ),
    ("web_protection", ignore_input!(macos_v3::web_protection)),
    (
        "log_oldest_record_days",
        ignore_input!(common::not_applicable),
    ),
    ("process_audit", ignore_input!(common::not_applicable)),
    ("remote_wipe", ignore_input!(macos_v3::remote_wipe)),
    ("powershell_logging", ignore_input!(common::not_applicable)),
    ("log_cleared", ignore_input!(common::not_applicable)),
    ("managed_repos_outside", |input| {
        managed_repo_value(input, true)
    }),
    ("managed_repos_total", |input| {
        managed_repo_value(input, false)
    }),
    (
        "password_min_length",
        ignore_input!(macos_v3::password_min_length),
    ),
];

#[cfg(any(target_os = "linux", test))]
const LINUX: Registry = &[
    ("os_auto_updates", ignore_input!(linux_v3::os_auto_updates)),
    (
        "antimalware_realtime",
        ignore_input!(linux_v3::antimalware_realtime),
    ),
    ("antimalware_active_threats", ignore_input!(common::unknown)),
    ("work_account", ignore_input!(linux_v3::work_account)),
    ("uptime_days", ignore_input!(linux_v3::uptime_days)),
    (
        "disk_encryption",
        ignore_input!(|| linux::disk_encryption().into()),
    ),
    ("firewall", ignore_input!(|| linux::firewall().into())),
    ("screen_lock", |input| match screen_lock_version(input) {
        2 => linux::screen_lock_minutes(),
        _ => linux::screen_lock().into(),
    }),
    (
        "os_supported",
        ignore_input!(|| linux::os_supported().into()),
    ),
    ("os_patch_age_days", ignore_input!(linux::os_patch_age_days)),
    ("password_set", ignore_input!(common::unknown)),
    ("auto_login", ignore_input!(|| linux::auto_login().into())),
    ("secure_boot", ignore_input!(|| linux::secure_boot().into())),
    (
        "antimalware_active",
        ignore_input!(|| linux::antimalware_active().into()),
    ),
    ("preboot_auth", ignore_input!(linux_luks::preboot_auth)),
    (
        "antimalware_signature_age_days",
        ignore_input!(linux_v3::antimalware_signature_age_days),
    ),
    (
        "antimalware_full_scan_age_days",
        ignore_input!(common::unknown),
    ),
    ("web_protection", ignore_input!(|| browsers::linux().into())),
    (
        "log_oldest_record_days",
        ignore_input!(linux_v3::log_oldest_record_days),
    ),
    ("process_audit", ignore_input!(common::not_applicable)),
    ("remote_wipe", ignore_input!(common::not_applicable)),
    ("powershell_logging", ignore_input!(common::not_applicable)),
    ("log_cleared", ignore_input!(common::not_applicable)),
    ("managed_repos_outside", |input| {
        managed_repo_value(input, true)
    }),
    ("managed_repos_total", |input| {
        managed_repo_value(input, false)
    }),
    (
        "password_min_length",
        ignore_input!(linux_v3::password_min_length),
    ),
];

#[cfg(any(target_os = "windows", test))]
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
    ("screen_lock", |input| match screen_lock_version(input) {
        2 => windows::screen_lock_minutes(),
        _ => windows::screen_lock(),
    }),
    ("os_supported", ignore_input!(windows::os_supported)),
    (
        "os_patch_age_days",
        ignore_input!(windows::os_patch_age_days),
    ),
    ("password_set", ignore_input!(common::unknown)),
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
    ("remote_wipe", ignore_input!(common::not_applicable)),
    (
        "powershell_logging",
        ignore_input!(windows::powershell_logging),
    ),
    ("log_cleared", ignore_input!(windows::log_cleared)),
    ("managed_repos_outside", |input| {
        managed_repo_value(input, true)
    }),
    ("managed_repos_total", |input| {
        managed_repo_value(input, false)
    }),
    (
        "password_min_length",
        ignore_input!(windows::password_min_length),
    ),
];

fn registry(os: Os) -> OsRegistry {
    match os {
        #[cfg(any(target_os = "macos", test))]
        Os::Macos => OsRegistry {
            checks: MACOS,
            #[cfg(test)]
            not_applicable: &[
                "antimalware_active_threats",
                "antimalware_full_scan_age_days",
                "log_oldest_record_days",
                "process_audit",
                "powershell_logging",
                "log_cleared",
            ],
        },
        #[cfg(any(target_os = "linux", test))]
        Os::Linux => OsRegistry {
            checks: LINUX,
            #[cfg(test)]
            not_applicable: &[
                "process_audit",
                "remote_wipe",
                "powershell_logging",
                "log_cleared",
            ],
        },
        #[cfg(any(target_os = "windows", test))]
        Os::Windows => OsRegistry {
            checks: WINDOWS,
            #[cfg(test)]
            not_applicable: &["remote_wipe"],
        },
        // A release binary carries only its own OS checks; a foreign OS has none.
        #[cfg(not(test))]
        _ => OsRegistry {
            checks: &[],
            #[cfg(test)]
            not_applicable: &[],
        },
    }
}

#[cfg(test)]
type LegacyRegistry = &'static [(&'static str, fn() -> ControlValue)];

#[cfg(test)]
fn legacy_registry(os: Os) -> LegacyRegistry {
    const MACOS: LegacyRegistry = &[
        ("os_auto_updates", macos_v3::os_auto_updates),
        ("antimalware_realtime", macos_v3::antimalware_realtime),
        ("antimalware_active_threats", common::not_applicable),
        ("work_account", macos_v3::work_account),
        ("uptime_days", macos_v3::uptime_days),
        ("disk_encryption", || macos::disk_encryption().into()),
        ("firewall", || macos::firewall().into()),
        ("screen_lock", || macos::screen_lock().into()),
        ("os_supported", || macos::os_supported().into()),
        ("os_patch_age_days", macos::os_patch_age_days),
        ("password_set", common::unknown),
        ("auto_login", || macos::auto_login().into()),
        ("secure_boot", common::unknown),
        ("antimalware_active", || macos::antimalware_active().into()),
        ("preboot_auth", macos_v3::preboot_auth),
        (
            "antimalware_signature_age_days",
            macos_v3::antimalware_signature_age_days,
        ),
        ("antimalware_full_scan_age_days", common::not_applicable),
        ("web_protection", macos_v3::web_protection),
        ("log_oldest_record_days", common::not_applicable),
        ("process_audit", common::not_applicable),
        ("remote_wipe", macos_v3::remote_wipe),
        ("powershell_logging", common::not_applicable),
        ("log_cleared", common::not_applicable),
        ("password_min_length", macos_v3::password_min_length),
    ];
    const LINUX: LegacyRegistry = &[
        ("os_auto_updates", linux_v3::os_auto_updates),
        ("antimalware_realtime", linux_v3::antimalware_realtime),
        ("antimalware_active_threats", common::unknown),
        ("work_account", linux_v3::work_account),
        ("uptime_days", linux_v3::uptime_days),
        ("disk_encryption", || linux::disk_encryption().into()),
        ("firewall", || linux::firewall().into()),
        ("screen_lock", || linux::screen_lock().into()),
        ("os_supported", || linux::os_supported().into()),
        ("os_patch_age_days", linux::os_patch_age_days),
        ("password_set", common::unknown),
        ("auto_login", || linux::auto_login().into()),
        ("secure_boot", || linux::secure_boot().into()),
        ("antimalware_active", || linux::antimalware_active().into()),
        ("preboot_auth", linux_luks::preboot_auth),
        (
            "antimalware_signature_age_days",
            linux_v3::antimalware_signature_age_days,
        ),
        ("antimalware_full_scan_age_days", common::unknown),
        ("web_protection", || browsers::linux().into()),
        ("log_oldest_record_days", linux_v3::log_oldest_record_days),
        ("process_audit", common::not_applicable),
        ("remote_wipe", common::not_applicable),
        ("powershell_logging", common::not_applicable),
        ("log_cleared", common::not_applicable),
        ("password_min_length", linux_v3::password_min_length),
    ];
    const WINDOWS: LegacyRegistry = &[
        ("os_auto_updates", windows::os_auto_updates),
        ("antimalware_realtime", windows::antimalware_realtime),
        (
            "antimalware_active_threats",
            windows::antimalware_active_threats,
        ),
        ("work_account", windows::work_account),
        ("uptime_days", windows::uptime_days),
        ("disk_encryption", windows::disk_encryption),
        ("firewall", windows::firewall),
        ("screen_lock", windows::screen_lock),
        ("os_supported", windows::os_supported),
        ("os_patch_age_days", windows::os_patch_age_days),
        ("password_set", common::unknown),
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
        ("web_protection", windows::web_protection),
        ("log_oldest_record_days", windows::log_oldest_record_days),
        ("process_audit", windows::process_audit),
        ("remote_wipe", common::not_applicable),
        ("powershell_logging", windows::powershell_logging),
        ("log_cleared", windows::log_cleared),
        ("password_min_length", windows::password_min_length),
    ];
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
    device_config: Option<&DeviceConfig>,
    repo_scan: Option<&repos::RepoScan>,
) -> BTreeMap<String, ControlValue> {
    registry(os)
        .checks
        .iter()
        .filter_map(|(id, check)| {
            let control = controls.iter().find(|control| control.id == *id)?;
            let input = CheckInput {
                control,
                device_config,
                repo_scan,
            };
            let value =
                std::panic::catch_unwind(|| check(&input)).unwrap_or_else(|_| "unknown".into());
            Some(((*id).to_string(), value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        run(os, &controls, None, None)
    }

    #[test]
    fn every_builtin_has_a_check_on_every_os() {
        for os in Os::ALL {
            let ids: Vec<&str> = registry(os).checks.iter().map(|(id, _)| *id).collect();
            let builtins: Vec<&str> = BUILTINS.iter().map(|(id, _)| *id).collect();
            assert_eq!(ids, builtins, "{os}");
        }
    }

    #[test]
    fn unavailable_controls_are_not_checkable_on_their_os() {
        for (os, unavailable) in [
            (
                Os::Macos,
                &[
                    "antimalware_active_threats",
                    "antimalware_full_scan_age_days",
                    "log_oldest_record_days",
                    "process_audit",
                    "powershell_logging",
                    "log_cleared",
                ][..],
            ),
            (
                Os::Linux,
                &[
                    "process_audit",
                    "remote_wipe",
                    "powershell_logging",
                    "log_cleared",
                ][..],
            ),
            (Os::Windows, &["remote_wipe"][..]),
        ] {
            for id in unavailable {
                assert!(!can_check(os, id), "{id} should be unavailable on {os}");
            }
            for (id, _) in registry(os).checks {
                if !unavailable.contains(id) {
                    assert!(can_check(os, id), "{id} should be checkable on {os}");
                }
            }
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
        let ran = run(Os::Windows, &controls, None, None);
        assert_eq!(ran.into_keys().collect::<Vec<_>>(), ["firewall"]);
    }

    #[test]
    fn registry_values_match_the_pre_refactor_checks_for_every_control() {
        let manifest =
            Manifest::parse(include_bytes!("../../../../examples/manifest.toml")).unwrap();
        let controls = BUILTINS
            .iter()
            .map(|(id, _)| {
                let mut control = manifest.body().controls[0].clone();
                control.id = (*id).into();
                control
            })
            .collect::<Vec<_>>();
        for os in Os::ALL {
            let mut expected = legacy_registry(os)
                .iter()
                .map(|(id, check)| {
                    (
                        (*id).to_owned(),
                        std::panic::catch_unwind(*check).unwrap_or_else(|_| "unknown".into()),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            expected.insert("managed_repos_outside".into(), "unknown".into());
            expected.insert("managed_repos_total".into(), "unknown".into());
            assert_eq!(run(os, &controls, None, None), expected, "{os}");
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
    fn screen_lock_at_version_two_is_a_supported_builtin_and_reports_its_own_value() {
        let demo = include_str!("../../../../examples/manifest.toml");
        let manifest = Manifest::parse(
            demo.replace("builtin:screen_lock@1", "builtin:screen_lock@2")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(check_supported(&manifest), Ok(()));
        let control = manifest.body().control("screen_lock").unwrap();
        assert_eq!(control.check, "builtin:screen_lock@2");
        // Off its own OS every check reads unknown; the value is the same for both versions there.
        for os in Os::ALL {
            let value = run(os, std::slice::from_ref(control), None, None);
            assert!(value.contains_key("screen_lock"), "{os}");
        }
        assert_eq!(
            screen_lock_version(&CheckInput {
                control,
                device_config: None,
                repo_scan: None
            }),
            2
        );
    }

    #[test]
    fn every_os_registers_the_same_checks() {
        let ids = |os| -> Vec<&str> { registry(os).checks.iter().map(|(id, _)| *id).collect() };
        assert_eq!(ids(Os::Macos), ids(Os::Linux));
        assert_eq!(ids(Os::Macos), ids(Os::Windows));
        assert_eq!(ids(Os::Macos).len(), BUILTINS.len());
    }

    #[test]
    #[cfg(not(windows))]
    fn windows_checks_report_unknown_off_windows_except_not_applicable_controls() {
        let all = run_all(Os::Windows);
        assert_eq!(all.len(), BUILTINS.len());
        assert_eq!(all["remote_wipe"], "n/a");
        assert!(
            all.iter()
                .filter(|(id, _)| id.as_str() != "remote_wipe")
                .all(|(_, value)| value == "unknown")
        );
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
    fn every_builtin_has_a_non_empty_default_text() {
        for (id, version) in BUILTINS {
            let check = format!("builtin:{id}@{version}");
            assert!(
                builtin_about(&check).is_some_and(|text| !text.trim().is_empty()),
                "{check}"
            );
        }
    }

    #[test]
    fn default_texts_are_the_builtins_in_order() {
        let keys: Vec<(&str, u32)> = builtin_defaults()
            .map(|(id, version, _)| (id, version))
            .collect();
        assert_eq!(keys, BUILTINS);
    }

    #[test]
    fn builtin_about_matches_only_an_exact_builtin_check() {
        let firewall = builtin_about("builtin:firewall@1").unwrap();
        assert!(firewall.starts_with("A device without a firewall accepts network connections"));
        assert_eq!(builtin_about("builtin:firewall@2"), None);
        assert_eq!(builtin_about("builtin:firewall@1 "), None);
        assert_eq!(builtin_about("firewall"), None);
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

#[cfg(test)]
mod contracts;
