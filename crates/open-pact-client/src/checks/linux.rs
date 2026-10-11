use std::fs;

use chrono::{NaiveDate, Utc};

use super::buckets;
use super::exec::run;

const APT_HISTORY: &str = "/var/log/apt/history.log";
const SECURE_BOOT_EFIVAR: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const AUTOLOGIN_FILES: &[&str] = &[
    "/etc/gdm3/custom.conf",
    "/etc/gdm3/daemon.conf",
    "/etc/gdm/custom.conf",
    "/etc/sddm.conf",
    "/etc/lightdm/lightdm.conf",
];
const AUTOLOGIN_DIRS: &[&str] = &["/etc/sddm.conf.d", "/etc/lightdm/lightdm.conf.d"];
const APT_ROTATED_LOGS: u32 = 3;

const UBUNTU_EOL: &[(&str, &str)] = &[
    ("22.04", "2027-06-01"),
    ("24.04", "2029-05-31"),
    ("25.10", "2026-07-01"),
    ("26.04", "2031-05-29"),
];
const FEDORA_EOL: &[(&str, &str)] = &[
    ("42", "2026-05-27"),
    ("43", "2026-12-09"),
    ("44", "2027-06-02"),
];

pub fn disk_encryption() -> &'static str {
    run("lsblk", &["-s", "-n", "-o", "NAME,TYPE,MOUNTPOINT"])
        .map_or("unknown", |t| parse_lsblk_inverse(&t))
}

pub fn firewall() -> &'static str {
    let firewalld = run("firewall-cmd", &["--state"]);
    let units = run("systemctl", &["is-active", "ufw"]);
    merge_firewall(
        firewalld.as_deref().and_then(parse_firewall_cmd),
        units.as_deref().and_then(parse_systemctl_unit),
    )
}

pub fn screen_lock() -> &'static str {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_lowercase();
    if desktop.contains("kde") {
        let Some(home) = std::env::var_os("HOME") else {
            return "unknown";
        };
        let path = std::path::Path::new(&home).join(".config/kscreenlockerrc");
        return match fs::read_to_string(path) {
            Ok(text) => parse_kscreenlocker(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => parse_kscreenlocker(""),
            Err(_) => "unknown",
        };
    }
    if desktop.contains("gnome") || desktop.contains("ubuntu") {
        let get = |schema: &str, key: &str| run("gsettings", &["get", schema, key]);
        let (Some(enabled), Some(idle), Some(delay)) = (
            get("org.gnome.desktop.screensaver", "lock-enabled"),
            get("org.gnome.desktop.session", "idle-delay"),
            get("org.gnome.desktop.screensaver", "lock-delay"),
        ) else {
            return "unknown";
        };
        return parse_gnome_lock(&enabled, &idle, &delay);
    }
    "unknown"
}

pub fn os_supported() -> &'static str {
    fs::read_to_string("/etc/os-release").map_or("unknown", |t| {
        parse_os_supported(&t, Utc::now().date_naive())
    })
}

pub fn os_patch_age() -> &'static str {
    let last = match fs::read_to_string(APT_HISTORY) {
        Ok(text) => first_upgrade_date(
            std::iter::once(text).chain((1..=APT_ROTATED_LOGS).filter_map(read_rotated_apt_log)),
        ),
        Err(_) => run("dnf", &["history", "list"]).and_then(|t| parse_dnf_history(&t)),
    };
    last.map_or("unknown", |d| {
        buckets::patch_age(d, Utc::now().date_naive())
    })
}

fn read_rotated_apt_log(n: u32) -> Option<String> {
    let path = format!("{APT_HISTORY}.{n}");
    fs::read_to_string(&path)
        .ok()
        .or_else(|| run("gzip", &["-dc", &format!("{path}.gz")]))
}

pub fn auto_login() -> &'static str {
    let mut paths: Vec<std::path::PathBuf> = AUTOLOGIN_FILES.iter().map(Into::into).collect();
    for dir in AUTOLOGIN_DIRS {
        if let Ok(dir) = fs::read_dir(dir) {
            paths.extend(dir.flatten().map(|e| e.path()));
        }
    }
    let texts: Vec<String> = paths
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .collect();
    aggregate_autologin(&texts)
}

pub fn secure_boot() -> &'static str {
    match run("mokutil", &["--sb-state"]).map(|t| parse_mokutil(&t)) {
        Some(state) if state != "unknown" => state,
        _ => fs::read(SECURE_BOOT_EFIVAR).map_or("unknown", |b| parse_secure_boot_efivar(&b)),
    }
}

pub fn antimalware_active() -> &'static str {
    run("systemctl", &["is-active", "clamav-daemon", "clamd@scan"])
        .map_or("unknown", |t| parse_antimalware_units(&t))
}

pub fn parse_lsblk_inverse(out: &str) -> &'static str {
    let mut groups: Vec<(bool, bool)> = Vec::new();
    for line in out.lines() {
        let Some(first) = line.chars().next() else {
            continue;
        };
        let root_level = first.is_alphanumeric();
        let mut fields = line
            .trim_start_matches(|c: char| c.is_whitespace() || "│├└─".contains(c))
            .split_whitespace();
        let (Some(_name), Some(kind)) = (fields.next(), fields.next()) else {
            continue;
        };
        let mount = fields.next();
        if root_level {
            groups.push((mount == Some("/"), false));
        }
        if let Some(group) = groups.last_mut() {
            if kind == "crypt" {
                group.1 = true;
            }
        }
    }
    let Some(root) = groups.iter().find(|g| g.0) else {
        return "unknown";
    };
    if root.1 {
        "full"
    } else if groups.iter().any(|g| g.1) {
        "partial"
    } else {
        "none"
    }
}

pub fn parse_firewall_cmd(out: &str) -> Option<bool> {
    let out = out.trim();
    if out == "running" {
        Some(true)
    } else if out.contains("not running") {
        Some(false)
    } else {
        None
    }
}

pub fn parse_systemctl_unit(out: &str) -> Option<bool> {
    match out.trim() {
        "active" => Some(true),
        "inactive" | "failed" => Some(false),
        _ => None,
    }
}

pub fn merge_firewall(firewalld: Option<bool>, ufw: Option<bool>) -> &'static str {
    let states = [firewalld, ufw];
    if states.contains(&Some(true)) {
        "on"
    } else if states.contains(&Some(false)) {
        "off"
    } else {
        "unknown"
    }
}

fn gsettings_number(out: &str) -> Option<u64> {
    out.split_whitespace().last()?.parse().ok()
}

fn gsettings_bool(out: &str) -> Option<bool> {
    match out.trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

pub fn parse_gnome_lock(lock_enabled: &str, idle_delay: &str, lock_delay: &str) -> &'static str {
    let (Some(enabled), Some(idle), Some(delay)) = (
        gsettings_bool(lock_enabled),
        gsettings_number(idle_delay),
        gsettings_number(lock_delay),
    ) else {
        return "unknown";
    };
    if !enabled || idle == 0 {
        return "off";
    }
    buckets::lock_delay(idle.saturating_add(delay))
}

pub fn parse_kscreenlocker(ini: &str) -> &'static str {
    let mut in_daemon = false;
    let mut autolock = true;
    let mut timeout_min: u64 = 5;
    for line in ini.lines().map(str::trim) {
        if let Some(section) = line.strip_prefix('[') {
            in_daemon = section.trim_end_matches(']') == "Daemon";
        } else if in_daemon {
            match line.split_once('=').map(|(k, v)| (k.trim(), v.trim())) {
                Some(("Autolock", v)) => {
                    autolock = !matches!(v.to_lowercase().as_str(), "false" | "no" | "off" | "0");
                }
                Some(("Timeout", v)) => timeout_min = v.parse().unwrap_or(timeout_min),
                _ => {}
            }
        }
    }
    if !autolock {
        return "off";
    }
    buckets::lock_delay(timeout_min.saturating_mul(60))
}

fn os_release_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim().trim_matches('"'))
}

fn version_key(v: &str) -> Option<(u32, u32)> {
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().map_or(Some(0), |m| m.parse().ok())?;
    Some((major, minor))
}

pub fn parse_os_supported(os_release: &str, today: NaiveDate) -> &'static str {
    let table = match os_release_field(os_release, "ID") {
        Some("ubuntu") => UBUNTU_EOL,
        Some("fedora") => FEDORA_EOL,
        _ => return "unknown",
    };
    let Some(version) = os_release_field(os_release, "VERSION_ID") else {
        return "unknown";
    };
    let Some(key) = version_key(version) else {
        return "unknown";
    };
    if let Some((_, eol)) = table.iter().find(|(v, _)| version_key(v) == Some(key)) {
        return match NaiveDate::parse_from_str(eol, "%Y-%m-%d") {
            Ok(eol) if today <= eol => "yes",
            Ok(_) => "no",
            Err(_) => "unknown",
        };
    }
    let newest = table.iter().filter_map(|(v, _)| version_key(v)).max();
    if newest.is_some_and(|n| key > n) {
        "yes"
    } else {
        "no"
    }
}

fn first_date(line: &str) -> Option<NaiveDate> {
    line.split_whitespace()
        .find_map(|t| NaiveDate::parse_from_str(t, "%Y-%m-%d").ok())
}

pub fn parse_apt_history(text: &str) -> Option<NaiveDate> {
    let mut upgraded = false;
    let mut latest = None;
    for line in text.lines() {
        if line.starts_with("Start-Date:") {
            upgraded = false;
        } else if line.starts_with("Upgrade:") {
            upgraded = true;
        } else if line.starts_with("End-Date:") && upgraded {
            latest = latest.max(first_date(line));
        }
    }
    latest
}

pub fn first_upgrade_date(logs: impl Iterator<Item = String>) -> Option<NaiveDate> {
    logs.into_iter().find_map(|log| parse_apt_history(&log))
}

const DNF_UPGRADE_COMMANDS: &[&str] = &[
    "upgrade",
    "update",
    "up",
    "upgrade-minimal",
    "distro-sync",
    "dsync",
    "system-upgrade",
    "offline",
];

fn is_dnf_upgrade(command: &str) -> bool {
    let mut tokens = command
        .split(|c: char| c.is_whitespace() || c == '|')
        .filter(|t| !t.is_empty())
        .skip_while(|t| t.chars().all(|c| c.is_ascii_digit()));
    tokens
        .find(|t| !t.starts_with('-') && !t.rsplit('/').next().is_some_and(is_dnf_program))
        .is_some_and(|t| DNF_UPGRADE_COMMANDS.contains(&t))
}

fn is_dnf_program(name: &str) -> bool {
    matches!(name, "dnf" | "dnf5" | "yum" | "microdnf")
}

pub fn parse_dnf_history(text: &str) -> Option<NaiveDate> {
    text.lines()
        .filter_map(|line| {
            let (at, date) = line.split_whitespace().find_map(|t| {
                Some((
                    line.find(t)?,
                    NaiveDate::parse_from_str(t, "%Y-%m-%d").ok()?,
                ))
            })?;
            is_dnf_upgrade(&line[..at]).then_some(date)
        })
        .max()
}

pub fn parse_autologin(conf: &str) -> bool {
    let mut section = "";
    for line in conf.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[') {
            section = name.trim_end_matches(']');
            continue;
        }
        let Some((key, value)) = line.split_once('=').map(|(k, v)| (k.trim(), v.trim())) else {
            continue;
        };
        match key {
            "AutomaticLoginEnable" if matches!(value.to_lowercase().as_str(), "true" | "1") => {
                return true;
            }
            "User" if section == "Autologin" && !value.is_empty() => return true,
            "autologin-user" if !value.is_empty() => return true,
            _ => {}
        }
    }
    false
}

pub fn aggregate_autologin(configs: &[String]) -> &'static str {
    if configs.is_empty() {
        "unknown"
    } else if configs.iter().any(|c| parse_autologin(c)) {
        "on"
    } else {
        "off"
    }
}

pub fn parse_mokutil(out: &str) -> &'static str {
    if out.contains("SecureBoot enabled") {
        "on"
    } else if out.contains("SecureBoot disabled") {
        "off"
    } else {
        "unknown"
    }
}

pub fn parse_secure_boot_efivar(bytes: &[u8]) -> &'static str {
    match bytes.get(4) {
        Some(1) => "on",
        Some(0) => "off",
        _ => "unknown",
    }
}

pub fn parse_antimalware_units(out: &str) -> &'static str {
    let states: Vec<&str> = out.lines().map(str::trim).collect();
    if states.contains(&"active") {
        "yes"
    } else if states.iter().any(|s| matches!(*s, "inactive" | "failed")) {
        "no"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn lsblk_luks_under_lvm_root() {
        let out = "\
ubuntu--vg-ubuntu--lv lvm  /
└─dm_crypt-0          crypt
  └─nvme0n1p3         part
    └─nvme0n1         disk
nvme0n1p2             part /boot
└─nvme0n1             disk
";
        assert_eq!(parse_lsblk_inverse(out), "full");
    }

    #[test]
    fn lsblk_plain_root() {
        let out = "\
nvme0n1p2 part /
└─nvme0n1 disk
nvme0n1p1 part /boot/efi
└─nvme0n1 disk
";
        assert_eq!(parse_lsblk_inverse(out), "none");
    }

    #[test]
    fn lsblk_encrypted_data_but_plain_root() {
        let out = "\
nvme0n1p2 part /
└─nvme0n1 disk
luks-data crypt /home
└─sda1    part
  └─sda   disk
";
        assert_eq!(parse_lsblk_inverse(out), "partial");
    }

    #[test]
    fn lsblk_without_root_is_unknown() {
        assert_eq!(parse_lsblk_inverse(""), "unknown");
        assert_eq!(
            parse_lsblk_inverse("sda1 part /data\n└─sda disk\n"),
            "unknown"
        );
    }

    #[test]
    fn firewall_sources_merge() {
        assert_eq!(parse_firewall_cmd("running\n"), Some(true));
        assert_eq!(parse_firewall_cmd("not running\n"), Some(false));
        assert_eq!(parse_firewall_cmd("bash: firewall-cmd: not found"), None);
        assert_eq!(parse_systemctl_unit("active\n"), Some(true));
        assert_eq!(parse_systemctl_unit("inactive\n"), Some(false));
        assert_eq!(parse_systemctl_unit(""), None);
        assert_eq!(merge_firewall(Some(false), Some(true)), "on");
        assert_eq!(merge_firewall(None, Some(false)), "off");
        assert_eq!(merge_firewall(None, None), "unknown");
    }

    #[test]
    fn gnome_lock() {
        assert_eq!(
            parse_gnome_lock("true\n", "uint32 300\n", "uint32 0\n"),
            "le_5min"
        );
        assert_eq!(
            parse_gnome_lock("true\n", "uint32 300\n", "uint32 300\n"),
            "le_15min"
        );
        assert_eq!(
            parse_gnome_lock("true\n", "uint32 900\n", "uint32 60\n"),
            "gt_15min"
        );
        assert_eq!(
            parse_gnome_lock("false\n", "uint32 300\n", "uint32 0\n"),
            "off"
        );
        assert_eq!(
            parse_gnome_lock("true\n", "uint32 0\n", "uint32 0\n"),
            "off"
        );
        assert_eq!(
            parse_gnome_lock("", "uint32 300\n", "uint32 0\n"),
            "unknown"
        );
    }

    #[test]
    fn kde_lock() {
        let ini = "[Daemon]\nAutolock=true\nTimeout=10\nLockGrace=30\n";
        assert_eq!(
            parse_kscreenlocker("[Daemon]\nTimeout=5\nLockGrace=300\n"),
            "le_5min"
        );
        assert_eq!(parse_kscreenlocker(ini), "le_15min");
        assert_eq!(parse_kscreenlocker("[Daemon]\nAutolock=false\n"), "off");
        assert_eq!(parse_kscreenlocker(""), "le_5min");
        assert_eq!(parse_kscreenlocker("[Daemon]\nTimeout=30\n"), "gt_15min");
    }

    #[test]
    fn os_release_support() {
        let ubuntu = |v: &str| format!("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"{v}\"\n");
        let today = d(2026, 10, 11);
        assert_eq!(parse_os_supported(&ubuntu("24.04"), today), "yes");
        assert_eq!(parse_os_supported(&ubuntu("22.04"), today), "yes");
        assert_eq!(parse_os_supported(&ubuntu("20.04"), today), "no");
        assert_eq!(parse_os_supported(&ubuntu("25.04"), today), "no");
        assert_eq!(parse_os_supported(&ubuntu("26.10"), today), "yes");
        assert_eq!(parse_os_supported(&ubuntu("22.04"), d(2027, 6, 2)), "no");
        assert_eq!(
            parse_os_supported("ID=fedora\nVERSION_ID=43\n", today),
            "yes"
        );
        assert_eq!(
            parse_os_supported("ID=fedora\nVERSION_ID=41\n", today),
            "no"
        );
        assert_eq!(parse_os_supported("ID=arch\n", today), "unknown");
        assert_eq!(parse_os_supported("", today), "unknown");
    }

    #[test]
    fn apt_history_last_upgrade() {
        let log = "\
Start-Date: 2026-09-01  06:00:00
Commandline: apt install foo
Install: foo:amd64 (1.0)
End-Date: 2026-09-01  06:00:10

Start-Date: 2026-09-20  06:25:01
Commandline: /usr/bin/unattended-upgrade
Upgrade: libc6:amd64 (2.39-1, 2.39-2)
End-Date: 2026-09-20  06:25:30

Start-Date: 2026-10-05  09:00:00
Commandline: apt remove bar
Remove: bar:amd64 (1.0)
End-Date: 2026-10-05  09:00:05
";
        assert_eq!(parse_apt_history(log), Some(d(2026, 9, 20)));
        assert_eq!(parse_apt_history(""), None);
    }

    #[test]
    fn dnf_history_last_upgrade() {
        let out = "\
ID     | Command line             | Date and time    | Action(s)      | Altered
-------------------------------------------------------------------------------
    12 | install htop             | 2026-10-02 08:00 | Install        |    1
    11 | upgrade -y               | 2026-09-28 07:10 | I, O, U        |   42
    10 | update                   | 2026-08-01 07:10 | I, U           |   10
";
        assert_eq!(parse_dnf_history(out), Some(d(2026, 9, 28)));
        assert_eq!(parse_dnf_history("Error: no history"), None);
    }

    #[test]
    fn autologin() {
        let gdm_on = "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=alice\n";
        let gdm_off = "[daemon]\n#AutomaticLoginEnable=true\nWaylandEnable=false\n";
        let sddm_on = "[Autologin]\nUser=alice\nSession=plasma\n";
        let sddm_off = "[Autologin]\nUser=\n";
        assert!(parse_autologin(gdm_on));
        assert!(!parse_autologin(gdm_off));
        assert!(parse_autologin(sddm_on));
        assert!(!parse_autologin(sddm_off));
        assert_eq!(aggregate_autologin(&[]), "unknown");
        assert_eq!(aggregate_autologin(&[gdm_off.into(), sddm_on.into()]), "on");
        assert_eq!(aggregate_autologin(&[gdm_off.into()]), "off");
    }

    #[test]
    fn secure_boot() {
        assert_eq!(parse_mokutil("SecureBoot enabled\n"), "on");
        assert_eq!(
            parse_mokutil("SecureBoot disabled\nPlatform is in Setup Mode\n"),
            "off"
        );
        assert_eq!(
            parse_mokutil("EFI variables are not supported on this system\n"),
            "unknown"
        );
        assert_eq!(parse_secure_boot_efivar(&[6, 0, 0, 0, 1]), "on");
        assert_eq!(parse_secure_boot_efivar(&[6, 0, 0, 0, 0]), "off");
        assert_eq!(parse_secure_boot_efivar(&[]), "unknown");
    }

    #[test]
    fn antimalware() {
        assert_eq!(parse_antimalware_units("active\ninactive\n"), "yes");
        assert_eq!(parse_antimalware_units("inactive\ninactive\n"), "no");
        assert_eq!(parse_antimalware_units(""), "unknown");
    }

    #[test]
    fn dnf5_history_ignores_package_names_and_reads_plain_columns() {
        let out = "\
ID Command line                          Date and time       Action(s) Altered
 9 dnf install python3-update-notifier  2026-10-09 09:00:00                 4
 8 dnf -y upgrade --refresh             2026-09-30 05:47:37                46
 7 dnf5 --config /example.config -y --  2026-10-01 05:47:41               142
";
        assert_eq!(parse_dnf_history(out), Some(d(2026, 9, 30)));
        let only_install = " 9 dnf install foo-update-tools  2026-10-09 09:00:00  4\n";
        assert_eq!(parse_dnf_history(only_install), None);
    }

    #[test]
    fn apt_upgrade_falls_back_to_rotated_logs() {
        let current = "Start-Date: 2026-10-02  06:00:00\nCommandline: apt install foo\nInstall: foo:amd64 (1.0)\nEnd-Date: 2026-10-02  06:00:10\n";
        let rotated = "Start-Date: 2026-09-20  06:25:01\nUpgrade: libc6:amd64 (2.39-1, 2.39-2)\nEnd-Date: 2026-09-20  06:25:30\n";
        let logs = [current.to_string(), String::new(), rotated.to_string()];
        assert_eq!(first_upgrade_date(logs.into_iter()), Some(d(2026, 9, 20)));
        assert_eq!(first_upgrade_date(std::iter::empty()), None);
    }

    #[test]
    fn autologin_keys_may_have_spaces_around_equals() {
        assert!(parse_autologin("[daemon]\nAutomaticLoginEnable = true\n"));
        assert!(parse_autologin("[Autologin]\nUser = alice\n"));
        assert!(!parse_autologin(
            "[daemon]\n#  AutomaticLoginEnable = true\n"
        ));
    }

    #[test]
    fn lightdm_autologin_user() {
        assert!(parse_autologin("[Seat:*]\nautologin-user=alice\n"));
        assert!(!parse_autologin(
            "[Seat:*]\nautologin-user=\n#autologin-user=alice\n"
        ));
    }

    #[test]
    fn kde_lock_keys_tolerate_spaces_and_case() {
        assert_eq!(parse_kscreenlocker("[Daemon]\nAutolock = false\n"), "off");
        assert_eq!(parse_kscreenlocker("[Daemon]\nAutolock=False\n"), "off");
        assert_eq!(parse_kscreenlocker("[Daemon]\nTimeout = 20\n"), "gt_15min");
    }

    #[test]
    fn eol_dates_match_published_tables() {
        assert_eq!(
            parse_os_supported("ID=ubuntu\nVERSION_ID=\"22.04\"\n", d(2027, 6, 1)),
            "yes"
        );
        assert_eq!(
            parse_os_supported("ID=ubuntu\nVERSION_ID=\"22.04\"\n", d(2027, 6, 2)),
            "no"
        );
        assert_eq!(
            parse_os_supported("ID=fedora\nVERSION_ID=43\n", d(2026, 12, 9)),
            "yes"
        );
        assert_eq!(
            parse_os_supported("ID=fedora\nVERSION_ID=43\n", d(2026, 12, 10)),
            "no"
        );
    }

    #[test]
    fn lsblk_ascii_tree_in_non_utf8_locale() {
        let out = "\
vg--root-lv  lvm   /
`-luks-0     crypt
  `-vda3     part
    `-vda    disk
vda2         part  /boot
`-vda        disk
";
        assert_eq!(parse_lsblk_inverse(out), "full");
    }
}
