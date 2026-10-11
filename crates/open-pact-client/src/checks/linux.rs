use std::fs;

use chrono::{NaiveDate, Utc};

use super::buckets;
use super::exec::run;

const UFW_CONF: &str = "/etc/ufw/ufw.conf";
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
    run(
        "lsblk",
        &["-s", "-n", "-o", "NAME,TYPE,RO,RM,FSTYPE,MOUNTPOINT"],
    )
    .map_or("unknown", |t| parse_lsblk_inverse(&t))
}

pub fn firewall() -> &'static str {
    let firewalld = run("firewall-cmd", &["--state"]);
    let service = run("systemctl", &["is-active", "ufw"])
        .as_deref()
        .and_then(parse_systemctl_unit);
    let conf = fs::read_to_string(UFW_CONF).ok();
    merge_firewall(
        firewalld.as_deref().and_then(parse_firewall_cmd),
        ufw_enabled(conf.as_deref(), service),
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
    if security_updates_pending() {
        return "unknown";
    }
    last.map_or("unknown", |d| {
        buckets::patch_age(d, Utc::now().date_naive())
    })
}

fn security_updates_pending() -> bool {
    if fs::metadata(APT_HISTORY).is_ok() {
        return run("apt-get", &["-s", "-o", "Debug::NoLocking=1", "upgrade"])
            .is_some_and(|t| apt_security_pending(&t));
    }
    run("dnf", &["-C", "-q", "updateinfo", "list", "--security"])
        .is_some_and(|t| dnf_security_pending(&t))
}

/// Reads `apt-get -s upgrade`. A package in the security pocket with an
/// `Inst` line, or any kept-back package, is an outstanding update.
pub fn apt_security_pending(out: &str) -> bool {
    out.lines().any(|l| {
        (l.starts_with("Inst ") && l.to_lowercase().contains("security"))
            || l.contains("have been kept back")
    })
}

/// Reads `dnf updateinfo list --security`. Each advisory is one line that
/// starts with an id such as `FICTIONAL-2026-0001`.
pub fn dnf_security_pending(out: &str) -> bool {
    out.lines().any(|l| {
        let mut t = l.split_whitespace();
        let id = t.next().unwrap_or("");
        t.count() >= 2
            && id.contains('-')
            && id.chars().any(|c| c.is_ascii_digit())
            && id.chars().next().is_some_and(|c| c.is_ascii_uppercase())
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

/// One block device that nothing else is stacked on, with the facts the
/// encryption check needs. `lsblk -s` lists each such device first, then its
/// ancestors. A filesystem backed by several devices (RAID, multi-PV LVM,
/// multi-device btrfs) has several leaf paths, and each needs a crypt device.
struct StorageGroup {
    name: String,
    kind: String,
    read_only: bool,
    removable: bool,
    fstype: String,
    mount: String,
    /// The device itself and its ancestors as (tree depth, is crypt), in
    /// `lsblk -s` order.
    tree: Vec<(usize, bool)>,
}

/// Mounts that hold no user data and stay plaintext on a standard encrypted
/// install, so they do not count against `disk_encryption`.
const BOOT_MOUNTS: &[&str] = &["/boot", "/boot/efi", "/efi"];
const NON_PERSISTENT_FSTYPES: &[&str] =
    &["squashfs", "iso9660", "udf", "tmpfs", "overlay", "ramfs"];

#[derive(PartialEq)]
enum Coverage {
    All,
    Some,
    NoneCovered,
}

impl StorageGroup {
    /// Encryption coverage of the backing leaf paths, or None when the tree
    /// skips a depth level and cannot be trusted.
    fn coverage(&self) -> Option<Coverage> {
        let mut on_path: Vec<bool> = Vec::new();
        let mut leaves: Vec<bool> = Vec::new();
        for (i, &(depth, crypt)) in self.tree.iter().enumerate() {
            if depth > on_path.len() {
                return None;
            }
            on_path.truncate(depth);
            on_path.push(crypt || on_path.last().copied().unwrap_or(false));
            if self.tree.get(i + 1).is_none_or(|&(next, _)| next <= depth) {
                leaves.push(on_path[depth]);
            }
        }
        Some(if leaves.iter().all(|&c| c) {
            Coverage::All
        } else if leaves.iter().any(|&c| c) {
            Coverage::Some
        } else {
            Coverage::NoneCovered
        })
    }

    fn is_swap(&self) -> bool {
        self.fstype == "swap" || self.mount == "[SWAP]"
    }

    /// In scope: a writable, non-removable, persistent local block device that
    /// is mounted or used as swap. Excluded on purpose: read-only and
    /// removable media, loop and optical devices, squashfs/iso/tmpfs/overlay,
    /// zram (RAM-backed), boot partitions, and unmounted devices.
    fn in_scope(&self) -> bool {
        if self.read_only || self.removable {
            return false;
        }
        if matches!(self.kind.as_str(), "loop" | "rom") || self.name.starts_with("zram") {
            return false;
        }
        if NON_PERSISTENT_FSTYPES.contains(&self.fstype.as_str()) {
            return false;
        }
        if self.is_swap() {
            return true;
        }
        !self.mount.is_empty() && !BOOT_MOUNTS.contains(&self.mount.as_str())
    }
}

fn parse_lsblk_row<'a>(
    mut fields: impl Iterator<Item = &'a str>,
) -> Option<(bool, bool, String, String)> {
    let read_only = flag(fields.next()?)?;
    let removable = flag(fields.next()?)?;
    let tail: Vec<&str> = fields.collect();
    let (fstype, mount) = match tail.as_slice() {
        [] => ("", String::new()),
        [one] if one.starts_with('/') || one.starts_with('[') => ("", (*one).to_string()),
        [one] => (*one, String::new()),
        [fs, mount @ ..] => (*fs, mount.join(" ")),
    };
    Some((read_only, removable, fstype.to_string(), mount))
}

fn flag(s: &str) -> Option<bool> {
    match s {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

/// Input is `lsblk -s -n -o NAME,TYPE,RO,RM,FSTYPE,MOUNTPOINT`.
///
/// `full` when every backing leaf path of every in-scope filesystem has a
/// crypt device, `none` when no leaf path has one, `partial` otherwise (also
/// for one filesystem whose branches are only partly encrypted), `unknown`
/// when the root filesystem is not listed or the tree cannot be read.
pub fn parse_lsblk_inverse(out: &str) -> &'static str {
    let mut groups: Vec<StorageGroup> = Vec::new();
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let depth = line
            .chars()
            .take_while(|c| !c.is_alphanumeric())
            .count()
            .div_ceil(2);
        let body = line.trim_start_matches(|c: char| c.is_whitespace() || "│├└─|`-".contains(c));
        let mut parts = body.split_whitespace();
        let (Some(name), Some(kind)) = (parts.next(), parts.next()) else {
            return "unknown";
        };
        if depth == 0 {
            let Some((read_only, removable, fstype, mount)) = parse_lsblk_row(parts) else {
                return "unknown";
            };
            groups.push(StorageGroup {
                name: name.to_string(),
                kind: kind.to_string(),
                read_only,
                removable,
                fstype,
                mount,
                tree: vec![(0, kind == "crypt")],
            });
        } else if let Some(group) = groups.last_mut() {
            group.tree.push((depth, kind == "crypt"));
        } else {
            return "unknown";
        }
    }
    let scoped: Vec<&StorageGroup> = groups.iter().filter(|g| g.in_scope()).collect();
    if !scoped.iter().any(|g| g.mount == "/") {
        return "unknown";
    }
    let mut coverage = Vec::new();
    for group in scoped {
        match group.coverage() {
            Some(c) => coverage.push(c),
            None => return "unknown",
        }
    }
    if coverage.iter().all(|c| *c == Coverage::All) {
        "full"
    } else if coverage.iter().all(|c| *c == Coverage::NoneCovered) {
        "none"
    } else {
        "partial"
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

/// The ufw service is a oneshot unit that stays `active` after it exits, even
/// when `ENABLED=no` makes it load no rules. UFW protects the device only when
/// `/etc/ufw/ufw.conf` says `ENABLED=yes` (world-readable, no root needed) and
/// the service is active. Without the file the config cannot confirm anything,
/// so an active service alone is `None`.
pub fn ufw_enabled(conf: Option<&str>, service: Option<bool>) -> Option<bool> {
    let Some(conf) = conf else {
        return service.filter(|active| !active);
    };
    let enabled = conf
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .rfind(|(k, _)| k.trim() == "ENABLED")
        .is_some_and(|(_, v)| v.trim().trim_matches('"').eq_ignore_ascii_case("yes"));
    if enabled { service } else { Some(false) }
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

/// Patch-age heuristic. Package history records neither the archive pocket nor
/// advisories, so a transaction counts as an OS update only when it was a
/// whole-system upgrade (`apt upgrade`, `dist-upgrade`, `full-upgrade`,
/// `unattended-upgrade`, with no package names) that upgraded something and
/// finished without an error. An application upgrade, a base package alone,
/// or an interrupted transaction never resets the age. Held-back and skipped
/// packages leave no trace in history, so `os_patch_age` also asks the package
/// manager for outstanding security updates and reports `unknown` when any
/// remain. Without a qualifying entry the age is unknown.
const APT_FULL_UPGRADE_VERBS: &[&str] =
    &["upgrade", "dist-upgrade", "full-upgrade", "safe-upgrade"];

fn is_apt_full_upgrade(commandline: &str) -> bool {
    let mut tokens = commandline.split_whitespace();
    let Some(program) = tokens.next().and_then(|t| t.rsplit('/').next()) else {
        return false;
    };
    if program.starts_with("unattended-upgrade") {
        return true;
    }
    if !matches!(program, "apt" | "apt-get" | "aptitude") {
        return false;
    }
    let args: Vec<&str> = tokens.filter(|t| !t.starts_with('-')).collect();
    matches!(args.as_slice(), [verb] if APT_FULL_UPGRADE_VERBS.contains(verb))
}

pub fn parse_apt_history(text: &str) -> Option<NaiveDate> {
    let mut full_upgrade = false;
    let mut upgraded = false;
    let mut failed = false;
    let mut latest = None;
    for line in text.lines() {
        if line.starts_with("Start-Date:") {
            (full_upgrade, upgraded, failed) = (false, false, false);
        } else if let Some(cmd) = line.strip_prefix("Commandline:") {
            full_upgrade = is_apt_full_upgrade(cmd);
        } else if line.starts_with("Upgrade:") {
            upgraded = true;
        } else if line.starts_with("Error:") {
            failed = true;
        } else if line.starts_with("End-Date:") && upgraded && full_upgrade && !failed {
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

/// A dnf transaction counts only when it upgrades the whole system: an upgrade
/// verb with no package-name filter and no flag that narrows the set, except
/// `--security`, which still covers every outstanding security update. Offline upgrades take a subcommand instead of packages. The history
/// column truncates long command lines, so a cut-off filter is not seen.
const DNF_SYSTEM_UPGRADE_COMMANDS: &[&str] = &["system-upgrade", "offline"];
const DNF_SUBSET_FLAGS: &[&str] = &[
    "--advisor",
    "--sec-severity",
    "--cve",
    "--bz",
    "--bugfix",
    "--enhancement",
    "--newpackage",
    "--exclude",
    "-x",
    "--skip-broken",
];

fn is_dnf_upgrade(command: &str) -> bool {
    let mut tokens = command
        .split(|c: char| c.is_whitespace() || c == '|')
        .filter(|t| !t.is_empty())
        .skip_while(|t| t.chars().all(|c| c.is_ascii_digit()))
        .filter(|t| !t.rsplit('/').next().is_some_and(is_dnf_program))
        .skip_while(|t| t.starts_with('-'));
    let Some(verb) = tokens.next() else {
        return false;
    };
    if !DNF_UPGRADE_COMMANDS.contains(&verb) {
        return false;
    }
    if DNF_SYSTEM_UPGRADE_COMMANDS.contains(&verb) {
        return true;
    }
    let rest: Vec<&str> = tokens.collect();
    rest.iter()
        .all(|t| t.starts_with('-') && !DNF_SUBSET_FLAGS.iter().any(|f| t.starts_with(f)))
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
ubuntu--vg-ubuntu--lv lvm  0 0 ext4  /
└─dm_crypt-0          crypt 0 0 crypto_LUKS
  └─nvme0n1p3         part 0 0
    └─nvme0n1         disk 0 0
nvme0n1p2             part 0 0 ext4 /boot
└─nvme0n1             disk 0 0
";
        assert_eq!(parse_lsblk_inverse(out), "full");
    }

    #[test]
    fn lsblk_raid1_with_one_encrypted_leg_is_partial() {
        let out = "\
md0 raid1 0 0 ext4 /
├─crypt-leg crypt 0 0
│ └─sda1 part 0 0
│   └─sda disk 0 0
└─sdb1 part 0 0
  └─sdb disk 0 0
";
        assert_eq!(parse_lsblk_inverse(out), "partial");
    }

    #[test]
    fn lsblk_raid1_encrypted_above_or_on_every_leg() {
        let above = "\
crypt-md crypt 0 0 ext4 /
└─md0 raid1 0 0
  ├─sda1 part 0 0
  │ └─sda disk 0 0
  └─sdb1 part 0 0
    └─sdb disk 0 0
";
        assert_eq!(parse_lsblk_inverse(above), "full");
        let legs = "\
md0 raid1 0 0 ext4 /
├─crypt-a crypt 0 0
│ └─sda1 part 0 0
│   └─sda disk 0 0
└─crypt-b crypt 0 0
  └─sdb1 part 0 0
    └─sdb disk 0 0
";
        assert_eq!(parse_lsblk_inverse(legs), "full");
    }

    #[test]
    fn lsblk_lvm_spanning_encrypted_and_plain_pv_is_partial() {
        let out = "\
vg-root lvm 0 0 ext4 /
├─crypt-pv1 crypt 0 0
│ └─sda2 part 0 0
│   └─sda disk 0 0
└─sdb2 part 0 0
  └─sdb disk 0 0
";
        assert_eq!(parse_lsblk_inverse(out), "partial");
    }

    #[test]
    fn lsblk_raid1_with_two_plain_legs_is_none_and_skipped_depth_is_unknown() {
        let plain = "\
md0 raid1 0 0 ext4 /
├─sda1 part 0 0
│ └─sda disk 0 0
└─sdb1 part 0 0
  └─sdb disk 0 0
";
        assert_eq!(parse_lsblk_inverse(plain), "none");
        let skipped = "\
md0 raid1 0 0 ext4 /
    └─sda1 part 0 0
";
        assert_eq!(parse_lsblk_inverse(skipped), "unknown");
    }

    #[test]
    fn lsblk_encrypted_root_but_plain_home_is_partial() {
        let out = "\
vg-root     lvm  0 0 ext4 /
└─luks-root crypt 0 0
  └─sda2    part 0 0
    └─sda   disk 0 0
sdb1        part 0 0 ext4 /home
└─sdb       disk 0 0
";
        assert_eq!(parse_lsblk_inverse(out), "partial");
    }

    #[test]
    fn lsblk_encrypted_root_and_home_is_full() {
        let out = "\
vg-root     lvm  0 0 ext4 /
└─luks-root crypt 0 0
  └─sda2    part 0 0
    └─sda   disk 0 0
luks-home   crypt 0 0 ext4 /home
└─sdb1      part 0 0
  └─sdb     disk 0 0
";
        assert_eq!(parse_lsblk_inverse(out), "full");
    }

    #[test]
    fn lsblk_plain_root() {
        let out = "\
nvme0n1p2 part 0 0 ext4 /
└─nvme0n1 disk 0 0
nvme0n1p1 part 0 0 vfat /boot/efi
└─nvme0n1 disk 0 0
";
        assert_eq!(parse_lsblk_inverse(out), "none");
    }

    #[test]
    fn lsblk_encrypted_data_but_plain_root() {
        let out = "\
nvme0n1p2 part 0 0 ext4 /
└─nvme0n1 disk 0 0
luks-data crypt 0 0 ext4 /home
└─sda1    part 0 0
  └─sda   disk 0 0
";
        assert_eq!(parse_lsblk_inverse(out), "partial");
    }

    #[test]
    fn lsblk_other_mounted_data_disk_counts() {
        let out = "\
luks-root crypt 0 0 ext4 /
└─sda2    part 0 0
  └─sda   disk 0 0
sdb1      part 0 0 xfs /srv/data
└─sdb     disk 0 0
";
        assert_eq!(parse_lsblk_inverse(out), "partial");
    }

    #[test]
    fn lsblk_plain_swap_partition_makes_encrypted_root_partial() {
        let out = "\
luks-root crypt 0 0 ext4 /
└─sda2    part 0 0
  └─sda   disk 0 0
sda3      part 0 0 swap [SWAP]
└─sda     disk 0 0
";
        assert_eq!(parse_lsblk_inverse(out), "partial");
    }

    #[test]
    fn lsblk_encrypted_swap_and_zram_swap_stay_full() {
        let out = "\
luks-root crypt 0 0 ext4 /
└─sda2    part 0 0
  └─sda   disk 0 0
cryptswap crypt 0 0 swap [SWAP]
└─sda3    part 0 0
  └─sda   disk 0 0
zram0     disk 0 0 swap [SWAP]
";
        assert_eq!(parse_lsblk_inverse(out), "full");
    }

    #[test]
    fn lsblk_ignores_removable_read_only_loop_and_unmounted_devices() {
        let out = "\
luks-root crypt 0 0 ext4 /
└─sda2    part 0 0
  └─sda   disk 0 0
sdc1      part 0 1 vfat /media/user/stick
└─sdc     disk 0 1
sr0       rom  0 0 iso9660 /media/user/disc
loop3     loop 1 0 squashfs /snap/example/1
sdd1      part 0 0 ext4
└─sdd     disk 0 0
sde1      part 1 0 ext4 /mnt/archive
└─sde     disk 1 0
";
        assert_eq!(parse_lsblk_inverse(out), "full");
    }

    #[test]
    fn lsblk_unreadable_row_is_unknown() {
        assert_eq!(parse_lsblk_inverse("sda1 part ? ? ext4 /\n"), "unknown");
    }

    #[test]
    fn lsblk_without_root_is_unknown() {
        assert_eq!(parse_lsblk_inverse(""), "unknown");
        assert_eq!(
            parse_lsblk_inverse("sda1 part 0 0 ext4 /data\n└─sda disk 0 0\n"),
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
    fn ufw_active_service_with_disabled_config_is_off() {
        let disabled = "# comment\nENABLED=no\nLOGLEVEL=low\n";
        assert_eq!(ufw_enabled(Some(disabled), Some(true)), Some(false));
        assert_eq!(
            merge_firewall(None, ufw_enabled(Some(disabled), Some(true))),
            "off"
        );
    }

    #[test]
    fn ufw_needs_enabled_config_and_active_service() {
        let enabled = "ENABLED=yes\n";
        assert_eq!(ufw_enabled(Some(enabled), Some(true)), Some(true));
        assert_eq!(ufw_enabled(Some("ENABLED=Yes"), Some(true)), Some(true));
        assert_eq!(ufw_enabled(Some(enabled), Some(false)), Some(false));
        assert_eq!(ufw_enabled(Some(enabled), None), None);
        assert_eq!(ufw_enabled(Some("#ENABLED=yes\n"), Some(true)), Some(false));
        assert_eq!(ufw_enabled(Some(""), Some(true)), Some(false));
        assert_eq!(ufw_enabled(None, Some(true)), None);
        assert_eq!(ufw_enabled(None, Some(false)), Some(false));
        assert_eq!(ufw_enabled(None, None), None);
    }

    #[test]
    fn firewalld_running_state_wins_over_disabled_ufw() {
        let ufw = ufw_enabled(Some("ENABLED=no\n"), Some(true));
        assert_eq!(merge_firewall(parse_firewall_cmd("running\n"), ufw), "on");
        assert_eq!(
            merge_firewall(parse_firewall_cmd("not running\n"), None),
            "off"
        );
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

    fn apt_entry(date: &str, cmd: &str, upgrade: &str) -> String {
        format!(
            "Start-Date: {date}  06:00:00\nCommandline: {cmd}\nUpgrade: {upgrade}\nEnd-Date: {date}  06:00:30\n\n"
        )
    }

    #[test]
    fn apt_single_application_upgrade_does_not_reset_patch_age() {
        let log = apt_entry("2026-09-01", "apt upgrade", "libc6:amd64 (2.39-1, 2.39-2)")
            + &apt_entry(
                "2026-10-11",
                "apt install --only-upgrade fictional-editor",
                "fictional-editor:amd64 (1.0, 1.1)",
            );
        assert_eq!(parse_apt_history(&log), Some(d(2026, 9, 1)));
        let only_app = apt_entry(
            "2026-10-11",
            "apt install fictional-editor",
            "fictional-editor:amd64 (1.0, 1.1)",
        );
        assert_eq!(parse_apt_history(&only_app), None);
        let named_upgrade = apt_entry(
            "2026-10-11",
            "apt upgrade fictional-editor",
            "fictional-editor:amd64 (1.0, 1.1)",
        );
        assert_eq!(parse_apt_history(&named_upgrade), None);
    }

    #[test]
    fn apt_whole_system_upgrades_count() {
        let pkg = "fictional-lib:amd64 (1.0, 1.1)";
        for cmd in [
            "apt upgrade",
            "apt-get -y dist-upgrade",
            "/usr/bin/apt full-upgrade",
            "/usr/bin/unattended-upgrade",
        ] {
            let log = apt_entry("2026-10-01", cmd, pkg);
            assert_eq!(parse_apt_history(&log), Some(d(2026, 10, 1)), "{cmd}");
        }
    }

    #[test]
    fn apt_base_package_alone_or_failed_transaction_is_not_an_os_update() {
        let base = apt_entry(
            "2026-10-02",
            "apt install --only-upgrade base-files",
            "base-files:amd64 (1, 2)",
        );
        assert_eq!(parse_apt_history(&base), None);
        let kernel = apt_entry(
            "2026-10-02",
            "aptdaemon role='role-commit-packages'",
            "linux-image-6.8.0-1-generic:amd64 (6.8.0-1, 6.8.0-2)",
        );
        assert_eq!(parse_apt_history(&kernel), None);
        let failed = apt_entry("2026-10-03", "apt upgrade", "fictional-lib:amd64 (1, 2)")
            .replace("End-Date", "Error: dpkg interrupted\nEnd-Date");
        assert_eq!(parse_apt_history(&failed), None);
    }

    #[test]
    fn apt_kept_back_or_pending_security_updates_are_detected() {
        let kept = "The following packages have been kept back:\n  fictional-lib\n";
        assert!(apt_security_pending(kept));
        let inst = "Inst fictional-lib [1.0] (1.1 Fictional:1/stable-security [amd64])\n";
        assert!(apt_security_pending(inst));
        let plain = "Inst fictional-editor [1] (2 Fictional:1/stable [amd64])\n0 upgraded\n";
        assert!(!apt_security_pending(plain));
        assert!(!apt_security_pending(""));
    }

    #[test]
    fn dnf_pending_security_advisories_are_detected() {
        let out = "FICTIONAL-2026-0001 Important/Sec. fictional-lib-1.1.x86_64\n";
        assert!(dnf_security_pending(out));
        assert!(!dnf_security_pending(""));
        assert!(!dnf_security_pending(
            "Last metadata expiration check: 1 day, 0:00:00 ago.\n"
        ));
    }

    #[test]
    fn apt_held_upgrade_with_no_upgraded_packages_is_ignored() {
        let held = "Start-Date: 2026-10-11  06:00:00\nCommandline: apt upgrade\nEnd-Date: 2026-10-11  06:00:30\n";
        assert_eq!(parse_apt_history(held), None);
    }

    #[test]
    fn dnf_package_filtered_upgrade_does_not_reset_patch_age() {
        let out = "\
ID Command line                         Date and time       Action(s) Altered
 9 dnf upgrade fictional-editor         2026-10-11 09:00:00                 1
 8 dnf update -y fictional-editor       2026-10-10 09:00:00                 1
 7 dnf -y upgrade --refresh             2026-09-01 05:47:37                46
";
        assert_eq!(parse_dnf_history(out), Some(d(2026, 9, 1)));
        let security = " 9 dnf upgrade --security fictional-editor 2026-10-11 09:00:00 1\n";
        assert_eq!(parse_dnf_history(security), None);
        let bare_security = " 9 dnf upgrade --security 2026-10-11 09:00:00 1\n";
        assert_eq!(parse_dnf_history(bare_security), Some(d(2026, 10, 11)));
        let severity = " 9 dnf upgrade --sec-severity=Critical 2026-10-11 09:00:00 1\n";
        assert_eq!(parse_dnf_history(severity), None);
        let excluded = " 9 dnf upgrade --exclude=fictional-lib 2026-10-11 09:00:00 1\n";
        assert_eq!(parse_dnf_history(excluded), None);
        let only_filtered = " 9 dnf upgrade fictional-editor 2026-10-11 09:00:00 1\n";
        assert_eq!(parse_dnf_history(only_filtered), None);
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
        let rotated = "Start-Date: 2026-09-20  06:25:01\nCommandline: apt upgrade\nUpgrade: libc6:amd64 (2.39-1, 2.39-2)\nEnd-Date: 2026-09-20  06:25:30\n";
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
vg--root-lv  lvm   0 0 ext4 /
`-luks-0     crypt 0 0
  `-vda3     part  0 0
    `-vda    disk  0 0
vda2         part  0 0 ext4 /boot
`-vda        disk  0 0
";
        assert_eq!(parse_lsblk_inverse(out), "full");
    }
}
