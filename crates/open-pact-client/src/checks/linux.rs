use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;

use chrono::{DateTime, Duration, NaiveDate, Utc};

use super::buckets;
use super::exec::{Ran, run, run_status};

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
/// Security lists older than this may lack an update the archive has published since (R4-M1).
const APT_SECURITY_LISTS_MAX_AGE: Duration = Duration::days(7);
/// The plain name and the compressed forms APT may keep a downloaded index in.
const APT_INDEX_SUFFIXES: &[&str] = &["", ".lz4", ".zst", ".gz", ".xz", ".bz2", ".lzma"];
const APT_HELPER: &str = "/usr/lib/apt/apt-helper";

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

/// The files and commands the patch-age check reads, so tests can supply them.
trait PackageHost {
    fn read(&self, path: &str) -> Option<String>;
    fn run(&self, program: &str, args: &[&str]) -> Option<Ran>;
    /// The paths of the entries in a directory.
    fn list(&self, dir: &str) -> Option<Vec<String>>;
    /// The size and `hash` of a file's bytes, or with `decode` of the content APT reads from
    /// it after decompression. `None` when the file cannot be read or decoded in time.
    fn digest(&self, path: &str, decode: bool, hash: Hash) -> Option<IndexDigest>;
    /// What identifies one version of a file without reading it: its inode, size and change
    /// times. A directory's stamp does not vary. `None` when the file cannot be examined.
    fn stamp(&self, path: &str) -> Option<String>;
}

/// The checksum sections of a Release this check can verify, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
enum Hash {
    Sha256,
    Sha512,
}

impl Hash {
    const ALL: [Hash; 2] = [Hash::Sha256, Hash::Sha512];

    fn section(self) -> &'static str {
        match self {
            Hash::Sha256 => "SHA256:",
            Hash::Sha512 => "SHA512:",
        }
    }
}

/// An index's size and lowercase hex digest, as a Release lists it.
#[derive(Debug, PartialEq)]
struct IndexDigest {
    size: u64,
    hash: String,
}

struct System;

impl PackageHost for System {
    fn read(&self, path: &str) -> Option<String> {
        fs::read_to_string(path).ok()
    }

    fn run(&self, program: &str, args: &[&str]) -> Option<Ran> {
        run_status(program, args)
    }

    fn list(&self, dir: &str) -> Option<Vec<String>> {
        let entries = fs::read_dir(dir).ok()?;
        entries
            .map(|e| Some(e.ok()?.path().to_str()?.to_string()))
            .collect()
    }

    fn digest(&self, path: &str, decode: bool, hash: Hash) -> Option<IndexDigest> {
        if !decode {
            return hash_stream(fs::File::open(path).ok()?, hash);
        }
        // `apt-helper cat-file` decodes every compression APT stores lists in.
        let mut child = std::process::Command::new(APT_HELPER)
            .args(["cat-file", path])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let stdout = child.stdout.take()?;
        let hasher = std::thread::spawn(move || hash_stream(stdout, hash));
        let deadline = std::time::Instant::now() + super::exec::TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        };
        let digest = hasher.join().ok()?;
        digest.filter(|_| status.success())
    }

    fn stamp(&self, path: &str) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(path).ok()?;
        if meta.is_dir() {
            return Some("directory".into());
        }
        Some(format!(
            "{}:{} {} {}.{} {}.{}",
            meta.dev(),
            meta.ino(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec()
        ))
    }
}

fn hash_stream(input: impl Read, hash: Hash) -> Option<IndexDigest> {
    match hash {
        Hash::Sha256 => hash_with::<sha2::Sha256>(input),
        Hash::Sha512 => hash_with::<sha2::Sha512>(input),
    }
}

fn hash_with<D: sha2::Digest>(mut input: impl Read) -> Option<IndexDigest> {
    let mut hasher = D::new();
    let mut size = 0u64;
    let mut chunk = vec![0u8; 1 << 16];
    loop {
        match input.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&chunk[..n]);
                size += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(IndexDigest {
        size,
        hash: hex::encode(hasher.finalize()),
    })
}

pub fn os_patch_age() -> &'static str {
    patch_age(&System, Utc::now())
}

/// What the package manager says about outstanding security updates. Only `Clear` lets the date
/// of the last whole-system upgrade stand for the patch age (R3-M1).
#[derive(Debug, PartialEq)]
enum SecurityUpdates {
    Clear,
    Pending,
    Unknown,
}

/// The age of the last whole-system upgrade, or `unknown` unless the security query ran, exited
/// zero and showed nothing outstanding.
fn patch_age(host: &(impl PackageHost + Sync), now: DateTime<Utc>) -> &'static str {
    let (last, updates) = match host.read(APT_HISTORY) {
        Some(text) => (
            first_upgrade_date(
                std::iter::once(text)
                    .chain((1..=APT_ROTATED_LOGS).filter_map(|n| read_rotated_apt_log(host, n))),
            ),
            apt_security_updates(host, now),
        ),
        None => (
            succeeded(host.run("dnf", &["history", "list"]))
                .and_then(|out| parse_dnf_history(&out)),
            succeeded(host.run("dnf", &["-C", "-q", "updateinfo", "list", "--security"]))
                .map_or(SecurityUpdates::Unknown, |out| parse_dnf_security(&out)),
        ),
    };
    match (updates, last) {
        (SecurityUpdates::Clear, Some(date)) => buckets::patch_age(date, now.date_naive()),
        _ => "unknown",
    }
}

fn succeeded(ran: Option<Ran>) -> Option<String> {
    ran.filter(|r| r.success).map(|r| r.text)
}

/// The parser reads apt's English messages, so the query runs in the C locale.
/// `apt-get -s upgrade` compares the installed packages with the downloaded lists only, so
/// without current security lists it reports no upgrades while some are outstanding.
/// Each APT command loads every cached index, so the simulation runs while the cache is being
/// verified to stay within the check budget. Both must describe one cache generation (R7-M1):
/// the lists are stamped before the simulation starts and again after both finish, and any
/// change, such as an `apt update` landing in between, makes the result unknown.
fn apt_security_updates(host: &(impl PackageHost + Sync), now: DateTime<Utc>) -> SecurityUpdates {
    let Some(config) = AptConfig::read(host) else {
        return SecurityUpdates::Unknown;
    };
    let before = cache_generation(host, &config);
    let query = [
        "LC_ALL=C",
        "apt-get",
        "-s",
        "-o",
        "Debug::NoLocking=1",
        "upgrade",
    ];
    let (current, simulated) = std::thread::scope(|s| {
        let simulation = s.spawn(|| succeeded(host.run("env", &query)));
        let current = apt_security_lists_current(host, &config, now);
        (current, simulation.join().ok().flatten())
    });
    let unchanged = before.is_some() && before == cache_generation(host, &config);
    match simulated {
        Some(out) if current && unchanged => parse_apt_security(&out),
        _ => SecurityUpdates::Unknown,
    }
}

/// The architectures dpkg installs packages for and the indexes APT is configured to download.
struct AptConfig {
    architectures: BTreeSet<String>,
    targets: Vec<IndexTarget>,
}

impl AptConfig {
    fn read(host: &impl PackageHost) -> Option<AptConfig> {
        let native = succeeded(host.run("dpkg", &["--print-architecture"]))?;
        let foreign = succeeded(host.run("dpkg", &["--print-foreign-architectures"]))?;
        let targets = succeeded(host.run("apt-get", &["indextargets", "--no-release-info"]))
            .and_then(|out| parse_index_targets(&out))?;
        Some(AptConfig {
            architectures: native
                .split_whitespace()
                .chain(foreign.split_whitespace())
                .map(str::to_string)
                .collect(),
            targets,
        })
    }

    /// The directories APT keeps the configured indexes and their Releases in.
    fn dirs(&self) -> BTreeSet<&str> {
        self.targets
            .iter()
            .filter_map(|t| t.filename.rsplit_once('/').map(|(dir, _)| dir))
            .collect()
    }
}

/// One version of the package lists: the stamp of every entry in the list directories, and the
/// SHA-256 of every Release among them. Re-hashing every index would double the check's cost;
/// a rewritten or replaced index gets a new stamp. `None` when an entry cannot be examined.
fn cache_generation(
    host: &impl PackageHost,
    config: &AptConfig,
) -> Option<BTreeMap<String, String>> {
    let mut generation = BTreeMap::new();
    for dir in config.dirs() {
        for path in host.list(dir)? {
            let mut stamp = host.stamp(&path)?;
            if path.ends_with("Release") {
                let release = host.read(&path)?;
                stamp += &hash_stream(release.as_bytes(), Hash::Sha256)?.hash;
            }
            generation.insert(path, stamp);
        }
    }
    Some(generation)
}

/// One index file APT is configured to download, as `apt-get indextargets` describes it.
struct IndexTarget {
    /// The index's path below the source's Release, such as `main/binary-amd64/Packages`.
    meta_key: String,
    /// Where APT keeps the download, before any compression suffix.
    filename: String,
    /// A `deb` Packages index, which the upgrade simulation reads.
    packages: bool,
    /// Absent for a flat repository, whose single index serves every architecture.
    architecture: Option<String>,
}

impl IndexTarget {
    /// The path of the source's Release without its `Release` or `InRelease` name. APT names
    /// each download after its URI, and the index URI is the Release directory plus the meta
    /// key, so the meta key, escaped the same way, ends the file name.
    fn release_prefix(&self) -> Option<&str> {
        self.filename.strip_suffix(&apt_file_name(&self.meta_key))
    }
}

/// Escapes a URI path as APT's `URItoFileName` does: special and non-printable bytes become
/// `%xx`, then `/` becomes `_`.
fn apt_file_name(uri: &str) -> String {
    uri.bytes()
        .map(|b| match b {
            b'/' => "_".to_string(),
            b'\\' | b'|' | b'{' | b'}' | b'[' | b']' | b'<' | b'>' | b'"' | b'^' | b'~' | b'_'
            | b'=' | b'!' | b'@' | b'#' | b'$' | b'%' | b'&' | b'*' => format!("%{b:02x}"),
            b if b <= 0x20 || b >= 0x7f => format!("%{b:02x}"),
            b => char::from(b).to_string(),
        })
        .collect()
}

/// Reads the deb822 records of `apt-get indextargets --no-release-info`, which lists every
/// configured index whether or not it was downloaded. A record without a meta key or file name
/// makes the whole list unreadable.
fn parse_index_targets(out: &str) -> Option<Vec<IndexTarget>> {
    out.split("\n\n")
        .filter(|record| !record.trim().is_empty())
        .map(|record| {
            let field = |name: &str| release_field(record, name).map(str::to_string);
            Some(IndexTarget {
                meta_key: field("MetaKey")?,
                filename: field("Filename")?,
                packages: field("Target-Of").as_deref() == Some("deb")
                    && field("Identifier").as_deref() == Some("Packages"),
                architecture: field("Architecture"),
            })
        })
        .collect()
}

/// The lines of one checksum section of a Release, such as `SHA256:`. The other sections and
/// the signature that follows are not part of it.
fn release_section<'a>(release: &'a str, header: &str) -> impl Iterator<Item = &'a str> {
    release
        .lines()
        .skip_while(move |l| l.trim_end() != header)
        .skip(1)
        .take_while(|l| l.starts_with(' '))
}

/// The index files the strongest checksum section of a Release lists, by name, and that
/// section's hash (R7-L3). APT also verifies a download with the strongest hash it knows.
fn release_indexes(release: &str) -> (Hash, BTreeMap<&str, IndexDigest>) {
    let section = |hash: Hash| -> BTreeMap<&str, IndexDigest> {
        release_section(release, hash.section())
            .filter_map(|l| match l.split_whitespace().collect::<Vec<_>>()[..] {
                [digest, size, name] => Some((
                    name,
                    IndexDigest {
                        size: size.parse().ok()?,
                        hash: digest.to_ascii_lowercase(),
                    },
                )),
                _ => None,
            })
            .collect()
    };
    Hash::ALL
        .into_iter()
        .rev()
        .map(|hash| (hash, section(hash)))
        .find(|(_, listed)| !listed.is_empty())
        .unwrap_or((Hash::Sha256, BTreeMap::new()))
}

/// Every index name a Release lists in any checksum section, usable by this check or not.
fn release_names(release: &str) -> BTreeSet<&str> {
    ["MD5Sum:", "SHA1:", "SHA256:", "SHA512:"]
        .into_iter()
        .flat_map(|header| release_section(release, header))
        .filter_map(|l| l.split_whitespace().nth(2))
        .collect()
}

/// Whether the APT cache provably holds what the archive published (R4-M1, R5-M1, R6-M1,
/// R6-M2). The upgrade simulation reads the cached Packages indexes without checking them, so
/// a missing, truncated or older index hides updates. The check therefore needs:
///
/// - a readable Release for every configured source, and no Release APT is not configured
///   for, since without one nothing tells whether it is a security source;
/// - at least one security source (`Suite` or `Codename` ending in `-security`), each published
///   within the last week, before its `Valid-Until`, and listing a Packages index for the
///   native architecture and for every foreign architecture dpkg installs packages for;
/// - for every source, each Packages index APT would read (native, foreign or `all`
///   architecture, listed in the Release or cached) cached with exactly the size and digest
///   the Release's strongest checksum section (SHA512, else SHA256) lists for it, so an index
///   listed without a usable hash fails (R7-L3). A stored form matches its own entry, or its
///   decoded content matches the uncompressed entry. Only an index the Release lists as empty
///   may be absent, because APT does not store it.
///
/// Anything else, including a date that does not parse, means the cache is not proven.
fn apt_security_lists_current(
    host: &impl PackageHost,
    config: &AptConfig,
    now: DateTime<Utc>,
) -> bool {
    let AptConfig {
        architectures,
        targets,
    } = config;
    let mut sources: BTreeMap<&str, Vec<&IndexTarget>> = BTreeMap::new();
    for target in targets {
        match target.release_prefix() {
            Some(prefix) => sources.entry(prefix).or_default().push(target),
            None if target.packages => return false,
            None => {}
        }
    }
    let configured: BTreeSet<String> = sources
        .keys()
        .flat_map(|prefix| [format!("{prefix}InRelease"), format!("{prefix}Release")])
        .collect();
    let mut cached = BTreeSet::new();
    for dir in config.dirs() {
        let Some(entries) = host.list(dir) else {
            return false;
        };
        if entries
            .iter()
            .any(|path| path.ends_with("Release") && !configured.contains(path))
        {
            return false;
        }
        cached.extend(entries);
    }
    let mut security = 0;
    for (prefix, targets) in &sources {
        let Some(release) = host
            .read(&format!("{prefix}InRelease"))
            .or_else(|| host.read(&format!("{prefix}Release")))
        else {
            return false;
        };
        let (hash, listed) = release_indexes(&release);
        let named = release_names(&release);
        let arch_all_unused = release_field(&release, "No-Support-for-Architecture-all")
            .is_some_and(|v| v.split_whitespace().any(|w| w == "Packages"));
        let used: Vec<&IndexTarget> = targets
            .iter()
            .copied()
            .filter(|t| t.packages)
            .filter(|t| match t.architecture.as_deref() {
                None => true,
                Some("all") => !arch_all_unused,
                Some(arch) => architectures.contains(arch),
            })
            .filter(|t| {
                APT_INDEX_SUFFIXES.iter().any(|suffix| {
                    named.contains(format!("{}{suffix}", t.meta_key).as_str())
                        || cached.contains(&format!("{}{suffix}", t.filename))
                })
            })
            .collect();
        if !used
            .iter()
            .all(|t| index_matches(host, t, hash, &listed, &cached))
        {
            return false;
        }
        let is_security = ["Suite", "Codename"]
            .iter()
            .filter_map(|name| release_field(&release, name))
            .any(|suite| suite.ends_with("-security"));
        if !is_security {
            continue;
        }
        security += 1;
        let flat = used.iter().any(|t| t.architecture.is_none());
        let covered =
            |arch: &String| flat || used.iter().any(|t| t.architecture.as_ref() == Some(arch));
        if !release_current(&release, now) || !architectures.iter().all(covered) {
            return false;
        }
    }
    security > 0
}

/// Whether every cached form of one index matches the Release, and at least one exists unless
/// the Release lists the index as empty.
fn index_matches(
    host: &impl PackageHost,
    target: &IndexTarget,
    hash: Hash,
    listed: &BTreeMap<&str, IndexDigest>,
    cached: &BTreeSet<String>,
) -> bool {
    let plain = listed.get(target.meta_key.as_str());
    let stored: Vec<&str> = APT_INDEX_SUFFIXES
        .iter()
        .copied()
        .filter(|suffix| cached.contains(&format!("{}{suffix}", target.filename)))
        .collect();
    if stored.is_empty() {
        return plain.is_some_and(|d| d.size == 0);
    }
    stored.iter().all(|suffix| {
        let path = format!("{}{suffix}", target.filename);
        let as_stored = listed.get(format!("{}{suffix}", target.meta_key).as_str());
        as_stored.is_some_and(|want| host.digest(&path, false, hash).as_ref() == Some(want))
            || (!suffix.is_empty()
                && plain.is_some_and(|want| host.digest(&path, true, hash).as_ref() == Some(want)))
    })
}

/// Whether a Release was published within the last week and has not passed its `Valid-Until`.
fn release_current(release: &str, now: DateTime<Utc>) -> bool {
    let published = release_field(release, "Date").and_then(parse_release_date);
    let expired = release_field(release, "Valid-Until")
        .map(|until| parse_release_date(until).is_none_or(|until| until <= now));
    published.is_some_and(|date| now - date <= APT_SECURITY_LISTS_MAX_AGE) && expired != Some(true)
}

fn release_field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
        .map(str::trim)
}

/// Reads a Release date such as `Mon, 12 Oct 2026  1:43:41 UTC`: APT pads a one-digit hour
/// with a space and writes the zone as `UTC`, `GMT` or a numeric offset.
fn parse_release_date(text: &str) -> Option<DateTime<Utc>> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let [.., day, month, year, time, zone] = words[..] else {
        return None;
    };
    let zone = match zone {
        "UTC" | "GMT" | "UT" | "Z" => "+0000",
        offset => offset,
    };
    DateTime::parse_from_str(
        &format!("{day} {month} {year} {time} {zone}"),
        "%d %b %Y %H:%M:%S %z",
    )
    .ok()
    .map(|t| t.with_timezone(&Utc))
}

/// Reads `apt-get -s upgrade`. Any `Inst` line or kept-back package is an outstanding update:
/// APT names only the candidate's pocket, so a security fix superseded by a newer `-updates`
/// version would not show "security". Output is understood only if it ends in the
/// `N upgraded, N newly installed` summary.
fn parse_apt_security(out: &str) -> SecurityUpdates {
    if out
        .lines()
        .any(|l| l.starts_with("Inst ") || l.contains("have been kept back"))
    {
        SecurityUpdates::Pending
    } else if out
        .lines()
        .any(|l| l.contains(" upgraded, ") && l.contains(" newly installed"))
    {
        SecurityUpdates::Clear
    } else {
        SecurityUpdates::Unknown
    }
}

/// Reads `dnf -q updateinfo list --security`. Each advisory is one line that starts with an id
/// such as `FICTIONAL-2026-0001`. Output with no advisory is understood only if it is empty.
fn parse_dnf_security(out: &str) -> SecurityUpdates {
    let advisory = |l: &str| {
        let mut t = l.split_whitespace();
        let id = t.next().unwrap_or("");
        t.count() >= 2
            && id.contains('-')
            && id.chars().any(|c| c.is_ascii_digit())
            && id.chars().next().is_some_and(|c| c.is_ascii_uppercase())
    };
    if out.lines().any(advisory) {
        SecurityUpdates::Pending
    } else if out.trim().is_empty() {
        SecurityUpdates::Clear
    } else {
        SecurityUpdates::Unknown
    }
}

fn read_rotated_apt_log(host: &impl PackageHost, n: u32) -> Option<String> {
    let path = format!("{APT_HISTORY}.{n}");
    host.read(&path).or_else(|| {
        host.run("gzip", &["-dc", &format!("{path}.gz")])
            .map(|r| r.text)
    })
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

/// Subset flags count on both sides of the verb: `dnf --exclude=x upgrade` narrows the set too.
fn is_dnf_upgrade(command: &str) -> bool {
    let tokens: Vec<&str> = command
        .split(|c: char| c.is_whitespace() || c == '|')
        .filter(|t| !t.is_empty())
        .skip_while(|t| t.chars().all(|c| c.is_ascii_digit()))
        .filter(|t| !t.rsplit('/').next().is_some_and(is_dnf_program))
        .collect();
    let Some(at) = tokens.iter().position(|t| !t.starts_with('-')) else {
        return false;
    };
    let (before, verb, after) = (&tokens[..at], tokens[at], &tokens[at + 1..]);
    let narrows = |t: &&str| DNF_SUBSET_FLAGS.iter().any(|f| t.starts_with(f));
    if !DNF_UPGRADE_COMMANDS.contains(&verb) || before.iter().any(narrows) {
        return false;
    }
    DNF_SYSTEM_UPGRADE_COMMANDS.contains(&verb)
        || after.iter().all(|t| t.starts_with('-') && !narrows(t))
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
        use SecurityUpdates::*;
        let kept = "The following packages have been kept back:\n  fictional-lib\n";
        assert_eq!(parse_apt_security(kept), Pending);
        let inst = "Inst fictional-lib [1.0] (1.1 Fictional:1/stable-security [amd64])\n";
        assert_eq!(parse_apt_security(inst), Pending);
        let superseded = "Inst fictional-lib [1.0] (1.2 Fictional:1/stable-updates [amd64])\n\
            1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n";
        assert_eq!(parse_apt_security(superseded), Pending);
        let none = "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n";
        assert_eq!(parse_apt_security(none), Clear);
        assert_eq!(parse_apt_security(""), Unknown);
    }

    #[test]
    fn dnf_pending_security_advisories_are_detected() {
        use SecurityUpdates::*;
        let out = "FICTIONAL-2026-0001 Important/Sec. fictional-lib-1.1.x86_64\n";
        assert_eq!(parse_dnf_security(out), Pending);
        assert_eq!(parse_dnf_security(""), Clear);
        assert_eq!(
            parse_dnf_security("Last metadata expiration check: 1 day, 0:00:00 ago.\n"),
            Unknown
        );
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

    struct FakeHost {
        files: BTreeMap<String, String>,
        commands: Vec<(&'static str, Option<(bool, String)>)>,
    }

    impl PackageHost for FakeHost {
        fn read(&self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }

        fn run(&self, program: &str, args: &[&str]) -> Option<Ran> {
            let line = format!("{program} {}", args.join(" "));
            let (_, out) = self.commands.iter().find(|(c, _)| *c == line)?;
            out.clone().map(|(success, text)| Ran { success, text })
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            let prefix = format!("{dir}/");
            Some(
                self.files
                    .keys()
                    .filter(|p| p.strip_prefix(&prefix).is_some_and(|n| !n.contains('/')))
                    .cloned()
                    .collect(),
            )
        }

        /// A fake index decodes to its own text, whatever its suffix.
        fn digest(&self, path: &str, _decode: bool, hash: Hash) -> Option<IndexDigest> {
            hash_stream(self.files.get(path)?.as_bytes(), hash)
        }

        /// A fake file is rewritten whenever its text changes.
        fn stamp(&self, path: &str) -> Option<String> {
            Some(hash_stream(self.files.get(path)?.as_bytes(), Hash::Sha256)?.hash)
        }
    }

    impl FakeHost {
        fn with(mut self, path: &str, text: &str) -> FakeHost {
            self.files.insert(path.to_string(), text.to_string());
            self
        }

        fn without(mut self, path: &str) -> FakeHost {
            assert!(self.files.remove(path).is_some(), "{path} was not there");
            self
        }

        /// Replaces what `command` prints; `None` stands for a command that did not finish.
        fn answer(mut self, command: &str, out: Option<(bool, &str)>) -> FakeHost {
            let (_, old) = self
                .commands
                .iter_mut()
                .find(|(c, _)| *c == command)
                .unwrap();
            *old = owned(out);
            self
        }

        /// Adds a configured source that has no Release and no index downloaded.
        fn configure(self, suite: &str) -> FakeHost {
            let targets = self
                .run("apt-get", &["indextargets", "--no-release-info"])
                .unwrap();
            let targets = targets.text + &index_target(suite);
            self.answer(INDEX_TARGETS, Some((true, &targets)))
        }
    }

    const APT_QUERY: &str = "env LC_ALL=C apt-get -s -o Debug::NoLocking=1 upgrade";
    const INDEX_TARGETS: &str = "apt-get indextargets --no-release-info";
    const ARCH: &str = "dpkg --print-architecture";
    const FOREIGN_ARCHS: &str = "dpkg --print-foreign-architectures";
    const LISTS: &str = "/var/lib/apt/lists";
    const APT_CLEAR: &str = "Reading package lists...\nCalculating upgrade...\n\
        0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n";
    const DNF_HISTORY: &str = "dnf history list";
    const DNF_QUERY: &str = "dnf -C -q updateinfo list --security";

    /// The security suite's Release header as Ubuntu writes it, published the day before `now()`.
    const SECURITY_LISTS: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n\
        Origin: Fictional\nSuite: fictional-security\nCodename: fictional\n\
        Date: Sun, 11 Oct 2026  2:34:10 UTC\n";
    /// A release pocket: published once and never again, so its date says nothing.
    const RELEASE_POCKET: &str = "Origin: Fictional\nSuite: fictional\nCodename: fictional\n\
        Date: Thu, 25 Apr 2024 15:10:33 UTC\n";

    fn now() -> DateTime<Utc> {
        d(2026, 10, 12).and_hms_opt(12, 0, 0).unwrap().and_utc()
    }

    /// The file-name prefix APT gives to everything it downloads for a fictional `suite`.
    fn source(suite: &str) -> String {
        format!("{LISTS}/archive.example.invalid_debian_dists_{suite}_")
    }

    /// The amd64 Packages index of `suite`, where APT keeps it compressed.
    fn packages(suite: &str) -> String {
        format!("{}main_binary-amd64_Packages.lz4", source(suite))
    }

    /// The `indextargets` records of a configured `suite`: its amd64 and i386 Packages and a
    /// translation whose name APT escapes.
    fn index_target(suite: &str) -> String {
        let prefix = source(suite);
        format!(
            "MetaKey: main/binary-amd64/Packages\nFilename: {prefix}main_binary-amd64_Packages\n\
             Target-Of: deb\nIdentifier: Packages\nArchitecture: amd64\n\n\
             MetaKey: main/binary-i386/Packages\nFilename: {prefix}main_binary-i386_Packages\n\
             Target-Of: deb\nIdentifier: Packages\nArchitecture: i386\n\n\
             MetaKey: main/i18n/Translation-en_GB\nFilename: {prefix}main_i18n_Translation-en%5fGB\n\
             Target-Of: deb\nIdentifier: Translations\n\n"
        )
    }

    /// The content of every downloaded fictional Packages index.
    const INDEX: &str = "Package: fictional-lib\nVersion: 1.1\nArchitecture: amd64\n\n";

    /// One SHA256 line of a Release: the hash and size of `content`, listed under `name`.
    fn entry(name: &str, content: &str) -> String {
        let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(content.as_bytes()));
        format!(" {sha} {} {name}\n", content.len())
    }

    /// A Release header followed by the index list APT checks downloads against: the amd64 and
    /// i386 Packages with the content of `INDEX`, and an xz form with a hash nothing matches.
    fn listing(header: &str) -> String {
        format!(
            "{header}MD5Sum:\n 0d 99 main/binary-amd64/Packages\nSHA256:\n{}{} 0e 321 main/binary-amd64/Packages.xz\n",
            entry("main/binary-amd64/Packages", INDEX),
            entry("main/binary-i386/Packages", INDEX),
        )
    }

    /// A host with one configured source per Release header, each downloaded completely.
    fn apt_host(lists: &[&str], query: Option<(bool, &str)>) -> FakeHost {
        let mut host = FakeHost {
            files: BTreeMap::from([(
                APT_HISTORY.to_string(),
                apt_entry(
                    "2026-10-11",
                    "apt upgrade",
                    "fictional-lib:amd64 (1.0, 1.1)",
                ),
            )]),
            commands: vec![
                (APT_QUERY, owned(query)),
                (ARCH, Some((true, "amd64\n".to_string()))),
                (FOREIGN_ARCHS, Some((true, String::new()))),
                (INDEX_TARGETS, Some((true, String::new()))),
            ],
        };
        for (n, header) in lists.iter().enumerate() {
            let suite = format!("suite{n}");
            host = host
                .configure(&suite)
                .with(&format!("{}InRelease", source(&suite)), &listing(header))
                .with(&packages(&suite), INDEX);
        }
        host
    }

    fn dnf_host(history: Option<(bool, &str)>, query: Option<(bool, &str)>) -> FakeHost {
        FakeHost {
            files: BTreeMap::new(),
            commands: vec![(DNF_HISTORY, owned(history)), (DNF_QUERY, owned(query))],
        }
    }

    fn owned(out: Option<(bool, &str)>) -> Option<(bool, String)> {
        out.map(|(success, text)| (success, text.to_string()))
    }

    const DNF_UPGRADED: &str = "\
ID Command line                          Date and time       Action(s) Altered
 3 dnf -y upgrade --refresh              2026-10-11 15:52:37                46
";

    /// R3-M1: only a query that ran and was understood can show that no security update is
    /// outstanding. Anything else leaves the patch age unknown.
    #[test]
    fn apt_patch_age_needs_a_readable_security_query() {
        let today = now();
        assert_eq!(
            patch_age(
                &apt_host(&[SECURITY_LISTS, RELEASE_POCKET], Some((true, APT_CLEAR))),
                today
            ),
            "le_14d"
        );
        for (what, host) in [
            (
                "pending",
                apt_host(
                    &[SECURITY_LISTS, RELEASE_POCKET],
                    Some((
                        true,
                        "Inst fictional-lib [1.0] (1.1 Fictional:1/stable-security [amd64])\n",
                    )),
                ),
            ),
            (
                "failed",
                apt_host(
                    &[SECURITY_LISTS, RELEASE_POCKET],
                    Some((false, "E: Could not open lock file /var/lib/dpkg/lock\n")),
                ),
            ),
            (
                "timed out",
                apt_host(&[SECURITY_LISTS, RELEASE_POCKET], None),
            ),
            (
                "unrecognized",
                apt_host(
                    &[SECURITY_LISTS, RELEASE_POCKET],
                    Some((true, "FICTIONAL unexpected output\n")),
                ),
            ),
            ("no package lists", apt_host(&[], Some((true, APT_CLEAR)))),
        ] {
            assert_eq!(patch_age(&host, today), "unknown", "{what}");
        }
    }

    /// R4-M1: with old or expired security lists, an empty simulation proves nothing. The
    /// archive may hold a security update the lists do not show yet.
    #[test]
    fn apt_patch_age_needs_current_security_lists() {
        let clear = Some((true, APT_CLEAR));
        let debian = "Origin: Fictional\nSuite: stable-security\nCodename: fictional-security\n\
            Date: Mon, 12 Oct 2026 06:00:00 +0000\nValid-Until: Mon, 19 Oct 2026 06:00:00 +0000\n";
        assert_eq!(patch_age(&apt_host(&[debian], clear), now()), "le_14d");
        let security =
            |date: &str, until: &str| format!("Suite: fictional-security\nDate: {date}\n{until}");
        for (what, lists) in [
            (
                "expired",
                security(
                    "Sat, 01 Jan 2000 00:00:00 +0000",
                    "Valid-Until: Sun, 02 Jan 2000 00:00:00 +0000\n",
                ),
            ),
            (
                "past Valid-Until",
                security(
                    "Mon, 12 Oct 2026 06:00:00 +0000",
                    "Valid-Until: Mon, 12 Oct 2026 07:00:00 +0000\n",
                ),
            ),
            (
                "older than a week",
                security("Sat, 03 Oct 2026 12:00:00 UTC", ""),
            ),
            ("unreadable date", security("FICTIONAL", "")),
            (
                "unreadable Valid-Until",
                security(
                    "Mon, 12 Oct 2026 06:00:00 +0000",
                    "Valid-Until: FICTIONAL\n",
                ),
            ),
            ("no security suite", RELEASE_POCKET.to_string()),
        ] {
            let host = apt_host(&[RELEASE_POCKET, &lists], clear);
            assert_eq!(patch_age(&host, now()), "unknown", "{what}");
        }
        let one_stale = apt_host(
            &[
                SECURITY_LISTS,
                &security("Sat, 03 Oct 2026 12:00:00 UTC", ""),
            ],
            clear,
        );
        assert_eq!(patch_age(&one_stale, now()), "unknown", "one stale suite");
    }

    /// R5-M1: a clear simulation counts only when the downloaded lists cover every configured
    /// source and every Packages index of each security source.
    #[test]
    fn apt_patch_age_needs_every_security_index() {
        let clear = Some((true, APT_CLEAR));
        let complete = || apt_host(&[SECURITY_LISTS, RELEASE_POCKET], clear);
        assert_eq!(patch_age(&complete(), now()), "le_14d", "complete");
        let flat = apt_host(&[], clear)
            .answer(
                INDEX_TARGETS,
                Some((
                    true,
                    "MetaKey: Packages\nFilename: /var/lib/apt/lists/_tmp_fictional-archive_._Packages\n\
                     Target-Of: deb\nIdentifier: Packages\n\n",
                )),
            )
            .with(
                "/var/lib/apt/lists/_tmp_fictional-archive_._Release",
                &format!("{SECURITY_LISTS}SHA256:\n{}", entry("Packages", INDEX)),
            )
            .with("/var/lib/apt/lists/_tmp_fictional-archive_._Packages", INDEX);
        assert_eq!(patch_age(&flat, now()), "le_14d", "flat repository");
        let empty = complete().without(&packages("suite0")).with(
            &format!("{}InRelease", source("suite0")),
            &format!(
                "{SECURITY_LISTS}SHA256:\n{}",
                entry("main/binary-amd64/Packages", "")
            ),
        );
        assert_eq!(
            patch_age(&empty, now()),
            "le_14d",
            "an index listed as empty"
        );

        let pending = Some((
            true,
            "Inst fictional-lib [1.0] (1.1 Fictional:1/fictional-security [amd64])\n",
        ));
        let no_amd64 = format!(
            "{SECURITY_LISTS}SHA256:\n{}",
            entry("main/binary-i386/Packages", INDEX)
        );
        for (what, host) in [
            (
                "pending update",
                apt_host(&[SECURITY_LISTS, RELEASE_POCKET], pending),
            ),
            (
                "Packages index removed",
                complete().without(&packages("suite0")),
            ),
            (
                "configured source without a Release",
                complete().configure("suite2"),
            ),
            (
                "pocket without a Release",
                complete().without(&format!("{}InRelease", source("suite1"))),
            ),
            (
                "second security source without its index",
                apt_host(&[SECURITY_LISTS, SECURITY_LISTS], clear).without(&packages("suite1")),
            ),
            (
                "second security source not downloaded",
                apt_host(&[SECURITY_LISTS], clear).configure("suite1"),
            ),
            (
                "orphan Release",
                complete().with(
                    &format!("{LISTS}/unconfigured.invalid_dists_fictional-security_Release"),
                    &listing(SECURITY_LISTS),
                ),
            ),
            (
                "orphan Release for a missing configured one",
                complete()
                    .without(&format!("{}InRelease", source("suite0")))
                    .with(
                        &format!("{LISTS}/unconfigured.invalid_dists_fictional-security_Release"),
                        &listing(SECURITY_LISTS),
                    ),
            ),
            (
                "no index for this architecture",
                complete().with(&format!("{}InRelease", source("suite0")), &no_amd64),
            ),
            (
                "index targets unavailable",
                complete().answer(INDEX_TARGETS, None),
            ),
            (
                "architecture unknown",
                complete().answer(ARCH, Some((false, ""))),
            ),
            (
                "unreadable index targets",
                complete().answer(INDEX_TARGETS, Some((true, "Identifier: Packages\n"))),
            ),
        ] {
            assert_eq!(patch_age(&host, now()), "unknown", "{what}");
        }
    }

    /// The i386 Packages index of `suite`.
    fn foreign_packages(suite: &str) -> String {
        format!("{}main_binary-i386_Packages.lz4", source(suite))
    }

    /// R6-M1: APT installs packages for every foreign architecture dpkg is configured with, so
    /// each one needs a downloaded security index that matches the Release.
    #[test]
    fn apt_patch_age_covers_foreign_architectures() {
        let clear = Some((true, APT_CLEAR));
        let multiarch = || {
            apt_host(&[SECURITY_LISTS, RELEASE_POCKET], clear)
                .answer(FOREIGN_ARCHS, Some((true, "i386\n")))
                .with(&foreign_packages("suite0"), INDEX)
                .with(&foreign_packages("suite1"), INDEX)
        };
        assert_eq!(
            patch_age(&multiarch(), now()),
            "le_14d",
            "complete multiarch"
        );
        let native_only = format!(
            "{SECURITY_LISTS}SHA256:\n{}",
            entry("main/binary-amd64/Packages", INDEX)
        );
        for (what, host) in [
            (
                "foreign security index removed",
                multiarch().without(&foreign_packages("suite0")),
            ),
            (
                "foreign security index stale",
                multiarch().with(&foreign_packages("suite0"), ""),
            ),
            (
                "security source publishes no foreign index",
                multiarch().with(&format!("{}InRelease", source("suite0")), &native_only),
            ),
            (
                "foreign architectures unknown",
                multiarch().answer(FOREIGN_ARCHS, Some((false, ""))),
            ),
        ] {
            assert_eq!(patch_age(&host, now()), "unknown", "{what}");
        }
    }

    /// R6-M2: a downloaded index counts only when its size and SHA-256 match the entry the
    /// Release lists for it, after APT decodes it or as stored.
    #[test]
    fn apt_patch_age_needs_indexes_that_match_the_release() {
        let clear = Some((true, APT_CLEAR));
        let complete = || apt_host(&[SECURITY_LISTS, RELEASE_POCKET], clear);
        let plain = packages("suite0").replace(".lz4", "");
        let older = INDEX.replace("1.1", "1.0");
        assert_eq!(older.len(), INDEX.len());
        let stored_xz = format!(
            "{SECURITY_LISTS}SHA256:\n{}",
            entry("main/binary-amd64/Packages.xz", "FICTIONAL xz bytes")
        );
        let as_listed_xz = complete()
            .without(&packages("suite0"))
            .with(&format!("{}InRelease", source("suite0")), &stored_xz)
            .with(
                &plain.replace("Packages", "Packages.xz"),
                "FICTIONAL xz bytes",
            );
        assert_eq!(
            patch_age(&as_listed_xz, now()),
            "le_14d",
            "stored form listed in the Release"
        );
        let arch_all = |extra: &str| {
            complete()
                .answer(
                    INDEX_TARGETS,
                    Some((
                        true,
                        &(index_target("suite0")
                            + &index_target("suite1")
                            + &format!(
                                "MetaKey: main/binary-all/Packages\nFilename: {}main_binary-all_Packages\n\
                                 Target-Of: deb\nIdentifier: Packages\nArchitecture: all\n\n",
                                source("suite0")
                            )),
                    )),
                )
                .with(
                    &format!("{}InRelease", source("suite0")),
                    &(listing(&format!("{SECURITY_LISTS}{extra}"))
                        + &entry("main/binary-all/Packages", INDEX)),
                )
        };
        assert_eq!(
            patch_age(
                &arch_all("No-Support-for-Architecture-all: Packages\n"),
                now()
            ),
            "le_14d",
            "an arch-all index APT does not use"
        );
        for (what, host) in [
            (
                "empty plain index",
                complete().without(&packages("suite0")).with(&plain, ""),
            ),
            (
                "empty compressed index",
                complete()
                    .without(&packages("suite0"))
                    .with(&plain.replace("Packages", "Packages.gz"), ""),
            ),
            (
                "same size, older content",
                complete().with(&packages("suite0"), &older),
            ),
            (
                "a second, stale copy beside the current one",
                complete().with(&plain, &older),
            ),
            (
                "non-security source mismatched",
                complete().with(&packages("suite1"), &older),
            ),
            ("arch-all index APT uses, missing", arch_all("")),
            (
                "Release without SHA256 entries",
                complete().with(
                    &format!("{}InRelease", source("suite0")),
                    &format!("{SECURITY_LISTS}MD5Sum:\n 0d 99 main/binary-amd64/Packages\n"),
                ),
            ),
        ] {
            assert_eq!(patch_age(&host, now()), "unknown", "{what}");
        }
    }

    /// One SHA512 line of a Release: the hash and size of `content`, listed under `name`.
    fn entry512(name: &str, content: &str) -> String {
        let sha = hex::encode(<sha2::Sha512 as sha2::Digest>::digest(content.as_bytes()));
        format!(" {sha} {} {name}\n", content.len())
    }

    /// R7-L3: an index is checked with the strongest hash its Release lists, so a source that
    /// publishes only SHA512 is verified too, and a SHA256 match does not excuse a SHA512
    /// mismatch. An index the Release lists without a usable hash leaves the cache unproven.
    #[test]
    fn apt_patch_age_verifies_the_strongest_listed_hash() {
        let clear = Some((true, APT_CLEAR));
        let pocket = |hashes: &str| {
            apt_host(&[SECURITY_LISTS, RELEASE_POCKET], clear).with(
                &format!("{}InRelease", source("suite1")),
                &format!("{RELEASE_POCKET}{hashes}"),
            )
        };
        let sha512_only = || {
            pocket(&format!(
                "SHA512:\n{}",
                entry512("main/binary-amd64/Packages", INDEX)
            ))
        };
        assert_eq!(
            patch_age(&sha512_only(), now()),
            "le_14d",
            "complete SHA512-only source"
        );
        let older = INDEX.replace("1.1", "1.0");
        for (what, host) in [
            (
                "SHA512-only source with a truncated index",
                sha512_only().with(&packages("suite1"), "Package: fictional-lib\n"),
            ),
            (
                "SHA512-only source with an older index",
                sha512_only().with(&packages("suite1"), &older),
            ),
            (
                "SHA256 matches but SHA512 does not",
                pocket(&format!(
                    "SHA256:\n{}SHA512:\n{}",
                    entry("main/binary-amd64/Packages", INDEX),
                    entry512("main/binary-amd64/Packages", &older)
                )),
            ),
            (
                "index listed with MD5 only",
                pocket("MD5Sum:\n 0d 99 main/binary-amd64/Packages\n"),
            ),
        ] {
            assert_eq!(patch_age(&host, now()), "unknown", "{what}");
        }
    }

    /// A host whose package lists APT refreshes while the upgrade simulation runs: every
    /// command and file read sees `before` until the simulation finishes, then `after`. Hashing
    /// an index waits for the refresh, so validation hashes the refreshed cache.
    struct RefreshingHost {
        before: FakeHost,
        after: FakeHost,
        refreshed: std::sync::Mutex<bool>,
        changed: std::sync::Condvar,
    }

    impl RefreshingHost {
        fn new(before: FakeHost, after: FakeHost) -> RefreshingHost {
            RefreshingHost {
                before,
                after,
                refreshed: std::sync::Mutex::new(false),
                changed: std::sync::Condvar::new(),
            }
        }

        fn now(&self) -> &FakeHost {
            if *self.refreshed.lock().unwrap() {
                &self.after
            } else {
                &self.before
            }
        }
    }

    impl PackageHost for RefreshingHost {
        fn read(&self, path: &str) -> Option<String> {
            self.now().read(path)
        }

        fn run(&self, program: &str, args: &[&str]) -> Option<Ran> {
            let ran = self.now().run(program, args);
            if format!("{program} {}", args.join(" ")) == APT_QUERY {
                *self.refreshed.lock().unwrap() = true;
                self.changed.notify_all();
            }
            ran
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            self.now().list(dir)
        }

        fn digest(&self, path: &str, decode: bool, hash: Hash) -> Option<IndexDigest> {
            let refreshed = self.refreshed.lock().unwrap();
            let _ = self
                .changed
                .wait_timeout_while(refreshed, std::time::Duration::from_secs(5), |r| !*r)
                .unwrap();
            self.now().digest(path, decode, hash)
        }

        fn stamp(&self, path: &str) -> Option<String> {
            self.now().stamp(path)
        }
    }

    /// R7-M1: the simulation and the validation must describe one cache generation. A refresh
    /// that lands while the simulation runs makes the result unknown, even though the
    /// refreshed cache on its own passes validation.
    #[test]
    fn apt_patch_age_needs_one_cache_generation() {
        let clear = Some((true, APT_CLEAR));
        let complete = || apt_host(&[SECURITY_LISTS, RELEASE_POCKET], clear);
        let older = INDEX.replace("1.1", "1.0");
        let stable = RefreshingHost::new(complete(), complete());
        assert_eq!(patch_age(&stable, now()), "le_14d", "no refresh");
        let refreshed =
            RefreshingHost::new(complete().with(&packages("suite0"), &older), complete());
        assert_eq!(
            patch_age(&refreshed, now()),
            "unknown",
            "simulation read the older index, validation the refreshed one"
        );
        let new_release = RefreshingHost::new(
            complete(),
            complete().with(
                &format!("{}InRelease", source("suite0")),
                &listing(&SECURITY_LISTS.replace("2:34:10", "8:00:00")),
            ),
        );
        assert_eq!(
            patch_age(&new_release, now()),
            "unknown",
            "Release replaced during the simulation"
        );
    }

    #[test]
    fn dnf_patch_age_needs_a_readable_security_query() {
        let today = now();
        let upgraded = Some((true, DNF_UPGRADED));
        assert_eq!(
            patch_age(&dnf_host(upgraded, Some((true, ""))), today),
            "le_14d"
        );
        for (what, host) in [
            (
                "pending",
                dnf_host(
                    upgraded,
                    Some((
                        true,
                        "FICTIONAL-2026-0001 Important/Sec. fictional-lib-1.1.x86_64\n",
                    )),
                ),
            ),
            (
                "no cache",
                dnf_host(
                    upgraded,
                    Some((
                        false,
                        "Cache-only enabled but no cache for repository \"updates\"\n",
                    )),
                ),
            ),
            ("timed out", dnf_host(upgraded, None)),
            (
                "unrecognized",
                dnf_host(upgraded, Some((true, "FICTIONAL unexpected output\n"))),
            ),
            (
                "history failed",
                dnf_host(Some((false, DNF_UPGRADED)), Some((true, ""))),
            ),
        ] {
            assert_eq!(patch_age(&host, today), "unknown", "{what}");
        }
    }

    #[test]
    fn dnf_subset_flags_before_the_verb_do_not_reset_patch_age() {
        let today = now();
        let row = |cmd: &str| format!(" 3 {cmd:<37} 2026-10-11 15:52:37  46\n");
        for cmd in [
            "dnf --exclude=fictional-lib upgrade",
            "dnf --security --sec-severity=Critical upgrade",
            "dnf -x fictional-lib upgrade",
        ] {
            let host = dnf_host(Some((true, &row(cmd))), Some((true, "")));
            assert_eq!(patch_age(&host, today), "unknown", "{cmd}");
        }
        for cmd in ["dnf --security upgrade", "dnf -y --refresh upgrade"] {
            let host = dnf_host(Some((true, &row(cmd))), Some((true, "")));
            assert_eq!(patch_age(&host, today), "le_14d", "{cmd}");
        }
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
