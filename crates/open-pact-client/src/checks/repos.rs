use std::cell::Cell;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const FILE: &str = "repo-scan.json";
const MAX_DEPTH: usize = 8;
const MAX_AGE_SECS: i64 = 48 * 60 * 60;
const PRUNED: &[&str] = &["node_modules", "target", "bin", "obj", ".Trash"];

pub(crate) fn lower_process_priority() {
    #[cfg(unix)]
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 10);
    }
    #[cfg(windows)]
    unsafe {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
            fn SetPriorityClass(process: *mut std::ffi::c_void, priority: u32) -> i32;
        }
        let _ = SetPriorityClass(GetCurrentProcess(), 0x0000_4000);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RepoScan {
    pub(crate) scanned_at: i64,
    pub(crate) managed_repos_outside: i32,
    pub(crate) managed_repos_total: i32,
    pub(crate) outside_paths: Vec<PathBuf>,
    #[serde(default)]
    pub(crate) partial: bool,
    #[serde(default)]
    pub(crate) access_denied: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Remote {
    host: String,
    path: String,
}

pub(crate) fn fresh(scan: &RepoScan, now: i64) -> bool {
    !scan.partial && now >= scan.scanned_at && now.saturating_sub(scan.scanned_at) <= MAX_AGE_SECS
}

pub(crate) fn load(home: &Path, now: i64) -> Result<Option<RepoScan>> {
    Ok(load_attempt(home)?.filter(|scan| fresh(scan, now)))
}

pub(crate) fn load_attempt(home: &Path) -> Result<Option<RepoScan>> {
    let path = home.join(FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| path.display().to_string()),
    };
    let Ok(scan) = serde_json::from_slice::<RepoScan>(&bytes) else {
        return Ok(None);
    };
    Ok(Some(scan))
}

pub(crate) fn scan_and_store(
    home: &Path,
    root: &Path,
    folders: &[PathBuf],
    patterns: &[String],
) -> Result<RepoScan> {
    let ssh_hosts = fs::read_to_string(root.join(".ssh/config"))
        .map(|text| parse_ssh_hosts(&text))
        .unwrap_or_default();
    let folders = folders
        .iter()
        .map(|folder| fs::canonicalize(folder).unwrap_or_else(|_| absolute(folder)))
        .collect::<Vec<_>>();
    let mut repos = HashSet::new();
    let mut counts = (0_i32, 0_i32);
    let mut outside_paths = Vec::new();
    let mut partial = false;
    let mut access_denied = false;
    let repo_partial = Cell::new(false);
    let repo_access_denied = Cell::new(false);
    walk(
        root,
        0,
        &mut repos,
        &mut partial,
        &mut access_denied,
        &mut |repo| {
            let urls = match read_remote_urls(repo) {
                Ok(urls) => urls,
                Err(error) => {
                    repo_partial.set(true);
                    repo_access_denied.set(
                        repo_access_denied.get()
                            || error.kind() == std::io::ErrorKind::PermissionDenied,
                    );
                    return;
                }
            };
            if !urls
                .iter()
                .any(|url| remote_matches(url, &ssh_hosts, patterns))
            {
                return;
            }
            counts.1 += 1;
            let repo_path = fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
            if !folders.iter().any(|folder| repo_path.starts_with(folder)) {
                counts.0 += 1;
                outside_paths.push(repo_path);
            }
        },
    )?;
    partial |= repo_partial.get();
    access_denied |= repo_access_denied.get();
    outside_paths.sort();
    let scan = RepoScan {
        scanned_at: chrono::Utc::now().timestamp(),
        managed_repos_outside: counts.0,
        managed_repos_total: counts.1,
        outside_paths,
        partial,
        access_denied,
    };
    fs::create_dir_all(home)?;
    let path = home.join(FILE);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| path.display().to_string())?;
    file.write_all(&serde_json::to_vec(&scan)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(scan)
}

fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    }
}

fn walk(
    dir: &Path,
    depth: usize,
    seen: &mut HashSet<PathBuf>,
    partial: &mut bool,
    access_denied: &mut bool,
    visit: &mut impl FnMut(&Path),
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    match fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            *partial = true;
            *access_denied |= error.kind() == std::io::ErrorKind::PermissionDenied;
            return Ok(());
        }
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            *partial = true;
            *access_denied |= error.kind() == std::io::ErrorKind::PermissionDenied;
            return Ok(());
        }
    };
    let mut has_git = false;
    let mut children = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                *partial = true;
                *access_denied |= error.kind() == std::io::ErrorKind::PermissionDenied;
                continue;
            }
        };
        let path = entry.path();
        let kind = match fs::symlink_metadata(&path) {
            Ok(meta) => meta.file_type(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                *partial = true;
                *access_denied |= error.kind() == std::io::ErrorKind::PermissionDenied;
                continue;
            }
        };
        if path.file_name().is_some_and(|name| name == ".git") {
            has_git = true;
            continue;
        }
        if !kind.is_dir() {
            continue;
        }
        let name = entry.file_name();
        if PRUNED.iter().any(|pruned| name == *pruned) || (depth == 0 && name == "Library") {
            continue;
        }
        children.push(path);
    }
    if has_git {
        let canonical = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        if seen.insert(canonical) {
            visit(dir);
        }
    }
    if depth < MAX_DEPTH {
        for child in children {
            walk(&child, depth + 1, seen, partial, access_denied, visit)?;
        }
    }
    Ok(())
}

fn read_remote_urls(repo: &Path) -> std::io::Result<Vec<String>> {
    let git = repo.join(".git");
    let git_dir = match fs::symlink_metadata(&git) {
        Ok(metadata) if metadata.is_dir() => git,
        Ok(metadata) if metadata.file_type().is_symlink() => return Ok(Vec::new()),
        Ok(_) => {
            let text = fs::read_to_string(&git)?;
            let Some(path) = text.trim().strip_prefix("gitdir:") else {
                return Ok(Vec::new());
            };
            let path = repo.join(path.trim());
            fs::canonicalize(&path).unwrap_or(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    fs::read_dir(&git_dir)?.count();
    let commondir = match fs::read_to_string(git_dir.join("commondir")) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let common = commondir.map_or_else(
        || git_dir.clone(),
        |text| {
            let path = git_dir.join(text.trim());
            fs::canonicalize(&path).unwrap_or(path)
        },
    );
    parse_config(&common.join("config"))
}

fn parse_config(path: &Path) -> std::io::Result<Vec<String>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut section = String::new();
    let mut urls = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].to_ascii_lowercase();
            continue;
        }
        if section.starts_with("remote ")
            && let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("url")
        {
            let value = value.trim().trim_matches('"').trim_matches('\'');
            urls.push(value.to_string());
        }
    }
    Ok(urls)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SshConfig {
    blocks: Vec<HostBlock>,
}

#[derive(Clone, Debug)]
struct HostBlock {
    patterns: Vec<String>,
    host_name: Option<String>,
}

impl SshConfig {
    fn resolve(&self, host: &str) -> String {
        self.blocks
            .iter()
            .find_map(|block| {
                host_matches_block(host, &block.patterns)
                    .then_some(block.host_name.as_deref())
                    .flatten()
            })
            .unwrap_or(host)
            .to_ascii_lowercase()
    }
}

fn parse_ssh_hosts(text: &str) -> SshConfig {
    let mut config = SshConfig::default();
    let mut current = Some(HostBlock {
        patterns: vec!["*".to_string()],
        host_name: None,
    });
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else { continue };
        let values = fields.collect::<Vec<_>>();
        if key.eq_ignore_ascii_case("host") {
            if let Some(block) = current.take() {
                config.blocks.push(block);
            }
            current = Some(HostBlock {
                patterns: values
                    .iter()
                    .map(|value| value.to_ascii_lowercase())
                    .collect(),
                host_name: None,
            });
        } else if key.eq_ignore_ascii_case("hostname")
            && let Some(hostname) = values.first()
            && let Some(block) = current.as_mut()
            && block.host_name.is_none()
        {
            block.host_name = Some(hostname.to_ascii_lowercase());
        }
    }
    if let Some(block) = current {
        config.blocks.push(block);
    }
    config
}

fn host_matches_block(host: &str, patterns: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    let denied = patterns
        .iter()
        .filter_map(|pattern| pattern.strip_prefix('!'))
        .any(|pattern| wildcard_matches(&host, pattern));
    !denied
        && patterns
            .iter()
            .filter(|pattern| !pattern.starts_with('!'))
            .any(|pattern| wildcard_matches(&host, pattern))
}

fn wildcard_matches(value: &str, pattern: &str) -> bool {
    let mut value_index = 0;
    let mut pattern_index = 0;
    let mut star = None;
    let mut retry = 0;
    let value = value.as_bytes();
    let pattern = pattern.to_ascii_lowercase();
    let pattern = pattern.as_bytes();
    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            value_index += 1;
            pattern_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star = Some(pattern_index);
            pattern_index += 1;
            retry = value_index;
        } else if let Some(star_index) = star {
            retry += 1;
            value_index = retry;
            pattern_index = star_index + 1;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn normalize_remote(raw: &str, ssh_hosts: &SshConfig) -> Option<Remote> {
    let (authority, path, resolve_ssh) = if let Some(rest) = raw.strip_prefix("ssh://") {
        let (authority, path) = rest.split_once('/')?;
        (authority, path, true)
    } else if let Some(rest) = raw.strip_prefix("https://") {
        let (authority, path) = rest.split_once('/')?;
        (authority, path, false)
    } else if let Some((_, rest)) = raw.split_once('@') {
        let (authority, path) = rest.split_once(':')?;
        (authority, path, true)
    } else {
        return None;
    };
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = host.split(':').next()?.to_ascii_lowercase();
    let host = if resolve_ssh {
        ssh_hosts.resolve(&host)
    } else {
        host
    };
    let mut path = path
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string();
    if let Some(stripped) = path.strip_suffix(".git") {
        path = stripped.to_string();
    }
    Some(Remote { host, path })
}

pub(crate) fn remote_matches(url: &str, ssh_hosts: &SshConfig, patterns: &[String]) -> bool {
    let Some(remote) = normalize_remote(url, ssh_hosts) else {
        return false;
    };
    matches_pattern(&remote, patterns)
}

fn matches_pattern(remote: &Remote, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        let Some((host, prefix)) = pattern.split_once('/') else {
            return false;
        };
        remote.host == host
            && remote.path.starts_with(prefix.trim_end_matches('/'))
            && (remote.path.len() == prefix.trim_end_matches('/').len()
                || remote
                    .path
                    .as_bytes()
                    .get(prefix.trim_end_matches('/').len())
                    == Some(&b'/'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(value: &str) -> String {
        value.into()
    }

    #[test]
    fn matches_scp_ssh_and_https_urls_by_host_and_path_prefix() {
        let patterns = [pattern("github.com/example-org/")];
        let hosts = SshConfig::default();
        for url in [
            "git@github.com:example-org/app.git",
            "ssh://git@github.com/example-org/app.git",
            "https://github.com/example-org/app.git",
            "https://user@github.com/example-org/app.git",
        ] {
            assert!(remote_matches(url, &hosts, &patterns), "{url}");
        }
        assert!(!remote_matches(
            "git@github.com:example-org-other/app.git",
            &hosts,
            &patterns
        ));
        assert!(!remote_matches(
            "https://github.com/other/app.git",
            &hosts,
            &patterns
        ));
    }

    #[test]
    fn resolves_ssh_aliases_using_first_matching_host_name() {
        let hosts = parse_ssh_hosts(
            "Host *\n HostName other.invalid\nHost alias\n HostName matching.invalid\n",
        );
        let patterns = [pattern("other.invalid/example-org/")];
        assert!(!remote_matches(
            "git@alias:example-org/app",
            &hosts,
            &[pattern("matching.invalid/example-org/")]
        ));
        assert!(remote_matches(
            "git@alias:example-org/app",
            &hosts,
            &patterns
        ));

        let hosts =
            parse_ssh_hosts("Host alias\n HostName matching.invalid\n HostName other.invalid\n");
        let patterns = [pattern("matching.invalid/example-org/")];
        assert!(remote_matches(
            "git@alias:example-org/app",
            &hosts,
            &patterns
        ));
        assert!(!remote_matches(
            "git@alias:example-org/app",
            &hosts,
            &[pattern("other.invalid/example-org/")]
        ));
    }

    #[test]
    fn matches_wildcard_and_negated_ssh_host_patterns_in_order() {
        let hosts = parse_ssh_hosts(
            "Host *.example !blocked.example\n HostName wildcard.invalid\nHost ?lias.test\n HostName alias.invalid\n",
        );
        assert_eq!(hosts.resolve("good.example"), "wildcard.invalid");
        assert_eq!(hosts.resolve("blocked.example"), "blocked.example");
        assert_eq!(hosts.resolve("alias.test"), "alias.invalid");
        assert!(remote_matches(
            "git@good.example:example-org/app",
            &hosts,
            &[pattern("wildcard.invalid/example-org/")]
        ));
        assert!(!remote_matches(
            "git@blocked.example:example-org/app",
            &hosts,
            &[pattern("wildcard.invalid/example-org/")]
        ));
        assert!(remote_matches(
            "https://good.example/example-org/app",
            &hosts,
            &[pattern("good.example/example-org/")]
        ));
    }

    #[test]
    fn stale_and_future_scans_are_unknown() {
        let scan = RepoScan {
            scanned_at: 100,
            managed_repos_outside: 1,
            managed_repos_total: 1,
            outside_paths: vec![PathBuf::from("/device/private/repo")],
            partial: false,
            access_denied: false,
        };
        assert!(fresh(&scan, 100 + MAX_AGE_SECS));
        assert!(!fresh(&scan, 101 + MAX_AGE_SECS));
        assert!(!fresh(&scan, 99));
    }

    #[test]
    fn corrupt_stored_scan_is_unavailable() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(FILE), b"{not json").unwrap();
        assert!(load(temp.path(), 100).unwrap().is_none());
    }

    #[test]
    fn partial_attempt_keeps_its_timestamp_for_scheduled_cadence() {
        let temp = tempfile::tempdir().unwrap();
        let scan = RepoScan {
            scanned_at: 1_000,
            managed_repos_outside: 0,
            managed_repos_total: 0,
            outside_paths: Vec::new(),
            partial: true,
            access_denied: false,
        };
        fs::write(temp.path().join(FILE), serde_json::to_vec(&scan).unwrap()).unwrap();
        assert_eq!(
            load_attempt(temp.path()).unwrap().unwrap().scanned_at,
            1_000
        );
        assert!(load(temp.path(), 1_000).unwrap().is_none());
    }

    #[test]
    fn readable_git_directory_without_config_is_a_normal_repository() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        fs::create_dir_all(root.join("app/.git")).unwrap();
        let scan = scan_and_store(
            &temp.path().join("client"),
            &root,
            &[],
            &[pattern("github.com/example-org/")],
        )
        .unwrap();
        assert!(!scan.partial);
        assert_eq!(scan.managed_repos_total, 0);
    }

    #[test]
    fn counts_matching_repositories_once_and_keeps_paths_local() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        let managed = root.join("work");
        let outside = root.join("other");
        let state = temp.path().join("client");
        for repo in [&managed, &outside] {
            fs::create_dir_all(repo.join(".git")).unwrap();
            fs::write(
                repo.join(".git/config"),
                "[remote \"origin\"]\n url = git@github.com:example-org/app.git\n",
            )
            .unwrap();
        }
        let scan = scan_and_store(
            &state,
            &root,
            std::slice::from_ref(&managed),
            &[pattern("github.com/example-org/")],
        )
        .unwrap();
        assert_eq!(
            (scan.managed_repos_outside, scan.managed_repos_total),
            (1, 2)
        );
        let saved = fs::read(state.join(FILE)).unwrap();
        let saved: RepoScan = serde_json::from_slice(&saved).unwrap();
        assert_eq!(
            saved.outside_paths,
            vec![fs::canonicalize(outside).unwrap()]
        );
        let saved_json = serde_json::to_string(&saved).unwrap();
        assert!(!saved_json.contains("github.com"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(state.join(FILE)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn follows_worktree_and_submodule_git_files_to_shared_configs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        let worktree = root.join("worktree");
        let shared = root.join(".git/worktrees/wt");
        fs::create_dir_all(&worktree).unwrap();
        fs::create_dir_all(&shared).unwrap();
        fs::write(worktree.join(".git"), "gitdir: ../.git/worktrees/wt\n").unwrap();
        fs::write(shared.join("commondir"), "../..\n").unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(
            root.join(".git/config"),
            "[remote \"origin\"]\n url = git@github.com:example-org/shared.git\n",
        )
        .unwrap();

        let submodule = root.join("project/vendor/lib");
        let module = root.join("project/.git/modules/vendor/lib");
        fs::create_dir_all(&submodule).unwrap();
        fs::create_dir_all(&module).unwrap();
        fs::write(
            submodule.join(".git"),
            "gitdir: ../../.git/modules/vendor/lib\n",
        )
        .unwrap();
        fs::write(
            module.join("config"),
            "[remote \"origin\"]\n url = git@github.com:example-org/submodule.git\n",
        )
        .unwrap();

        let scan = scan_and_store(
            &temp.path().join("client"),
            &root,
            &[],
            &[pattern("github.com/example-org/")],
        )
        .unwrap();
        assert_eq!(scan.managed_repos_total, 3);
        assert_eq!(scan.managed_repos_outside, 3);
    }

    #[test]
    fn skips_pruned_folders_and_does_not_follow_symlink_loops_or_registered_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        let managed = root.join("work/repo");
        let pruned = root.join("target/repo");
        for repo in [&managed, &pruned] {
            fs::create_dir_all(repo.join(".git")).unwrap();
            fs::write(
                repo.join(".git/config"),
                "[remote \"origin\"]\n url = git@github.com:example-org/app.git\n",
            )
            .unwrap();
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&managed, root.join("alias")).unwrap();
            std::os::unix::fs::symlink(&root, root.join("loop")).unwrap();
        }
        let scan = scan_and_store(
            &temp.path().join("client"),
            &root,
            &[root.join("work")],
            &[pattern("github.com/example-org/")],
        )
        .unwrap();
        assert_eq!(
            (scan.managed_repos_outside, scan.managed_repos_total),
            (0, 1)
        );
    }

    #[test]
    fn returns_unknown_control_values_without_a_fresh_scan() {
        let manifest =
            open_pact_core::Manifest::parse(include_bytes!("../../../../examples/manifest.toml"))
                .unwrap();
        let controls = manifest
            .body()
            .controls
            .iter()
            .filter(|control| {
                matches!(
                    control.id.as_str(),
                    "managed_repos_outside" | "managed_repos_total"
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let values = super::super::run(open_pact_core::Os::Linux, &controls, None, None);
        assert_eq!(values["managed_repos_outside"], "unknown");
        assert_eq!(values["managed_repos_total"], "unknown");
    }

    #[test]
    fn reports_the_two_stored_counts_as_integers() {
        let manifest =
            open_pact_core::Manifest::parse(include_bytes!("../../../../examples/manifest.toml"))
                .unwrap();
        let controls = manifest
            .body()
            .controls
            .iter()
            .filter(|control| {
                matches!(
                    control.id.as_str(),
                    "managed_repos_outside" | "managed_repos_total"
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let scan = RepoScan {
            scanned_at: chrono::Utc::now().timestamp(),
            managed_repos_outside: 1,
            managed_repos_total: 2,
            outside_paths: vec![PathBuf::from("/device/private/repo")],
            partial: false,
            access_denied: false,
        };
        let values = super::super::run(open_pact_core::Os::Linux, &controls, None, Some(&scan));
        assert_eq!(
            values["managed_repos_outside"],
            open_pact_core::ControlValue::Integer(1)
        );
        assert_eq!(
            values["managed_repos_total"],
            open_pact_core::ControlValue::Integer(2)
        );
        let report_results = serde_json::to_string(&values).unwrap();
        assert!(!report_results.contains("/device/private/repo"));

        let partial = RepoScan {
            partial: true,
            access_denied: false,
            ..scan
        };
        let values = super::super::run(open_pact_core::Os::Linux, &controls, None, Some(&partial));
        assert_eq!(values["managed_repos_outside"], "unknown");
        assert_eq!(values["managed_repos_total"], "unknown");
    }

    #[test]
    fn skips_every_pruned_folder() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        for name in PRUNED {
            let repo = root.join(name).join("repo");
            fs::create_dir_all(repo.join(".git")).unwrap();
            fs::write(
                repo.join(".git/config"),
                "[remote \"origin\"]\n url = git@github.com:example-org/app.git\n",
            )
            .unwrap();
        }
        let scan = scan_and_store(
            &temp.path().join("client"),
            &root,
            &[],
            &[pattern("github.com/example-org/")],
        )
        .unwrap();
        assert_eq!(scan.managed_repos_total, 0);
    }

    #[test]
    fn ignores_repositories_without_a_matching_remote() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        let no_remote = root.join("no-remote");
        let other_remote = root.join("other-remote");
        for repo in [&no_remote, &other_remote] {
            fs::create_dir_all(repo.join(".git")).unwrap();
        }
        fs::write(
            other_remote.join(".git/config"),
            "[remote \"origin\"]\n url = git@github.com:other-org/app.git\n",
        )
        .unwrap();
        let scan = scan_and_store(
            &temp.path().join("client"),
            &root,
            &[],
            &[pattern("github.com/example-org/")],
        )
        .unwrap();
        assert_eq!(scan.managed_repos_total, 0);
    }

    #[test]
    fn stored_scan_becomes_unavailable_after_48_hours() {
        let temp = tempfile::tempdir().unwrap();
        let scan = RepoScan {
            scanned_at: 100,
            managed_repos_outside: 1,
            managed_repos_total: 1,
            outside_paths: vec![PathBuf::from("/device/private/repo")],
            partial: false,
            access_denied: false,
        };
        fs::create_dir_all(temp.path()).unwrap();
        fs::write(temp.path().join(FILE), serde_json::to_vec(&scan).unwrap()).unwrap();
        assert!(load(temp.path(), 100 + MAX_AGE_SECS).unwrap().is_some());
        assert!(load(temp.path(), 101 + MAX_AGE_SECS).unwrap().is_none());
    }

    #[test]
    #[cfg(unix)]
    fn unreadable_git_directory_marks_scan_partial_when_permissions_are_effective() {
        use std::os::unix::fs::PermissionsExt;

        // Root bypasses mode bits, so this probe cannot prove unreadability there.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped permission probe because root bypasses mode bits");
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        struct RestorePermissions {
            git: PathBuf,
            git_permissions: fs::Permissions,
            config: PathBuf,
            config_permissions: fs::Permissions,
        }

        impl RestorePermissions {
            fn restore(&self) -> std::io::Result<()> {
                fs::set_permissions(&self.git, self.git_permissions.clone())?;
                fs::set_permissions(&self.config, self.config_permissions.clone())
            }
        }

        impl Drop for RestorePermissions {
            fn drop(&mut self) {
                let _ = self.restore();
            }
        }

        for (name, deny_config) in [("git-dir", false), ("git-config", true)] {
            let repo = root.join(name);
            let git = repo.join(".git");
            fs::create_dir_all(&git).unwrap();
            let config = git.join("config");
            fs::write(
                &config,
                "[remote \"origin\"]\n url = git@github.com:example-org/app.git\n",
            )
            .unwrap();
            let restore_permissions = RestorePermissions {
                git_permissions: fs::metadata(&git).unwrap().permissions(),
                config_permissions: fs::metadata(&config).unwrap().permissions(),
                git: git.clone(),
                config: config.clone(),
            };
            let denied = if deny_config { &config } else { &git };
            fs::set_permissions(denied, fs::Permissions::from_mode(0o0)).unwrap();
            let denied_is_readable = if deny_config {
                fs::read_to_string(&config).is_ok()
            } else {
                fs::read_dir(&git).is_ok()
            };
            if denied_is_readable {
                restore_permissions.restore().unwrap();
                eprintln!(
                    "skipped permission probe because this platform does not enforce mode bits"
                );
                return;
            }
            eprintln!("running permission probe for {name}");
            let scan = scan_and_store(
                &temp.path().join(format!("client-{name}")),
                &root,
                &[],
                &[pattern("github.com/example-org/")],
            )
            .unwrap();
            restore_permissions.restore().unwrap();
            assert!(scan.partial);
            assert!(scan.access_denied);
            assert!(!fresh(&scan, scan.scanned_at));
        }
    }

    #[test]
    #[ignore]
    fn fixture_scan_bench() {
        let root = std::env::var_os("OPEN_PACT_SCAN_FIXTURE")
            .expect("set OPEN_PACT_SCAN_FIXTURE to the fixture home");
        let root = PathBuf::from(root);
        let started = std::time::Instant::now();
        let scan = scan_and_store(
            &root.join("client-state"),
            &root,
            &[],
            &[pattern("github.com/example-org/")],
        )
        .unwrap();
        assert_eq!(
            (scan.managed_repos_outside, scan.managed_repos_total),
            (200, 200)
        );
        println!("scan elapsed: {:?}", started.elapsed());
    }
}
