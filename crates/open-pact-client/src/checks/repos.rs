use std::collections::{BTreeMap, HashSet};
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Remote {
    host: String,
    path: String,
}

pub(crate) fn fresh(scan: &RepoScan, now: i64) -> bool {
    now >= scan.scanned_at && now.saturating_sub(scan.scanned_at) <= MAX_AGE_SECS
}

pub(crate) fn load(home: &Path, now: i64) -> Result<Option<RepoScan>> {
    let path = home.join(FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| path.display().to_string()),
    };
    let scan: RepoScan = serde_json::from_slice(&bytes).context("invalid repo-scan.json")?;
    Ok(fresh(&scan, now).then_some(scan))
}

pub(crate) fn scan_and_store(
    home: &Path,
    root: &Path,
    folders: &[PathBuf],
    patterns: &[String],
) -> Result<RepoScan> {
    let ssh_hosts = ssh_hosts(&root.join(".ssh/config"));
    let folders = folders
        .iter()
        .map(|folder| fs::canonicalize(folder).unwrap_or_else(|_| absolute(folder)))
        .collect::<Vec<_>>();
    let mut repos = HashSet::new();
    let mut counts = (0_i32, 0_i32);
    let mut outside_paths = Vec::new();
    walk(root, 0, &mut repos, &mut |repo| {
        if !repo_matches(repo, &ssh_hosts, patterns) {
            return;
        }
        counts.1 += 1;
        let repo_path = fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
        if !folders.iter().any(|folder| repo_path.starts_with(folder)) {
            counts.0 += 1;
            outside_paths.push(repo_path);
        }
    })?;
    outside_paths.sort();
    let scan = RepoScan {
        scanned_at: chrono::Utc::now().timestamp(),
        managed_repos_outside: counts.0,
        managed_repos_total: counts.1,
        outside_paths,
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
    visit: &mut impl FnMut(&Path),
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    match fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| dir.display().to_string()),
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| dir.display().to_string()),
    };
    let mut has_git = false;
    let mut children = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => return Err(error).with_context(|| dir.display().to_string()),
        };
        let path = entry.path();
        let kind = match fs::symlink_metadata(&path) {
            Ok(meta) => meta.file_type(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| path.display().to_string()),
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
            walk(&child, depth + 1, seen, visit)?;
        }
    }
    Ok(())
}

fn repo_matches(repo: &Path, ssh_hosts: &BTreeMap<String, String>, patterns: &[String]) -> bool {
    read_remote_urls(repo)
        .iter()
        .any(|url| remote_matches(url, ssh_hosts, patterns))
}

fn read_remote_urls(repo: &Path) -> Vec<String> {
    let git = repo.join(".git");
    let git_dir = match fs::symlink_metadata(&git) {
        Ok(metadata) if metadata.is_dir() => git,
        Ok(metadata) if metadata.file_type().is_symlink() => return Vec::new(),
        Ok(_) => {
            let Ok(text) = fs::read_to_string(&git) else {
                return Vec::new();
            };
            let Some(path) = text.trim().strip_prefix("gitdir:") else {
                return Vec::new();
            };
            let path = repo.join(path.trim());
            fs::canonicalize(&path).unwrap_or(path)
        }
        Err(_) => return Vec::new(),
    };
    let common = fs::read_to_string(git_dir.join("commondir"))
        .ok()
        .map(|text| {
            let path = git_dir.join(text.trim());
            fs::canonicalize(&path).unwrap_or(path)
        })
        .unwrap_or(git_dir);
    parse_config(&common.join("config"))
}

fn parse_config(path: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
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
    urls
}

fn ssh_hosts(path: &Path) -> BTreeMap<String, String> {
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let mut hosts = Vec::<String>::new();
    let mut names = BTreeMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else { continue };
        let values = fields.collect::<Vec<_>>();
        if key.eq_ignore_ascii_case("host") {
            hosts = values
                .into_iter()
                .filter(|host| !host.contains(['*', '?', '!']))
                .map(str::to_ascii_lowercase)
                .collect();
        } else if key.eq_ignore_ascii_case("hostname")
            && let Some(hostname) = values.first()
        {
            for host in &hosts {
                names.insert(host.clone(), hostname.to_ascii_lowercase());
            }
        }
    }
    names
}

fn normalize_remote(raw: &str, ssh_hosts: &BTreeMap<String, String>) -> Option<Remote> {
    let (authority, path) = if let Some(rest) = raw.strip_prefix("ssh://") {
        rest.split_once('/')?
    } else if let Some(rest) = raw.strip_prefix("https://") {
        rest.split_once('/')?
    } else if let Some((_, rest)) = raw.split_once('@') {
        rest.split_once(':')?
    } else {
        return None;
    };
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = host.split(':').next()?.to_ascii_lowercase();
    let host = ssh_hosts.get(&host).map_or(host.as_str(), String::as_str);
    let mut path = path
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string();
    if let Some(stripped) = path.strip_suffix(".git") {
        path = stripped.to_string();
    }
    Some(Remote {
        host: host.to_ascii_lowercase(),
        path,
    })
}

pub(crate) fn remote_matches(
    url: &str,
    ssh_hosts: &BTreeMap<String, String>,
    patterns: &[String],
) -> bool {
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
        let hosts = BTreeMap::new();
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
    fn resolves_exact_ssh_aliases_and_keeps_wildcards_unmapped() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("config"),
            "Host work-git\n HostName github.com\nHost *.example\n HostName wrong.test\n",
        )
        .unwrap();
        let hosts = ssh_hosts(&temp.path().join("config"));
        let patterns = [pattern("github.com/example-org/")];
        assert!(remote_matches(
            "git@work-git:example-org/app",
            &hosts,
            &patterns
        ));
        assert!(!remote_matches(
            "git@one.example:example-org/app",
            &hosts,
            &patterns
        ));
    }

    #[test]
    fn stale_and_future_scans_are_unknown() {
        let scan = RepoScan {
            scanned_at: 100,
            managed_repos_outside: 1,
            managed_repos_total: 1,
            outside_paths: vec![PathBuf::from("/device/private/repo")],
        };
        assert!(fresh(&scan, 100 + MAX_AGE_SECS));
        assert!(!fresh(&scan, 101 + MAX_AGE_SECS));
        assert!(!fresh(&scan, 99));
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
        let saved = fs::read_to_string(state.join(FILE)).unwrap();
        assert!(saved.contains(outside.to_str().unwrap()));
        assert!(!saved.contains("github.com"));
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
        };
        fs::create_dir_all(temp.path()).unwrap();
        fs::write(temp.path().join(FILE), serde_json::to_vec(&scan).unwrap()).unwrap();
        assert!(load(temp.path(), 100 + MAX_AGE_SECS).unwrap().is_some());
        assert!(load(temp.path(), 101 + MAX_AGE_SECS).unwrap().is_none());
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
