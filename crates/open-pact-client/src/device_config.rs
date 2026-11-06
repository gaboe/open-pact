use std::path::{Path, PathBuf};

use crate::{Home, report, schedule};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub(crate) const FILE: &str = "open-pact.toml";

const CONFIG_TEMPLATE: &str = r#"[report]
collector = "https://collector.example.org/status"
# vpn_probe defaults to the collector host and port.
# vpn_probe = "vpn.example.org:443"

[schedule]
# Set enabled to true, then run open-pact-client apply.
enabled = false
# Use system only on Windows, from an elevated PowerShell prompt.
run_as = "user"

[managed_repos]
# Use absolute paths or ~/ paths. Paths stay on this device.
# These folders are reserved for managed repository checks.
folders = []
"#;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceConfig {
    pub(crate) report: Option<Report>,
    pub(crate) schedule: Option<Schedule>,
    pub(crate) managed_repos: Option<ManagedRepos>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Report {
    pub(crate) collector: String,
    pub(crate) vpn_probe: Option<String>,
}

impl Report {
    pub(crate) fn probe(&self) -> String {
        self.vpn_probe.clone().unwrap_or_else(|| {
            let url = report::collector_url(&self.collector).expect("validated collector");
            format!(
                "{}:{}",
                url.host().unwrap(),
                url.port_or_known_default().unwrap()
            )
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Schedule {
    pub(crate) enabled: bool,
    pub(crate) run_as: RunAs,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RunAs {
    User,
    System,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedRepos {
    pub(crate) folders: Vec<PathBuf>,
}

impl DeviceConfig {
    pub(crate) fn load(home: &Home) -> Result<Option<Self>> {
        let path = home.file(FILE);
        let text = match crate::read_home_file(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let text =
            String::from_utf8(text).with_context(|| format!("{} must be UTF-8", path.display()))?;
        let user_home =
            std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
        Self::parse(&text, user_home.as_deref())
            .with_context(|| format!("{}", path.display()))
            .map(Some)
    }

    pub(crate) fn parse(text: &str, user_home: Option<&Path>) -> Result<Self> {
        let mut config: Self = toml::from_str(text).context("section/key")?;
        if let Some(report) = &config.report {
            report::collector_url(&report.collector).context("[report].collector")?;
            schedule::probe_address(&report.probe()).context("[report].vpn_probe")?;
        }
        if let Some(schedule) = &config.schedule
            && schedule.run_as == RunAs::System
            && !cfg!(windows)
        {
            bail!("[schedule].run_as: system is available only on Windows");
        }
        if let Some(repos) = &mut config.managed_repos {
            for folder in &mut repos.folders {
                if folder == Path::new("~") || folder.starts_with("~/") {
                    let home = user_home
                        .context("[managed_repos].folders: cannot expand ~ without a user home")?;
                    *folder = home.join(folder.strip_prefix("~").unwrap());
                }
                if !folder.is_absolute() {
                    bail!(
                        "[managed_repos].folders: {} must be absolute after ~ expansion",
                        folder.display()
                    );
                }
            }
        }
        Ok(config)
    }
}

pub(crate) fn example(
    manifest: &open_pact_core::Manifest,
    os: open_pact_core::Os,
    repo_scan: Option<&crate::checks::repos::RepoScan>,
    user_home: Option<&Path>,
) -> String {
    let mut output = String::from(
        "# Review this template. The client writes it only through `finish`, after your confirmation.\n",
    );
    let controls = &manifest.body().controls;
    let required = controls
        .iter()
        .filter_map(|control| {
            if !crate::checks::can_check(os, &control.id) {
                return None;
            }
            let requirement = control.required.get(&os)?;
            (requirement.to_string() != "n/a").then_some((control.id.as_str(), requirement))
        })
        .collect::<Vec<_>>();
    let reported = controls
        .iter()
        .filter(|control| {
            crate::checks::can_check(os, &control.id) && !control.required.contains_key(&os)
        })
        .map(|control| control.id.as_str())
        .collect::<Vec<_>>();
    let not_checked = controls
        .iter()
        .filter(|control| {
            !crate::checks::can_check(os, &control.id)
                || control
                    .required
                    .get(&os)
                    .is_some_and(|requirement| requirement.to_string() == "n/a")
        })
        .map(|control| control.id.as_str())
        .collect::<Vec<_>>();

    if !required.is_empty() {
        output.push_str(&format!("# Company requirements on {os}:\n"));
        let id_width = required.iter().map(|(id, _)| id.len()).max().unwrap_or(0);
        for (id, value) in required {
            output.push_str(&format!("#   {id:<id_width$}  {value}\n"));
        }
    }
    append_comment_list(&mut output, "Reported only, no requirement:", &reported);
    append_comment_list(&mut output, &format!("Not checked on {os}:"), &not_checked);
    output.push('\n');
    let (before_managed_repos, after_managed_repos) = CONFIG_TEMPLATE
        .split_once("[managed_repos]\n")
        .expect("configuration template has a managed repository section");
    output.push_str(before_managed_repos);
    append_managed_repo_comment(&mut output, repo_scan, user_home);
    output.push_str("[managed_repos]\n");
    output.push_str(after_managed_repos);
    output.push('\n');
    output
}

fn append_comment_list(output: &mut String, label: &str, ids: &[&str]) {
    if ids.is_empty() {
        return;
    }
    output.push_str(&format!("# {label}\n"));
    let mut line = String::from("#   ");
    for (index, id) in ids.iter().enumerate() {
        let item = if index == 0 {
            (*id).to_string()
        } else {
            format!(", {id}")
        };
        if line.len() + item.len() > 80 && line.len() > 4 {
            output.push_str(&line);
            output.push('\n');
            line = String::from("#   ");
            line.push_str(id);
        } else {
            line.push_str(&item);
        }
    }
    if line.len() > 4 {
        output.push_str(&line);
        output.push('\n');
    }
}

fn append_managed_repo_comment(
    output: &mut String,
    scan: Option<&crate::checks::repos::RepoScan>,
    user_home: Option<&Path>,
) {
    let Some(scan) = scan else {
        output.push_str("# Managed repository scan is unavailable.\n");
        return;
    };
    let Some(paths) = &scan.managed_paths else {
        output.push_str("# Managed repository locations are unavailable.\n");
        if scan.partial {
            output.push_str("# Managed repository scan was partial; results may be incomplete.\n");
        }
        return;
    };
    let groups = user_home.map_or_else(
        || {
            let mut groups = paths
                .iter()
                .map(|path| (path.display().to_string(), 1))
                .collect::<Vec<_>>();
            groups.sort_by(|left, right| left.0.cmp(&right.0));
            groups
        },
        |home| crate::checks::repos::managed_repo_groups(paths, home),
    );
    output.push_str(&format!(
        "# Managed repositories found: {}\n",
        scan.managed_repos_total
    ));
    for (path, count) in &groups {
        output.push_str(&format!("#   {} ({count})\n", safe_comment_text(path)));
    }
    if scan.partial {
        output.push_str("# Managed repository scan was partial; results may be incomplete.\n");
    }
    output.push_str("# Add the folders that should hold them to `folders`");
    if let Some((path, _)) = groups.first() {
        let path = serde_json::to_string(path).expect("a string serializes to JSON");
        output.push_str(&format!(", for example: folders = [{path}]"));
    }
    output.push_str(".\n");
}

pub(crate) fn managed_repo_summary(scan: &crate::checks::repos::RepoScan, home: &Path) -> String {
    let mut output = String::new();
    match &scan.managed_paths {
        Some(paths) if paths.is_empty() => output.push_str("  No managed repositories found.\n"),
        Some(paths) => {
            output.push_str(&format!(
                "  Found {} managed repositories:\n",
                scan.managed_repos_total
            ));
            for (path, count) in crate::checks::repos::managed_repo_groups(paths, home) {
                output.push_str(&format!("    {} ({count})\n", safe_comment_text(&path)));
            }
        }
        None => output.push_str("  Managed repository locations are unavailable.\n"),
    }
    if scan.partial {
        output.push_str("  Managed repository scan was partial; results may be incomplete.\n");
    }
    output
}

fn safe_comment_text(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                character.escape_default().to_string()
            } else {
                character.to_string()
            }
        })
        .collect()
}

pub(crate) fn print_table(
    manifest: &open_pact_core::Manifest,
    os: open_pact_core::Os,
    config: Option<&DeviceConfig>,
    results: &std::collections::BTreeMap<String, open_pact_core::ControlValue>,
) {
    println!("control | manifest requirement | device setting | result");
    for control in &manifest.body().controls {
        let requirement = control
            .required
            .get(&os)
            .map(ToString::to_string)
            .unwrap_or_else(|| "report only".into());
        let setting = if matches!(
            control.id.as_str(),
            "managed_repos_outside" | "managed_repos_total"
        ) {
            config
                .and_then(|config| config.managed_repos.as_ref())
                .map(|repos| format!("managed_repos.folders = {:?}", repos.folders))
                .unwrap_or_else(|| "-".into())
        } else {
            "-".into()
        };
        let result = results
            .get(&control.id)
            .map(ToString::to_string)
            .unwrap_or_else(|| "-".into());
        println!("{} | {requirement} | {setting} | {result}", control.id);
    }
    if let Some(repos) = config.and_then(|config| config.managed_repos.as_ref()) {
        println!("managed_repos.folders = {:?}", repos.folders);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_config_load_names_the_file_section_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_owned());
        assert!(DeviceConfig::load(&home).unwrap().is_none());
        std::fs::write(
            home.file(FILE),
            "[report]\ncollector = 'http://example.org'",
        )
        .unwrap();
        let error = format!("{:#}", DeviceConfig::load(&home).unwrap_err());
        assert!(
            error.contains(FILE) && error.contains("[report].collector"),
            "{error}"
        );
        std::fs::write(
            home.file(FILE),
            "[schedule]\nenabled = false\nrun_as = 'user'",
        )
        .unwrap();
        assert!(DeviceConfig::load(&home).unwrap().unwrap().report.is_none());
    }

    #[test]
    fn device_config_example_is_valid_and_names_every_manifest_control() {
        let manifest =
            open_pact_core::Manifest::parse(include_bytes!("../../../examples/manifest.toml"))
                .unwrap();
        let text = example(&manifest, open_pact_core::Os::Macos, None, None);
        let config = DeviceConfig::parse(&text, Some(Path::new("/home/example"))).unwrap();
        assert!(!config.schedule.unwrap().enabled);
        assert!(text.contains("# Company requirements on macos:"));
        assert!(text.contains("# Reported only, no requirement:"));
        assert!(text.contains("# Not checked on macos:"));
        assert!(!text.contains(" requires "));
        let grouped = text
            .lines()
            .skip_while(|line| !line.starts_with("# Company requirements"))
            .take_while(|line| !line.is_empty());
        assert!(grouped.into_iter().all(|line| line.len() <= 80));
        for control in &manifest.body().controls {
            assert!(text.contains(control.id.as_str()));
        }
    }

    #[test]
    fn device_config_example_groups_required_report_only_and_not_checked_controls() {
        let manifest_text = r#"
manifest_version = 1
issuer = "company.example"
valid_from = "2026-10-01"
claim_max_age = "24h"
claim_retention = "12mo"
claim_recipients = ["auditor@example.com"]
disclosed_metadata = ["manifest_hash", "device_pseudonym", "device_key", "nonce", "time", "client_version", "os", "trust_level", "vpn_certificate_request", "virtualized", "log_checkpoint"]
data_controller = "Company Ltd., dpo@company.example"
min_trust_level = "L0"
unknown_grace = "7d"

[log]
allow_split_views = true
witness_quorum = 0
checkpoint_max_age = "1h"

[[control]]
id = "firewall"
source = "company_policy"
check = "builtin:firewall@1"
output = ["on", "off", "unknown"]
required = { macos = "on" }
grace = "0d"

[[control]]
id = "screen_lock"
source = "company_policy"
check = "builtin:screen_lock@1"
output = ["on", "off", "unknown"]
required = {}
grace = "0d"

[[control]]
id = "disk_encryption"
source = "company_policy"
check = "builtin:disk_encryption@1"
output = ["on", "off", "unknown"]
required = { linux = "on" }
grace = "0d"

[[control]]
id = "log_cleared"
source = "company_policy"
check = "builtin:log_cleared@1"
output = ["n/a", "unknown"]
required = { macos = "n/a" }
grace = "0d"

[[control]]
id = "powershell_logging"
source = "company_policy"
check = "builtin:powershell_logging@1"
output = ["on", "off", "n/a", "unknown"]
required = { windows = "on" }
grace = "0d"
"#;
        let manifest = open_pact_core::Manifest::parse(manifest_text.as_bytes()).unwrap();
        let text = example(&manifest, open_pact_core::Os::Macos, None, None);
        let expected = concat!(
            "# Company requirements on macos:\n",
            "#   firewall  on\n",
            "# Reported only, no requirement:\n",
            "#   screen_lock, disk_encryption\n",
            "# Not checked on macos:\n",
            "#   log_cleared, powershell_logging\n",
        );
        assert!(text.contains(expected), "{text}");
        assert!(!text.contains("# Company requirements on macos:\n#   \n"));
        assert!(!text.contains("# Not checked on macos:\n#   \n"));

        let required_on_current_os = manifest_text.replace(
            "required = { windows = \"on\" }",
            "required = { macos = \"on\" }",
        );
        let manifest = open_pact_core::Manifest::parse(required_on_current_os.as_bytes()).unwrap();
        let text = example(&manifest, open_pact_core::Os::Macos, None, None);
        assert!(
            text.contains("# Not checked on macos:\n#   log_cleared, powershell_logging\n"),
            "{text}"
        );
        assert!(!text.contains("# Company requirements on macos:\n#   powershell_logging"));
    }

    #[test]
    fn device_config_example_groups_repositories_at_home_as_home() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        for repo in ["app-one", "app-two"] {
            let git = home.join(repo).join(".git");
            std::fs::create_dir_all(&git).unwrap();
            std::fs::write(
                git.join("config"),
                "[remote \"origin\"]\n url = git@github.com:example-org/app.git\n",
            )
            .unwrap();
        }
        let scan = crate::checks::repos::scan_and_store(
            &temp.path().join("client"),
            &home,
            &[],
            &["github.com/example-org/".to_string()],
        )
        .unwrap();
        let manifest =
            open_pact_core::Manifest::parse(include_bytes!("../../../examples/manifest.toml"))
                .unwrap();
        let proposal = example(
            &manifest,
            open_pact_core::Os::Macos,
            Some(&scan),
            Some(&home),
        );
        assert!(
            proposal.contains("# Managed repositories found: 2\n#   ~ (2)\n"),
            "{proposal}"
        );
        assert!(!proposal.contains("~/~"));
    }

    #[test]
    fn device_config_example_shows_managed_repositories_from_a_fake_home_scan() {
        let manifest =
            open_pact_core::Manifest::parse(include_bytes!("../../../examples/manifest.toml"))
                .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        for path in ["work/one", "work/two", "clients/three"] {
            let repo = home.join(path);
            std::fs::create_dir_all(repo.join(".git")).unwrap();
            std::fs::write(
                repo.join(".git/config"),
                "[remote \"origin\"]\n url = git@github.com:example-org/app.git\n",
            )
            .unwrap();
        }
        let scan = crate::checks::repos::scan_and_store(
            &temp.path().join("client"),
            &home,
            &[],
            &["github.com/example-org/".to_string()],
        )
        .unwrap();
        let text = example(
            &manifest,
            open_pact_core::Os::Macos,
            Some(&scan),
            Some(&home),
        );
        assert!(
            text.contains("# Managed repositories found: 3\n#   ~/work (2)\n#   ~/clients (1)\n")
        );
        assert!(text.contains(
            "# Add the folders that should hold them to `folders`, for example: folders = [\"~/work\"]"
        ));
        let hint = text
            .find("# Add the folders that should hold them")
            .unwrap();
        let section = text.find("[managed_repos]\n").unwrap();
        assert!(hint < section);
        let folder_setting = text[section + "[managed_repos]\n".len()..]
            .lines()
            .find(|line| !line.starts_with('#') && !line.is_empty());
        assert_eq!(folder_setting, Some("folders = []"));
    }

    #[test]
    fn device_config_example_groups_shared_first_level_and_counts_managed_paths() {
        let manifest =
            open_pact_core::Manifest::parse(include_bytes!("../../../examples/manifest.toml"))
                .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        for path in ["code/work/one", "code/personal/two"] {
            let repo = home.join(path);
            std::fs::create_dir_all(repo.join(".git")).unwrap();
            std::fs::write(
                repo.join(".git/config"),
                "[remote \"origin\"]\n url = git@github.com:example-org/app.git\n",
            )
            .unwrap();
        }
        let scan = crate::checks::repos::scan_and_store(
            &temp.path().join("client"),
            &home,
            &[home.join("code")],
            &["github.com/example-org/".to_string()],
        )
        .unwrap();
        assert_eq!(scan.managed_repos_outside, 0);
        assert_eq!(scan.managed_repos_total, 2);
        let text = example(
            &manifest,
            open_pact_core::Os::Macos,
            Some(&scan),
            Some(&home),
        );
        assert!(text.contains("# Managed repositories found: 2\n#   ~/code (2)\n"));
    }

    #[test]
    fn device_config_example_suggests_the_largest_group_with_toml_escaping() {
        let manifest =
            open_pact_core::Manifest::parse(include_bytes!("../../../examples/manifest.toml"))
                .unwrap();
        let home = Path::new("/home/example");
        let scan = crate::checks::repos::RepoScan {
            scanned_at: 0,
            managed_repos_outside: 3,
            managed_repos_total: 3,
            outside_paths: Vec::new(),
            managed_paths: Some(vec![
                home.join("large\"group/a"),
                home.join("large\"group/b"),
                home.join("small/c"),
            ]),
            partial: false,
            access_denied: false,
            causes: Vec::new(),
        };

        let text = example(
            &manifest,
            open_pact_core::Os::Macos,
            Some(&scan),
            Some(home),
        );

        assert!(text.contains(
            "# Add the folders that should hold them to `folders`, for example: folders = [\"~/large\\\"group\"].\n"
        ), "{text}");
        assert!(text.contains("#   ~/large\"group (2)\n#   ~/small (1)\n"));
    }

    #[test]
    fn device_config_example_omits_folder_example_when_no_groups_exist() {
        let manifest =
            open_pact_core::Manifest::parse(include_bytes!("../../../examples/manifest.toml"))
                .unwrap();
        let scan = crate::checks::repos::RepoScan {
            scanned_at: 0,
            managed_repos_outside: 0,
            managed_repos_total: 0,
            outside_paths: Vec::new(),
            managed_paths: Some(Vec::new()),
            partial: false,
            access_denied: false,
            causes: Vec::new(),
        };

        let text = example(&manifest, open_pact_core::Os::Macos, Some(&scan), None);

        assert!(text.contains("# Add the folders that should hold them to `folders`.\n"));
        assert!(!text.contains("for example: folders"));
    }

    #[cfg(unix)]
    #[test]
    fn device_config_example_escapes_control_characters_in_repository_locations() {
        let manifest =
            open_pact_core::Manifest::parse(include_bytes!("../../../examples/manifest.toml"))
                .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let repo = home.join("work\nunexpected = 1\n#/repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(
            repo.join(".git/config"),
            "[remote \"origin\"]\n url = git@github.com:example-org/app.git\n",
        )
        .unwrap();
        let scan = crate::checks::repos::scan_and_store(
            &temp.path().join("client"),
            &home,
            &[],
            &["github.com/example-org/".to_string()],
        )
        .unwrap();
        let text = example(
            &manifest,
            open_pact_core::Os::Macos,
            Some(&scan),
            Some(&home),
        );
        assert!(
            text.contains("#   ~/work\\nunexpected = 1\\n# (1)\n"),
            "{text}"
        );
        DeviceConfig::parse(&text, Some(&home)).unwrap();
    }

    #[test]
    fn device_config_example_reports_unavailable_and_partial_repository_scans() {
        let manifest =
            open_pact_core::Manifest::parse(include_bytes!("../../../examples/manifest.toml"))
                .unwrap();
        let missing = example(&manifest, open_pact_core::Os::Macos, None, None);
        assert!(missing.contains("# Managed repository scan is unavailable.\n"));

        let home = Path::new("/home/example");
        let partial = crate::checks::repos::RepoScan {
            scanned_at: chrono::Utc::now().timestamp(),
            managed_repos_outside: 0,
            managed_repos_total: 2,
            outside_paths: Vec::new(),
            managed_paths: Some(vec![home.join("work/one"), home.join("archive/work/two")]),
            partial: true,
            access_denied: false,
            causes: Vec::new(),
        };
        let text = example(
            &manifest,
            open_pact_core::Os::Macos,
            Some(&partial),
            Some(home),
        );
        assert!(
            text.contains("# Managed repository scan was partial; results may be incomplete.\n")
        );
        assert!(text.contains(
            "# Managed repositories found: 2\n#   ~/archive (1)\n#   ~/work (1)\n# Managed repository scan was partial; results may be incomplete.\n"
        ));

        let old = crate::checks::repos::RepoScan {
            scanned_at: chrono::Utc::now().timestamp(),
            managed_repos_outside: 0,
            managed_repos_total: 2,
            outside_paths: Vec::new(),
            managed_paths: None,
            partial: false,
            access_denied: false,
            causes: Vec::new(),
        };
        let text = example(
            &manifest,
            open_pact_core::Os::Macos,
            Some(&old),
            Some(Path::new("/home/example")),
        );
        assert!(text.contains("# Managed repository locations are unavailable.\n"));
        assert!(!text.contains("# Managed repositories found: 0"));
    }

    #[test]
    fn step_four_summary_groups_paths_and_places_the_partial_note_last() {
        let home = Path::new("/home/example");
        let scan = crate::checks::repos::RepoScan {
            scanned_at: chrono::Utc::now().timestamp(),
            managed_repos_outside: 3,
            managed_repos_total: 3,
            outside_paths: Vec::new(),
            managed_paths: Some(vec![
                home.join("work/one"),
                home.join("work/two"),
                home.join("archive/work/three"),
            ]),
            partial: true,
            access_denied: false,
            causes: Vec::new(),
        };
        let text = managed_repo_summary(&scan, home);
        assert_eq!(
            text,
            concat!(
                "  Found 3 managed repositories:\n",
                "    ~/work (2)\n",
                "    ~/archive (1)\n",
                "  Managed repository scan was partial; results may be incomplete.\n",
            )
        );
    }

    #[test]
    fn step_four_summary_reports_no_repositories_and_unavailable_paths() {
        let empty = crate::checks::repos::RepoScan {
            scanned_at: chrono::Utc::now().timestamp(),
            managed_repos_outside: 0,
            managed_repos_total: 0,
            outside_paths: Vec::new(),
            managed_paths: Some(Vec::new()),
            partial: false,
            access_denied: false,
            causes: Vec::new(),
        };
        assert_eq!(
            managed_repo_summary(&empty, Path::new("/home/example")),
            "  No managed repositories found.\n"
        );
        let unavailable = crate::checks::repos::RepoScan {
            managed_paths: None,
            ..empty
        };
        assert_eq!(
            managed_repo_summary(&unavailable, Path::new("/home/example")),
            "  Managed repository locations are unavailable.\n"
        );
    }

    #[test]
    fn device_config_sections_and_expansion_need_no_filesystem() {
        let user_home = if cfg!(windows) {
            Path::new(r"C:\Users\example")
        } else {
            Path::new("/home/example")
        };
        let absolute = user_home.join("work");
        let text = format!(
            r#"
[report]
collector = "https://collector.example.org/status"
[schedule]
enabled = true
run_as = "user"
[managed_repos]
folders = ['~/missing', '{}']
"#,
            absolute.display()
        );
        let config = DeviceConfig::parse(&text, Some(user_home)).unwrap();
        assert_eq!(config.report.unwrap().probe(), "collector.example.org:443");
        assert_eq!(
            config.managed_repos.unwrap().folders,
            [user_home.join("missing"), absolute]
        );
        assert_eq!(
            DeviceConfig::parse("", None).unwrap(),
            DeviceConfig::default()
        );
    }

    #[test]
    fn device_config_rejects_unknown_keys_and_bad_values() {
        for (text, key) in [
            ("other = 1", "other"),
            ("[report]\ncollector = 'http://example.org'", "collector"),
            (
                "[report]\ncollector = 'https://example.org'\nvpn_probe = 'bad'",
                "vpn_probe",
            ),
            (
                "[report]\ncollector = 'https://example.org'\nextra = 1",
                "extra",
            ),
            ("[schedule]\nenabled = true\nrun_as = 'root'", "run_as"),
            (
                "[schedule]\nenabled = true\nrun_as = 'user'\nextra = 1",
                "extra",
            ),
            ("[managed_repos]\nfolders = ['relative']", "folders"),
            ("[managed_repos]\nfolders = []\nextra = 1", "extra"),
        ] {
            let error = format!("{:#}", DeviceConfig::parse(text, None).unwrap_err());
            assert!(error.contains(key), "{error}");
        }
    }

    #[test]
    fn device_config_probe_defaults_include_ipv6_and_explicit_port() {
        for (collector, expected) in [
            ("https://[::1]:8443/status", "[::1]:8443"),
            ("https://example.org:8443/status", "example.org:8443"),
        ] {
            let config =
                DeviceConfig::parse(&format!("[report]\ncollector = '{collector}'"), None).unwrap();
            assert_eq!(config.report.unwrap().probe(), expected);
        }
    }
}
