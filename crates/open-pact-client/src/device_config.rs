use std::path::{Path, PathBuf};

use crate::Home;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// The owner's own choices, kept by the client. The owner changes them through the wizard and the
/// `schedule` and `folders` commands, never by editing the file.
pub(crate) const FILE: &str = "device.json";
/// The settings file of an earlier client. It is read only to explain where its values went and to
/// offer its repository folders.
pub(crate) const LEGACY_FILE: &str = "open-pact.toml";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RunAs {
    #[default]
    User,
    System,
}

/// Where the notice about the ignored `open-pact.toml` was already shown.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
struct LegacyNoticeGiven {
    #[serde(default)]
    check: bool,
    #[serde(default)]
    job: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Surface {
    Check,
    Job,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceConfig {
    /// The owner agreed to the automatic sending that the signed manifest describes.
    #[serde(default)]
    pub(crate) auto_send: bool,
    /// Windows only: who runs the scheduled job.
    #[serde(default)]
    pub(crate) run_as: RunAs,
    /// Absolute folders that hold the owner's managed repositories.
    #[serde(default)]
    pub(crate) folders: Vec<PathBuf>,
    #[serde(default)]
    legacy_notice: LegacyNoticeGiven,
}

impl DeviceConfig {
    /// No file means no choices yet.
    pub(crate) fn load(home: &Home) -> Result<Self> {
        Ok(home.read_json(FILE)?.unwrap_or_default())
    }

    pub(crate) fn save(&self, home: &Home) -> Result<()> {
        home.write(FILE, &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    /// Adds a folder. Returns `false` when it was already listed.
    pub(crate) fn add_folder(&mut self, folder: PathBuf) -> bool {
        if self.folders.contains(&folder) {
            return false;
        }
        self.folders.push(folder);
        true
    }

    /// Removes a folder. Returns `false` when it was not listed.
    pub(crate) fn remove_folder(&mut self, folder: &Path) -> bool {
        let before = self.folders.len();
        self.folders.retain(|listed| listed != folder);
        self.folders.len() != before
    }
}

/// Turns what the owner typed into an absolute folder: `~` is the owner's home and a relative path
/// starts at the current directory.
pub(crate) fn absolute_folder(raw: &Path, user_home: Option<&Path>) -> Result<PathBuf> {
    if raw == Path::new("~") || raw.starts_with("~/") {
        let home = user_home.context("cannot expand ~ without a user home")?;
        return Ok(home.join(raw.strip_prefix("~").expect("checked prefix")));
    }
    if raw.as_os_str().is_empty() {
        bail!("a folder must not be empty");
    }
    std::path::absolute(raw).with_context(|| format!("make {} absolute", raw.display()))
}

fn legacy_value(home: &Home) -> Option<toml::Value> {
    let bytes = crate::read_home_file(&home.file(LEGACY_FILE)).ok()?;
    Some(toml::Value::Table(
        String::from_utf8(bytes)
            .ok()
            .and_then(|text| toml::from_str::<toml::Table>(&text).ok())
            .unwrap_or_default(),
    ))
}

/// What to tell the owner, once per surface, when an `open-pact.toml` still sits in the home.
pub(crate) fn legacy_notice(home: &Home, surface: Surface, command: &str) -> Option<String> {
    let value = legacy_value(home)?;
    let mut config = DeviceConfig::load(home).ok()?;
    let given = match surface {
        Surface::Check => &mut config.legacy_notice.check,
        Surface::Job => &mut config.legacy_notice.job,
    };
    if *given {
        return None;
    }
    *given = true;
    let _ = config.save(home);
    let has = |table: &str, key: &str| value.get(table).and_then(|table| table.get(key)).is_some();
    let mut lines = vec![format!(
        "{LEGACY_FILE} is ignored now. This client keeps your choices in {FILE}, and the company's signed manifest holds the rest:"
    )];
    if has("schedule", "enabled") || has("schedule", "run_as") {
        lines.push(format!(
            "  [schedule] enabled, run_as: `{command} schedule on` asks for them"
        ));
    }
    if has("schedule", "mode") || has("schedule", "vpn_probe") || has("schedule", "vpn_probe_name")
    {
        lines.push(
            "  [schedule] mode, vpn_probe, vpn_probe_name: the company sets them in the signed manifest"
                .into(),
        );
    }
    if has("managed_repos", "folders") {
        lines.push(format!(
            "  [managed_repos] folders: run `{command} folders add <path>`; the setup wizard offers to import them"
        ));
    }
    if value.get("report").is_some() {
        lines.push("  [report]: removed; the gateway receives claims".into());
    }
    lines.push(format!(
        "The file stays where it is. Delete it when you no longer need it: {}",
        home.file(LEGACY_FILE).display()
    ));
    Some(lines.join("\n"))
}

/// The repository folders of an earlier `open-pact.toml`, as absolute paths.
pub(crate) fn legacy_folders(home: &Home, user_home: Option<&Path>) -> Vec<PathBuf> {
    let Some(value) = legacy_value(home) else {
        return Vec::new();
    };
    value
        .get("managed_repos")
        .and_then(|table| table.get("folders"))
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .filter_map(|folder| absolute_folder(Path::new(folder), user_home).ok())
        .collect()
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

pub(crate) fn safe_comment_text(text: &str) -> String {
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
                .map(|config| format!("folders = {:?}", config.folders))
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
    if let Some(config) = config.filter(|config| !config.folders.is_empty()) {
        println!("repository folders = {:?}", config.folders);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> (tempfile::TempDir, Home) {
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_owned());
        (dir, home)
    }

    #[test]
    fn a_missing_file_means_no_choices_yet() {
        let (_dir, home) = home();
        assert_eq!(DeviceConfig::load(&home).unwrap(), DeviceConfig::default());
        assert!(!DeviceConfig::default().auto_send);
    }

    #[test]
    fn choices_survive_a_save_and_load() {
        let (_dir, home) = home();
        let mut config = DeviceConfig {
            auto_send: true,
            run_as: RunAs::System,
            ..DeviceConfig::default()
        };
        assert!(config.add_folder(PathBuf::from("/work")));
        assert!(!config.add_folder(PathBuf::from("/work")));
        config.save(&home).unwrap();
        assert_eq!(DeviceConfig::load(&home).unwrap(), config);
        assert!(config.remove_folder(Path::new("/work")));
        assert!(!config.remove_folder(Path::new("/work")));
    }

    #[test]
    fn a_damaged_file_names_itself() {
        let (_dir, home) = home();
        std::fs::write(home.file(FILE), "{\"unknown\": 1}").unwrap();
        let error = format!("{:#}", DeviceConfig::load(&home).unwrap_err());
        assert!(error.contains(FILE), "{error}");
    }

    #[test]
    fn folders_become_absolute() {
        let user_home = Path::new("/home/example");
        assert_eq!(
            absolute_folder(Path::new("~/work"), Some(user_home)).unwrap(),
            PathBuf::from("/home/example/work")
        );
        assert_eq!(
            absolute_folder(Path::new("~"), Some(user_home)).unwrap(),
            PathBuf::from("/home/example")
        );
        assert!(absolute_folder(Path::new("~/work"), None).is_err());
        assert!(absolute_folder(Path::new(""), None).is_err());
        assert!(
            absolute_folder(Path::new("work"), None)
                .unwrap()
                .is_absolute()
        );
    }

    #[test]
    fn the_ignored_toml_is_explained_once_per_surface() {
        let (_dir, home) = home();
        assert_eq!(legacy_notice(&home, Surface::Check, "client"), None);
        std::fs::write(
            home.file(LEGACY_FILE),
            "[schedule]\nenabled = true\nrun_as = 'user'\nmode = 'vpn'\nvpn_probe = '10.0.0.1:443'\n[managed_repos]\nfolders = ['/work']\n[report]\ncollector = 'https://collector.example.org'\n",
        )
        .unwrap();
        let notice = legacy_notice(&home, Surface::Check, "client").unwrap();
        for expected in [
            "open-pact.toml is ignored now",
            "[schedule] enabled, run_as: `client schedule on`",
            "[schedule] mode, vpn_probe, vpn_probe_name: the company sets them",
            "[managed_repos] folders: run `client folders add <path>`",
            "[report]: removed",
        ] {
            assert!(notice.contains(expected), "{notice}");
        }
        assert_eq!(legacy_notice(&home, Surface::Check, "client"), None);
        assert!(legacy_notice(&home, Surface::Job, "client").is_some());
        assert_eq!(legacy_notice(&home, Surface::Job, "client"), None);
        assert!(home.file(LEGACY_FILE).exists(), "the owner's file stays");
    }

    #[test]
    fn an_unparseable_toml_is_still_ignored_with_a_notice() {
        let (_dir, home) = home();
        std::fs::write(home.file(LEGACY_FILE), "[managed_repos\n").unwrap();
        let notice = legacy_notice(&home, Surface::Check, "client").unwrap();
        assert!(notice.contains("ignored now") && !notice.contains("folders add"));
        assert!(legacy_folders(&home, None).is_empty());
    }

    #[test]
    fn the_old_repository_folders_can_be_imported() {
        let (_dir, home) = home();
        std::fs::write(
            home.file(LEGACY_FILE),
            "[managed_repos]\nfolders = ['~/work', '/srv/code']\n",
        )
        .unwrap();
        assert_eq!(
            legacy_folders(&home, Some(Path::new("/home/example"))),
            vec![
                PathBuf::from("/home/example/work"),
                PathBuf::from("/srv/code")
            ]
        );
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
}
