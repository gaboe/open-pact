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

/// Where the notice about the ignored `open-pact.toml` was already shown. It has its own file, so a
/// notice never writes the owner's choices.
const NOTICE_FILE: &str = "legacy-notice.json";

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
    /// The owner went through wizard step 5, so `join` does not ask again. A file that an import
    /// or a command created leaves it false.
    #[serde(default)]
    pub(crate) setup_answered: bool,
}

impl DeviceConfig {
    /// No file means no choices yet.
    pub(crate) fn load(home: &Home) -> Result<Self> {
        Ok(home.read_json(FILE)?.unwrap_or_default())
    }

    /// `load`, and on the first read of a home without `device.json` it carries over what an
    /// earlier client kept: the repository folders in `open-pact.toml` (the owner's own choice)
    /// and a SYSTEM job on Windows. `persist` saves the result; a preview leaves the home alone.
    pub(crate) fn load_or_migrate(
        home: &Home,
        user_home: Option<&Path>,
        persist: bool,
    ) -> Result<Self> {
        Self::migrate(home, user_home, persist, cfg!(windows))
    }

    fn migrate(
        home: &Home,
        user_home: Option<&Path>,
        persist: bool,
        windows: bool,
    ) -> Result<Self> {
        if let Some(config) = home.read_json(FILE)? {
            return Ok(config);
        }
        let profile = crate::user_profile();
        let folders = legacy_folders(home, user_home.or(profile.as_deref()));
        let system = windows && installed_system_job(home);
        let mut config = Self::default();
        if folders.is_empty() && !system {
            return Ok(config);
        }
        config.folders = folders;
        if system {
            config.run_as = RunAs::System;
        }
        if persist {
            config.save(home)?;
        }
        Ok(config)
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

/// A SYSTEM job that an earlier client installed: its `schedule-applied.json` or its settings file
/// says so.
fn installed_system_job(home: &Home) -> bool {
    let applied = home
        .read_json::<serde_json::Value>(crate::schedule::APPLIED)
        .ok()
        .flatten();
    applied.is_some_and(|applied| applied["run_as"] == "system")
        || legacy_value(home).is_some_and(|value| {
            value
                .get("schedule")
                .and_then(|table| table.get("run_as"))
                .and_then(toml::Value::as_str)
                == Some("system")
        })
}

/// What to tell the owner, once per surface, when an `open-pact.toml` still sits in the home.
/// `config` is what the client read of the owner's choices after it carried the old ones over.
pub(crate) fn legacy_notice(
    home: &Home,
    surface: Surface,
    command: &str,
    config: &DeviceConfig,
) -> Option<String> {
    let value = legacy_value(home)?;
    let mut given: LegacyNoticeGiven = home
        .read_json(NOTICE_FILE)
        .ok()
        .flatten()
        .unwrap_or_default();
    let flag = match surface {
        Surface::Check => &mut given.check,
        Surface::Job => &mut given.job,
    };
    if *flag {
        return None;
    }
    *flag = true;
    if let Ok(bytes) = serde_json::to_vec(&given) {
        let _ = home.write(NOTICE_FILE, &bytes);
    }
    let has = |table: &str, key: &str| value.get(table).and_then(|table| table.get(key)).is_some();
    let mut lines = vec![format!(
        "{LEGACY_FILE} is ignored now. This client keeps your choices in {FILE}, and the company's signed manifest holds the rest:"
    )];
    if has("schedule", "enabled") || has("schedule", "run_as") {
        lines.push(format!(
            "  [schedule] enabled, run_as: turn automatic sending on with `{command} schedule on`; on Windows add `--user` or `--system`"
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
        lines.push(if config.folders.is_empty() {
            format!(
                "  [managed_repos] folders: run `{command} folders add <path>` for each; the setup wizard offers to import them"
            )
        } else {
            format!(
                "  [managed_repos] folders: imported into {FILE} because they were your choice; `{command} folders list` shows them and `{command} folders remove <path>` drops one"
            )
        });
    }
    if config.run_as == RunAs::System {
        lines.push(format!(
            "  An installed SYSTEM job was found. It keeps running the old client copy until you replace it. From an elevated PowerShell prompt run:\n    {}",
            crate::schedule::apply_command(&home.0, "schedule on --system")
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

/// The folders that hold the managed repositories a scan found. A folder whose name needs escaping
/// is left out, so it never reaches a prompt as something the owner did not type.
pub(crate) fn suggested_folders(
    scan: &crate::checks::repos::RepoScan,
    user_home: &Path,
) -> Vec<PathBuf> {
    let Some(paths) = &scan.managed_paths else {
        return Vec::new();
    };
    crate::checks::repos::managed_repo_groups(paths, user_home)
        .into_iter()
        .filter_map(|(group, _)| {
            let folder = match group.strip_prefix("~/") {
                Some(rest) => user_home.join(rest),
                None => user_home.to_path_buf(),
            };
            (safe_comment_text(&folder.display().to_string()) == folder.display().to_string())
                .then_some(folder)
        })
        .collect()
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
        let config = DeviceConfig::default();
        assert_eq!(
            legacy_notice(&home, Surface::Check, "client", &config),
            None
        );
        std::fs::write(
            home.file(LEGACY_FILE),
            "[schedule]\nenabled = true\nrun_as = 'user'\nmode = 'vpn'\nvpn_probe = '10.0.0.1:443'\n[managed_repos]\nfolders = ['/work']\n[report]\ncollector = 'https://collector.example.org'\n",
        )
        .unwrap();
        let notice = legacy_notice(&home, Surface::Check, "client", &config).unwrap();
        for expected in [
            "open-pact.toml is ignored now",
            "[schedule] enabled, run_as: turn automatic sending on with `client schedule on`",
            "[schedule] mode, vpn_probe, vpn_probe_name: the company sets them",
            "[managed_repos] folders: run `client folders add <path>`",
            "[report]: removed",
        ] {
            assert!(notice.contains(expected), "{notice}");
        }
        assert!(
            !notice.contains("asks for"),
            "`schedule on` takes flags and asks nothing: {notice}"
        );
        assert_eq!(
            legacy_notice(&home, Surface::Check, "client", &config),
            None
        );
        assert!(legacy_notice(&home, Surface::Job, "client", &config).is_some());
        assert_eq!(legacy_notice(&home, Surface::Job, "client", &config), None);
        assert!(home.file(LEGACY_FILE).exists(), "the owner's file stays");
        assert!(
            !home.file(FILE).exists(),
            "the notice flags have their own file and never create device.json"
        );
        assert!(home.file(NOTICE_FILE).exists());
    }

    #[test]
    fn the_notice_says_when_the_old_folders_were_imported() {
        let (_dir, home) = home();
        std::fs::write(
            home.file(LEGACY_FILE),
            "[managed_repos]\nfolders = ['/work']\n",
        )
        .unwrap();
        let config = DeviceConfig {
            folders: vec![PathBuf::from("/work")],
            ..DeviceConfig::default()
        };
        let notice = legacy_notice(&home, Surface::Check, "client", &config).unwrap();
        assert!(
            notice.contains("imported into device.json")
                && notice.contains("client folders remove <path>")
                && !notice.contains("folders add"),
            "{notice}"
        );
    }

    #[test]
    fn an_unparseable_toml_is_still_ignored_with_a_notice() {
        let (_dir, home) = home();
        std::fs::write(home.file(LEGACY_FILE), "[managed_repos\n").unwrap();
        let notice =
            legacy_notice(&home, Surface::Check, "client", &DeviceConfig::default()).unwrap();
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
        let user_home = Path::new("/home/example");
        assert_eq!(
            legacy_folders(&home, Some(user_home)),
            vec![
                user_home.join("work"),
                std::path::absolute("/srv/code").unwrap()
            ]
        );
    }

    #[test]
    fn the_first_read_carries_the_old_folders_into_device_json() {
        let (_dir, home) = home();
        let user_home = Path::new("/home/example");
        std::fs::write(
            home.file(LEGACY_FILE),
            "[managed_repos]\nfolders = ['~/work']\n",
        )
        .unwrap();
        let preview = DeviceConfig::migrate(&home, Some(user_home), false, false).unwrap();
        assert_eq!(preview.folders, vec![user_home.join("work")]);
        assert!(!home.file(FILE).exists(), "a preview writes nothing");

        let config = DeviceConfig::migrate(&home, Some(user_home), true, false).unwrap();
        assert_eq!(config.folders, vec![user_home.join("work")]);
        assert!(!config.auto_send && !config.setup_answered);
        assert_eq!(DeviceConfig::load(&home).unwrap(), config);

        let mut chosen = DeviceConfig::load(&home).unwrap();
        chosen.folders.clear();
        chosen.save(&home).unwrap();
        let again = DeviceConfig::migrate(&home, Some(user_home), true, false).unwrap();
        assert!(again.folders.is_empty(), "an existing device.json wins");
    }

    #[test]
    fn a_home_with_nothing_to_carry_over_gets_no_device_json() {
        let (_dir, home) = home();
        assert_eq!(
            DeviceConfig::migrate(&home, None, true, true).unwrap(),
            DeviceConfig::default()
        );
        std::fs::write(home.file(LEGACY_FILE), "[schedule]\nenabled = true\n").unwrap();
        DeviceConfig::migrate(&home, None, true, true).unwrap();
        assert!(!home.file(FILE).exists());
    }

    #[test]
    fn an_installed_system_job_keeps_run_as_system_on_windows() {
        for (name, content) in [
            (
                crate::schedule::APPLIED,
                "{\"run_as\":\"system\",\"executable\":\"C:/old/open-pact-client.exe\"}",
            ),
            (
                LEGACY_FILE,
                "[schedule]\nenabled = true\nrun_as = 'system'\n",
            ),
        ] {
            let (_dir, home) = home();
            std::fs::write(home.file(name), content).unwrap();
            let config = DeviceConfig::migrate(&home, None, true, true).unwrap();
            assert_eq!(config.run_as, RunAs::System, "{name}");
            assert_eq!(DeviceConfig::load(&home).unwrap().run_as, RunAs::System);
            let (_other_dir, other) = self::home();
            std::fs::write(other.file(name), content).unwrap();
            let elsewhere = DeviceConfig::migrate(&other, None, false, false).unwrap();
            assert_eq!(
                elsewhere.run_as,
                RunAs::User,
                "only Windows has SYSTEM jobs"
            );
        }
        let (_dir, home) = home();
        std::fs::write(home.file(crate::schedule::APPLIED), "{\"run_as\":\"user\"}").unwrap();
        assert_eq!(
            DeviceConfig::migrate(&home, None, true, true)
                .unwrap()
                .run_as,
            RunAs::User
        );
    }

    #[test]
    fn the_notice_names_the_elevated_command_for_a_system_job() {
        let (_dir, home) = home();
        std::fs::write(
            home.file(LEGACY_FILE),
            "[schedule]\nenabled = true\nrun_as = 'system'\n",
        )
        .unwrap();
        let config = DeviceConfig {
            run_as: RunAs::System,
            ..DeviceConfig::default()
        };
        let notice = legacy_notice(&home, Surface::Job, "client", &config).unwrap();
        assert!(
            notice.contains("elevated")
                && notice.contains("schedule on --system")
                && notice.contains(&home.0.to_string_lossy().into_owned()),
            "{notice}"
        );
    }

    #[test]
    fn repository_paths_with_control_characters_are_escaped_and_never_suggested() {
        let home = Path::new("/home/example");
        let scan = crate::checks::repos::RepoScan {
            scanned_at: chrono::Utc::now().timestamp(),
            managed_repos_outside: 2,
            managed_repos_total: 2,
            outside_paths: Vec::new(),
            managed_paths: Some(vec![
                home.join("work\nunexpected = 1\n#/repo"),
                home.join("plain/repo"),
            ]),
            partial: false,
            access_denied: false,
            causes: Vec::new(),
        };
        let overview = managed_repo_summary(&scan, home);
        assert!(
            overview.contains("    ~/work\\nunexpected = 1\\n# (1)\n"),
            "{overview}"
        );
        assert_eq!(overview.lines().count(), 3, "no raw newline from a path");
        assert_eq!(suggested_folders(&scan, home), vec![home.join("plain")]);
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
