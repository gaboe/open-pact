use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use toml_edit::{DocumentMut, Item, Table, TableLike, value};

use crate::{Home, report, schedule};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Conflict {
    pub(crate) key: String,
    pub(crate) company_value: String,
    pub(crate) file_value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Merge {
    pub(crate) text: String,
    pub(crate) added: Vec<String>,
    pub(crate) conflicts: Vec<Conflict>,
}

pub(crate) fn merge(
    manifest: &open_pact_core::Manifest,
    os: open_pact_core::Os,
    company: Option<&open_pact_core::ReportDefaults>,
    existing: Option<&str>,
) -> Merge {
    let mut text = existing
        .map(str::to_owned)
        .unwrap_or_else(|| example(manifest, os));
    if company.is_none() {
        return Merge {
            text,
            added: Vec::new(),
            conflicts: Vec::new(),
        };
    }
    let mut document = match text.parse::<DocumentMut>() {
        Ok(document) => document,
        Err(error) => {
            return Merge {
                text,
                added: Vec::new(),
                conflicts: vec![Conflict {
                    key: FILE.into(),
                    company_value: "company defaults".into(),
                    file_value: format!("cannot parse TOML: {error}"),
                }],
            };
        }
    };
    let mut added = Vec::new();
    let mut conflicts = Vec::new();
    if let Some(company) = company {
        let report_exists = document.contains_key("report");
        if report_exists && !document["report"].is_table_like() {
            conflicts.push(Conflict {
                key: "[report]".into(),
                company_value: "table".into(),
                file_value: document["report"].to_string().trim().to_owned(),
            });
        } else {
            if !report_exists {
                document["report"] = Item::Table(Table::new());
                added.push("[report]".into());
            }
            let report = document["report"]
                .as_table_like_mut()
                .expect("report table created");
            merge_report_value(
                report,
                "collector",
                &company.collector,
                existing.is_none(),
                &mut added,
                &mut conflicts,
            );
            if let Some(vpn_probe) = &company.vpn_probe {
                merge_report_value(
                    report,
                    "vpn_probe",
                    vpn_probe,
                    existing.is_none(),
                    &mut added,
                    &mut conflicts,
                );
            }
        }
    }
    if !added.is_empty() {
        text = document.to_string();
    }
    Merge {
        text,
        added,
        conflicts,
    }
}

fn merge_report_value(
    report: &mut dyn TableLike,
    key: &str,
    company_value: &str,
    template_only: bool,
    added: &mut Vec<String>,
    conflicts: &mut Vec<Conflict>,
) {
    let full_key = format!("[report].{key}");
    let current = report.get(key).cloned();
    if let Some(current) = current.as_ref().filter(|_| !template_only) {
        if current.as_str() != Some(company_value) {
            conflicts.push(Conflict {
                key: full_key,
                company_value: company_value.into(),
                file_value: current.to_string().trim().to_owned(),
            });
        }
        return;
    }
    report.insert(key, value(company_value));
    added.push(full_key);
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

pub(crate) fn example(manifest: &open_pact_core::Manifest, os: open_pact_core::Os) -> String {
    let mut output = String::from(
        "# Review this template. The client writes it only through `finish`, after your confirmation.\n",
    );
    for control in &manifest.body().controls {
        let requirement = control
            .required
            .get(&os)
            .map(ToString::to_string)
            .unwrap_or_else(|| "report only".into());
        for line in format!("{} requires {} on {}", control.id, requirement, os).lines() {
            output.push_str(&format!("# {line}\n"));
        }
    }
    output.push_str(&format!("\n{CONFIG_TEMPLATE}\n"));
    output
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
        let text = example(&manifest, open_pact_core::Os::Macos);
        let config = DeviceConfig::parse(&text, Some(Path::new("/home/example"))).unwrap();
        assert!(!config.schedule.unwrap().enabled);
        for control in &manifest.body().controls {
            assert!(text.contains(&format!("# {} requires ", control.id)));
        }
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

    fn company_defaults() -> open_pact_core::ReportDefaults {
        open_pact_core::ReportDefaults {
            collector: "https://collector.example.org/status".into(),
            vpn_probe: Some("vpn.example.org:443".into()),
        }
    }

    fn test_manifest() -> open_pact_core::Manifest {
        open_pact_core::Manifest::parse(include_bytes!("../../../examples/manifest.toml")).unwrap()
    }

    #[test]
    fn merge_without_a_file_uses_the_template_and_company_values() {
        let manifest = test_manifest();
        let result = merge(
            &manifest,
            open_pact_core::Os::Macos,
            Some(&company_defaults()),
            None,
        );
        let template = example(&manifest, open_pact_core::Os::Macos);
        assert!(result.text.contains("[schedule]"));
        assert!(result.text.contains("[managed_repos]"));
        for line in template.lines().filter(|line| line.starts_with("# ")) {
            assert!(result.text.contains(line), "missing template line {line}");
        }
        assert!(
            result
                .text
                .contains("collector = \"https://collector.example.org/status\"")
        );
        assert!(result.text.contains("vpn_probe = \"vpn.example.org:443\""));
        assert_eq!(result.added, ["[report].collector", "[report].vpn_probe"]);
        assert!(result.conflicts.is_empty());
        let config = DeviceConfig::parse(&result.text, Some(Path::new("/home/example"))).unwrap();
        assert_eq!(
            config.report.unwrap().collector,
            "https://collector.example.org/status"
        );
    }

    #[test]
    fn merge_without_company_values_matches_the_manifest_example() {
        let manifest = test_manifest();
        let os = open_pact_core::Os::Macos;
        assert_eq!(
            merge(&manifest, os, None, None).text,
            example(&manifest, os)
        );
    }

    #[test]
    fn merge_adds_a_missing_report_table_without_changing_owner_text() {
        let existing = "# owner note\n[schedule]\nenabled = true\nrun_as = \"user\"\n";
        let result = merge(
            &test_manifest(),
            open_pact_core::Os::Macos,
            Some(&company_defaults()),
            Some(existing),
        );
        assert!(result.text.starts_with("# owner note\n[schedule]"));
        assert!(
            result
                .text
                .contains("[report]\ncollector = \"https://collector.example.org/status\"")
        );
        assert_eq!(
            result.added,
            ["[report]", "[report].collector", "[report].vpn_probe"]
        );
        assert!(result.conflicts.is_empty());
    }

    #[test]
    fn merge_adds_missing_keys_to_an_existing_report_table() {
        let existing =
            "[report]\n# chosen by owner\ncollector = \"https://owner.example.org/status\"\n";
        let mut company = company_defaults();
        company.collector = "https://owner.example.org/status".into();
        let result = merge(
            &test_manifest(),
            open_pact_core::Os::Macos,
            Some(&company),
            Some(existing),
        );
        assert!(result.text.contains("# chosen by owner"));
        assert!(result.text.contains("vpn_probe = \"vpn.example.org:443\""));
        assert_eq!(result.added, ["[report].vpn_probe"]);
        assert!(result.conflicts.is_empty());
    }

    #[test]
    fn merge_keeps_owner_values_and_reports_company_conflicts() {
        let existing = "# keep this comment\n[report]\ncollector = \"https://owner.example.org/status\"\nvpn_probe = \"owner-vpn.example.org:443\"\n";
        let result = merge(
            &test_manifest(),
            open_pact_core::Os::Macos,
            Some(&company_defaults()),
            Some(existing),
        );
        assert_eq!(result.text, existing);
        assert!(result.added.is_empty());
        assert_eq!(result.conflicts.len(), 2);
        assert_eq!(result.conflicts[0].key, "[report].collector");
        assert_eq!(
            result.conflicts[0].file_value,
            "\"https://owner.example.org/status\""
        );
        assert_eq!(result.conflicts[1].key, "[report].vpn_probe");
    }

    #[test]
    fn merge_preserves_comments_and_key_order_and_is_idempotent() {
        let existing = "# owner file\n[report]\n# collector comment\ncollector = \"https://collector.example.org/status\"\n\n[schedule]\nenabled = true\nrun_as = \"user\"\n";
        let mut company = company_defaults();
        company.vpn_probe = Some("vpn.example.org:443".into());
        let first = merge(
            &test_manifest(),
            open_pact_core::Os::Macos,
            Some(&company),
            Some(existing),
        );
        assert!(first.text.contains("# collector comment"));
        assert!(first.text.find("[report]").unwrap() < first.text.find("[schedule]").unwrap());
        assert_eq!(first.added, ["[report].vpn_probe"]);
        let second = merge(
            &test_manifest(),
            open_pact_core::Os::Macos,
            Some(&company),
            Some(&first.text),
        );
        assert_eq!(second.text, first.text);
        assert!(second.added.is_empty());
        assert!(second.conflicts.is_empty());
    }

    #[test]
    fn merge_adds_missing_values_to_an_inline_report_table() {
        let existing = "report = { collector = 'https://collector.example.org/status', # chosen by owner\n    # probe belongs to the company\n}\n";
        let result = merge(
            &test_manifest(),
            open_pact_core::Os::Macos,
            Some(&company_defaults()),
            Some(existing),
        );
        assert!(
            result
                .text
                .contains("collector = 'https://collector.example.org/status'")
        );
        assert!(result.text.contains("vpn_probe = \"vpn.example.org:443\""));
        assert!(result.text.contains("# chosen by owner"));
        assert_eq!(result.added, ["[report].vpn_probe"]);
        assert!(result.conflicts.is_empty());
    }

    #[test]
    fn merge_reports_only_different_values_in_an_inline_report_table() {
        let existing = "report = { collector = 'https://owner.example.org/status' }\n";
        let result = merge(
            &test_manifest(),
            open_pact_core::Os::Macos,
            Some(&company_defaults()),
            Some(existing),
        );
        assert!(
            result
                .text
                .contains("collector = 'https://owner.example.org/status'")
        );
        assert!(result.text.contains("vpn_probe = \"vpn.example.org:443\""));
        assert_eq!(result.added, ["[report].vpn_probe"]);
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].key, "[report].collector");
    }
}
