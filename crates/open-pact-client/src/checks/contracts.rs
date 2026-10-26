use std::collections::BTreeSet;
use std::path::Path;

use chrono::{DateTime, Utc};
use open_pact_core::{ControlValue, Os};
use serde::Deserialize;

use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Contract {
    pub id: String,
    pub cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Case {
    pub name: String,
    pub os: Os,
    #[serde(default)]
    pub input: Vec<Option<String>>,
    #[serde(default)]
    pub code: Option<i32>,
    pub now: String,
    pub expected: ControlValue,
    #[serde(default)]
    pub observed: Option<ControlValue>,
    #[serde(default)]
    pub difference: Option<String>,
    pub known_diff: Option<String>,
    #[serde(default)]
    pub unrepresentable_input: Option<String>,
}

impl Case {
    pub fn text(&self, index: usize) -> &str {
        self.optional(index).unwrap_or_default()
    }

    pub fn optional(&self, index: usize) -> Option<&str> {
        self.input.get(index).and_then(Option::as_deref)
    }

    pub fn now(&self) -> DateTime<Utc> {
        self.now.parse().expect("case has RFC3339 now")
    }
}

pub(super) fn load() -> Vec<Contract> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/contracts");
    let mut files: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let contract: Contract = serde_json::from_slice(&std::fs::read(&path).unwrap())
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert_eq!(path.file_stem().unwrap().to_str().unwrap(), contract.id);
            contract
        })
        .collect()
}

fn kind(value: &ControlValue) -> String {
    match value {
        ControlValue::Integer(_) => "number".into(),
        ControlValue::Null => "null".into(),
        ControlValue::Text(text) => {
            if DateTime::parse_from_rfc3339(text).is_ok() {
                "timestamp".into()
            } else {
                text.into()
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Adapter {
    Registry,
    Windows,
    Macos,
    MacosV3,
    Linux,
    LinuxV3,
    Browsers,
}

fn adapter_for(id: &str, os: Os) -> Adapter {
    let check = registry(os)
        .iter()
        .find(|(registered, _)| *registered == id)
        .unwrap_or_else(|| panic!("unregistered contract {id}"))
        .1;
    if std::ptr::fn_addr_eq(check, macos_v3::unknown as CheckFn)
        || std::ptr::fn_addr_eq(check, macos_v3::not_applicable as CheckFn)
    {
        return Adapter::Registry;
    }

    match (os, id) {
        (Os::Macos, "web_protection") => Adapter::Browsers,
        (
            Os::Macos,
            "os_auto_updates"
            | "antimalware_realtime"
            | "work_account"
            | "uptime_days"
            | "preboot_auth"
            | "antimalware_active"
            | "antimalware_signature_age_days",
        ) => Adapter::MacosV3,
        (
            Os::Linux,
            "os_auto_updates"
            | "antimalware_realtime"
            | "work_account"
            | "uptime_days"
            | "preboot_auth"
            | "antimalware_signature_age_days"
            | "log_oldest_record_days",
        ) => Adapter::LinuxV3,
        (Os::Windows, _) => Adapter::Windows,
        (Os::Macos, _) => Adapter::Macos,
        (Os::Linux, _) => Adapter::Linux,
    }
}

fn run_case(id: &str, case: &Case) -> ControlValue {
    match adapter_for(id, case.os) {
        Adapter::Registry => {
            let check = registry(case.os)
                .iter()
                .find(|(registered, _)| *registered == id)
                .unwrap()
                .1;
            assert!(
                std::ptr::fn_addr_eq(check, macos_v3::unknown as CheckFn)
                    || std::ptr::fn_addr_eq(check, macos_v3::not_applicable as CheckFn),
                "registry adapter only runs platform constants"
            );
            check()
        }
        Adapter::Windows => windows::contract_adapter::run(id, case),
        Adapter::Macos => macos::contract_adapter::run(id, case),
        Adapter::MacosV3 => macos_v3::contract_adapter::run(id, case),
        Adapter::Linux => linux::contract_adapter::run(id, case),
        Adapter::LinuxV3 => linux_v3::contract_adapter::run(id, case),
        Adapter::Browsers => browsers::contract_adapter::run(id, case),
    }
}

#[test]
fn registered_contract_coverage() {
    let contracts = load();
    let manifest = Manifest::parse(include_bytes!("../../../../examples/manifest.toml")).unwrap();
    let registered: BTreeSet<_> = BUILTINS.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        contracts
            .iter()
            .map(|c| c.id.as_str())
            .collect::<BTreeSet<_>>(),
        registered
    );
    assert_eq!(contracts.len(), registered.len(), "duplicate contract ID");
    let document = include_str!("../../../../docs/controls.md");
    let rows: Vec<Vec<_>> = document
        .lines()
        .filter(|line| line.starts_with("| `"))
        .map(|line| line.split('|').map(str::trim).collect())
        .collect();
    assert_eq!(rows.len(), registered.len() * Os::ALL.len());
    for contract in &contracts {
        let control = manifest.body().control(&contract.id);
        let mut names = BTreeSet::new();
        for case in &contract.cases {
            let _ = adapter_for(&contract.id, case.os);
            assert!(
                case.expected == "unknown"
                    || control.is_none_or(|control| control.output.contains(&case.expected)),
                "{} {}: result outside signed domain",
                contract.id,
                case.name
            );
            assert!(
                names.insert((&case.os, &case.name)),
                "duplicate case {}",
                case.name
            );
            let _ = case.now();
            if let Some(reason) = &case.known_diff {
                assert!(!reason.trim().is_empty());
                assert!(reason == "pending integration" || reason.contains("report.md#"));
            }
            if let Some(observed) = &case.observed {
                assert!(
                    control.is_none_or(|control| control.output.contains(observed)),
                    "{} {}: observed result outside signed domain",
                    contract.id,
                    case.name
                );
                assert!(
                    case.difference
                        .as_ref()
                        .is_some_and(|difference| !difference.trim().is_empty())
                );
            }
        }
        for os in Os::ALL {
            let matching: Vec<_> = rows
                .iter()
                .filter(|row| row[1] == format!("`{}`", contract.id) && row[2] == os.to_string())
                .collect();
            assert_eq!(
                matching.len(),
                1,
                "{} {os}: missing or duplicate table row",
                contract.id
            );
            let expected: BTreeSet<_> = matching[0][3]
                .split(',')
                .map(|s| s.trim().trim_matches('`').to_string())
                .collect();
            let actual: BTreeSet<_> = contract
                .cases
                .iter()
                .filter(|case| {
                    case.os == os
                        && !(case.known_diff.is_some() && case.unrepresentable_input.is_some())
                })
                .map(|case| kind(&case.expected))
                .collect();
            assert_eq!(
                actual, expected,
                "{} {os}: missing result case",
                contract.id
            );
        }
    }
}

#[test]
fn contract_cases() {
    let mut ran = 0;
    let mut skipped = 0;
    for contract in load() {
        for case in contract.cases {
            match (&case.known_diff, &case.unrepresentable_input) {
                (Some(reason), Some(input)) => {
                    assert!(!reason.trim().is_empty());
                    assert!(!input.trim().is_empty());
                    assert!(case.observed.is_none());
                    assert!(case.difference.is_none());
                    eprintln!(
                        "SKIPPED {} {} {}: {input}; {reason}",
                        contract.id, case.os, case.name
                    );
                    skipped += 1;
                    continue;
                }
                (None, Some(input)) => panic!(
                    "{} {} {}: unrepresentable_input requires known_diff: {input}",
                    contract.id, case.os, case.name
                ),
                (Some(_), None) => {
                    let actual = run_case(&contract.id, &case);
                    if actual == case.expected {
                        panic!(
                            "{} {} {}: known_diff already passes; remove the marker",
                            contract.id, case.os, case.name
                        );
                    }
                    panic!(
                        "{} {} {}: known_diff can skip only input that the adapter cannot represent; use observed and difference for a runnable case",
                        contract.id, case.os, case.name
                    );
                }
                (None, None) => {}
            }

            assert_eq!(case.observed.is_some(), case.difference.is_some());
            let actual = run_case(&contract.id, &case);
            let expected = case.observed.as_ref().unwrap_or(&case.expected);
            assert_eq!(
                &actual, expected,
                "{} {} {}",
                contract.id, case.os, case.name
            );
            if let Some(observed) = &case.observed {
                assert_ne!(observed, &case.expected);
                eprintln!(
                    "DIFFERENCE {} {} {}: contract={:?} current={observed:?}: {}",
                    contract.id,
                    case.os,
                    case.name,
                    case.expected,
                    case.difference.as_deref().unwrap()
                );
            }
            ran += 1;
        }
    }
    eprintln!("contracts: {ran} executed, {skipped} unrepresentable inputs");
}
