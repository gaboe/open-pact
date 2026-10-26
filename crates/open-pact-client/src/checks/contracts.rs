use std::collections::BTreeSet;
use std::path::Path;

use chrono::{DateTime, Utc};
use open_pact_core::ControlValue;
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
    pub os: String,
    pub seam: String,
    #[serde(default)]
    pub input: Vec<Option<String>>,
    #[serde(default)]
    pub code: Option<i32>,
    pub now: String,
    pub expected: ControlValue,
    pub known_diff: Option<String>,
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
            assert!(["macos", "linux", "windows"].contains(&case.os.as_str()));
            let _ = case.now();
            if let Some(reason) = &case.known_diff {
                assert!(!reason.trim().is_empty());
                assert!(reason == "pending integration" || reason.contains("report.md#"));
            }
        }
        for os in ["macos", "linux", "windows"] {
            let matching: Vec<_> = rows
                .iter()
                .filter(|row| row[1] == format!("`{}`", contract.id) && row[2] == os)
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
                .filter(|case| case.os == os)
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
            if let Some(reason) = &case.known_diff {
                eprintln!(
                    "KNOWN_DIFF {} {} {}: {reason}",
                    contract.id, case.os, case.name
                );
                skipped += 1;
                continue;
            }
            let actual = match case.seam.as_str() {
                "registry" => {
                    let os = match case.os.as_str() {
                        "linux" => Os::Linux,
                        "macos" => Os::Macos,
                        "windows" => Os::Windows,
                        _ => unreachable!(),
                    };
                    let check = registry(os)
                        .iter()
                        .find(|(id, _)| *id == contract.id)
                        .unwrap()
                        .1;
                    assert!(
                        std::ptr::fn_addr_eq(check, macos_v3::unknown as CheckFn)
                            || std::ptr::fn_addr_eq(check, macos_v3::not_applicable as CheckFn),
                        "registry seam only runs platform constants"
                    );
                    check()
                }
                "windows" => windows::contract_adapter::run(&contract.id, &case),
                "macos" => macos::contract_adapter::run(&contract.id, &case),
                "macos_v3" => macos_v3::contract_adapter::run(&contract.id, &case),
                "linux" => linux::contract_adapter::run(&contract.id, &case),
                "linux_v3" => linux_v3::contract_adapter::run(&contract.id, &case),
                "browsers" => browsers::contract_adapter::run(&contract.id, &case),
                other => panic!("unknown seam {other}"),
            };
            assert_eq!(
                actual, case.expected,
                "{} {} {}",
                contract.id, case.os, case.name
            );
            ran += 1;
        }
    }
    eprintln!("contracts: {ran} executed, {skipped} known differences");
}
