use std::collections::BTreeSet;

use crate::{Manifest, Metadata, Os};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    #[error("control {id} is new")]
    NewControl { id: String },
    #[error("control {id} runs {new} instead of {old}")]
    CheckChanged {
        id: String,
        old: String,
        new: String,
    },
    #[error("control {id} adds outputs {added:?}")]
    OutputsAdded { id: String, added: Vec<String> },
    #[error("claim_retention is longer")]
    RetentionLonger,
    #[error("data_controller changed")]
    DataControllerChanged,
    #[error("claim_recipients adds {0:?}")]
    RecipientsAdded(Vec<String>),
    #[error("disclosed_metadata adds {0:?}")]
    MetadataAdded(Vec<Metadata>),
    #[error("control {id} is stricter on {os}")]
    RequiredStricter { id: String, os: Os },
    #[error("control {id} has a shorter grace")]
    GraceShorter { id: String },
    #[error("unknown_grace is shorter")]
    UnknownGraceShorter,
    #[error("claim_max_age is shorter")]
    MaxAgeShorter,
    #[error("min_trust_level is higher")]
    TrustLevelHigher,
}

fn added<T: Ord + Clone>(old: &BTreeSet<T>, new: &BTreeSet<T>) -> Vec<T> {
    new.difference(old).cloned().collect()
}

pub fn is_narrowing(old: &Manifest, new: &Manifest) -> Result<(), Vec<Violation>> {
    let (old, new) = (old.body(), new.body());
    let mut v = Vec::new();

    for c in &new.controls {
        let Some(o) = old.control(&c.id) else {
            v.push(Violation::NewControl { id: c.id.clone() });
            continue;
        };
        if o.check != c.check {
            v.push(Violation::CheckChanged {
                id: c.id.clone(),
                old: o.check.clone(),
                new: c.check.clone(),
            });
        }
        let extra: Vec<String> = c
            .output
            .iter()
            .filter(|x| !o.output.contains(x))
            .cloned()
            .collect();
        if !extra.is_empty() {
            v.push(Violation::OutputsAdded {
                id: c.id.clone(),
                added: extra,
            });
        }
        for os in Os::ALL {
            let stricter = match (o.required.get(&os), c.required.get(&os)) {
                (_, None) => false,
                (None, Some(_)) => true,
                (Some(was), Some(now)) => !now.0.is_superset(&was.0),
            };
            if stricter {
                v.push(Violation::RequiredStricter {
                    id: c.id.clone(),
                    os,
                });
            }
        }
        if !o.grace.certainly_shorter_or_equal(&c.grace) {
            v.push(Violation::GraceShorter { id: c.id.clone() });
        }
    }

    if !new
        .claim_retention
        .certainly_shorter_or_equal(&old.claim_retention)
    {
        v.push(Violation::RetentionLonger);
    }
    if new.data_controller != old.data_controller {
        v.push(Violation::DataControllerChanged);
    }
    let recipients = added(&old.claim_recipients, &new.claim_recipients);
    if !recipients.is_empty() {
        v.push(Violation::RecipientsAdded(recipients));
    }
    let metadata = added(&old.disclosed_metadata, &new.disclosed_metadata);
    if !metadata.is_empty() {
        v.push(Violation::MetadataAdded(metadata));
    }
    if !old
        .unknown_grace
        .certainly_shorter_or_equal(&new.unknown_grace)
    {
        v.push(Violation::UnknownGraceShorter);
    }
    if !old
        .claim_max_age
        .certainly_shorter_or_equal(&new.claim_max_age)
    {
        v.push(Violation::MaxAgeShorter);
    }
    if new.min_trust_level > old.min_trust_level {
        v.push(Violation::TrustLevelHigher);
    }

    if v.is_empty() { Ok(()) } else { Err(v) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = include_str!("../../../examples/manifest.toml");

    fn check(edits: &[(&str, &str)]) -> Result<(), Vec<Violation>> {
        let mut text = DEMO.to_string();
        for (from, to) in edits {
            assert!(text.contains(from), "fixture lacks {from}");
            text = text.replacen(from, to, 1);
        }
        let old = Manifest::parse(DEMO.as_bytes()).unwrap();
        is_narrowing(&old, &Manifest::parse(text.as_bytes()).unwrap())
    }

    fn rejected(edits: &[(&str, &str)], expected: Violation) {
        assert_eq!(check(edits), Err(vec![expected]));
    }

    const FIREWALL: &str = "[[control]]\nid = \"firewall\"\nsource = \"company_policy\"\ncheck = \"builtin:firewall@1\"\noutput = [\"on\", \"off\", \"unknown\"]\nrequired = { macos = \"on\", windows = \"on\", linux = \"on\" }\ngrace = \"1d\"\n\n";

    #[test]
    fn accepts_identical_manifest() {
        assert_eq!(check(&[]), Ok(()));
    }

    #[test]
    fn accepts_combined_narrowing() {
        assert_eq!(
            check(&[
                (FIREWALL, ""),
                (
                    r#"output = ["full", "partial", "none", "unknown"]"#,
                    r#"output = ["full", "none", "unknown"]"#
                ),
                (r#"claim_retention = "12mo""#, r#"claim_retention = "6mo""#),
                (
                    r#"["Company IT security", "auditor on request"]"#,
                    r#"["Company IT security"]"#
                ),
                (
                    r#""virtualized", "log_checkpoint"]"#,
                    r#""log_checkpoint"]"#
                ),
                (
                    r#"required = { macos = "le_5min", windows = "le_5min", linux = "le_5min" }"#,
                    r#"required = { macos = ["le_5min", "le_15min"], windows = "le_5min" }"#
                ),
                (r#"grace = "14d""#, r#"grace = "30d""#),
                (r#"unknown_grace = "7d""#, r#"unknown_grace = "2w""#),
                (r#"claim_max_age = "24h""#, r#"claim_max_age = "2d""#),
            ]),
            Ok(())
        );
    }

    #[test]
    fn rejects_new_control() {
        let extra = "\n[[control]]\nid = \"secure_boot\"\nsource = \"standard\"\ncheck = \"builtin:secure_boot@1\"\noutput = [\"on\", \"off\"]\nrequired = {}\ngrace = \"0d\"\n";
        rejected(
            &[("grace = \"14d\"\n", &format!("grace = \"14d\"\n{extra}"))],
            Violation::NewControl {
                id: "secure_boot".into(),
            },
        );
    }

    #[test]
    fn rejects_changed_check_code() {
        rejected(
            &[(
                r#"check = "builtin:firewall@1""#,
                r#"check = "builtin:firewall@2""#,
            )],
            Violation::CheckChanged {
                id: "firewall".into(),
                old: "builtin:firewall@1".into(),
                new: "builtin:firewall@2".into(),
            },
        );
    }

    #[test]
    fn rejects_added_output() {
        rejected(
            &[(
                r#"output = ["on", "off", "unknown"]"#,
                r#"output = ["on", "off", "partial", "unknown"]"#,
            )],
            Violation::OutputsAdded {
                id: "firewall".into(),
                added: vec!["partial".into()],
            },
        );
    }

    #[test]
    fn rejects_longer_retention() {
        rejected(
            &[(r#"claim_retention = "12mo""#, r#"claim_retention = "365d""#)],
            Violation::RetentionLonger,
        );
    }

    #[test]
    fn rejects_changed_data_controller() {
        rejected(
            &[("Company Ltd., dpo@", "Company Group Ltd., dpo@")],
            Violation::DataControllerChanged,
        );
    }

    #[test]
    fn rejects_added_recipient() {
        rejected(
            &[(r#""auditor on request"]"#, r#""auditor on request", "HR"]"#)],
            Violation::RecipientsAdded(vec!["HR".into()]),
        );
    }

    #[test]
    fn rejects_added_metadata() {
        rejected_from(
            (
                r#""virtualized", "log_checkpoint"]"#,
                r#""log_checkpoint"]"#,
            ),
            Violation::MetadataAdded(vec![Metadata::Virtualized]),
        );
    }

    fn rejected_from(old_edit: (&str, &str), expected: Violation) {
        assert!(DEMO.contains(old_edit.0), "fixture lacks {}", old_edit.0);
        let old = Manifest::parse(DEMO.replacen(old_edit.0, old_edit.1, 1).as_bytes()).unwrap();
        let new = Manifest::parse(DEMO.as_bytes()).unwrap();
        assert_eq!(is_narrowing(&old, &new), Err(vec![expected]));
    }

    #[test]
    fn rejects_stricter_required_value() {
        rejected_from(
            (
                r#"required = { macos = "le_5min","#,
                r#"required = { macos = ["le_5min", "le_15min"],"#,
            ),
            Violation::RequiredStricter {
                id: "screen_lock".into(),
                os: Os::Macos,
            },
        );
    }

    #[test]
    fn rejects_newly_required_os() {
        rejected_from(
            (
                r#"required = { macos = "on", windows = "on", linux = "on" }"#,
                r#"required = { macos = "on", windows = "on" }"#,
            ),
            Violation::RequiredStricter {
                id: "firewall".into(),
                os: Os::Linux,
            },
        );
    }

    #[test]
    fn rejects_shorter_grace() {
        rejected(
            &[(r#"grace = "14d""#, r#"grace = "1w""#)],
            Violation::GraceShorter {
                id: "os_supported".into(),
            },
        );
    }

    #[test]
    fn rejects_shorter_unknown_grace() {
        rejected(
            &[(r#"unknown_grace = "7d""#, r#"unknown_grace = "6d""#)],
            Violation::UnknownGraceShorter,
        );
    }

    #[test]
    fn rejects_shorter_claim_max_age() {
        rejected(
            &[(r#"claim_max_age = "24h""#, r#"claim_max_age = "12h""#)],
            Violation::MaxAgeShorter,
        );
    }

    #[test]
    fn rejects_higher_trust_level() {
        rejected(
            &[(r#"min_trust_level = "L0""#, r#"min_trust_level = "L1""#)],
            Violation::TrustLevelHigher,
        );
    }
}
