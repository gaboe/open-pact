use chrono::{DateTime, NaiveDate, TimeDelta, Utc};

use crate::{Accepted, Claim, Manifest, ManifestHash, Os, Span, TrustLevel};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow { warnings: Vec<Reason> },
    Deny { reasons: Vec<Reason> },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Reason {
    #[error("claim is for manifest {claimed}, gateway enforces {enforced}")]
    WrongManifest {
        claimed: ManifestHash,
        enforced: ManifestHash,
    },
    #[error("claim time {time} is older than claim_max_age {max_age}")]
    Stale { time: DateTime<Utc>, max_age: Span },
    #[error("claim time {0} is more than 5 minutes in the future")]
    FromFuture(DateTime<Utc>),
    #[error("manifest is valid from {0}")]
    NotYetValid(NaiveDate),
    #[error("trust_level = {claimed:?}, {min:?} required")]
    TrustLevelTooLow {
        claimed: TrustLevel,
        min: TrustLevel,
    },
    #[error("{id} is not in the manifest")]
    UnknownControl { id: String },
    #[error("{id} = {value} is not an output the manifest allows")]
    UndisclosedValue { id: String, value: String },
    #[error("{id} missing, required on {os}")]
    Missing { id: String, os: Os },
    #[error("{id} = {value}, {required} required{}", grace_note(.grace))]
    Failed {
        id: String,
        value: String,
        required: Accepted,
        grace: Span,
    },
    #[error("{id} = unknown, {required} required (unknown_grace {grace})")]
    Unknown {
        id: String,
        required: Accepted,
        grace: Span,
    },
}

impl Reason {
    /// The claim carried data the manifest does not allow, so the gateway must not keep it.
    pub fn breaks_disclosure_contract(&self) -> bool {
        matches!(
            self,
            Reason::UnknownControl { .. } | Reason::UndisclosedValue { .. }
        )
    }
}

fn grace_note(grace: &Span) -> String {
    if grace.is_zero() {
        String::new()
    } else {
        format!(" (grace {grace})")
    }
}

/// Grace is stateless for now: any failure with a non-zero grace, and any `unknown`, warns instead of denying,
/// because the gateway does not yet record when a failure started.
pub fn evaluate(manifest: &Manifest, claim: &Claim, now: DateTime<Utc>) -> Decision {
    let body = manifest.body();
    let mut deny = Vec::new();
    let mut warn = Vec::new();

    if &claim.manifest != manifest.hash() {
        deny.push(Reason::WrongManifest {
            claimed: claim.manifest.clone(),
            enforced: manifest.hash().clone(),
        });
    }
    if claim.time > now + TimeDelta::minutes(5) {
        deny.push(Reason::FromFuture(claim.time));
    }
    if body
        .claim_max_age
        .min_duration()
        .is_some_and(|max_age| now - claim.time > max_age)
    {
        deny.push(Reason::Stale {
            time: claim.time,
            max_age: body.claim_max_age.clone(),
        });
    }
    if now.date_naive() < body.valid_from {
        deny.push(Reason::NotYetValid(body.valid_from));
    }
    if claim.trust_level < body.min_trust_level {
        deny.push(Reason::TrustLevelTooLow {
            claimed: claim.trust_level,
            min: body.min_trust_level,
        });
    }
    for (id, value) in &claim.results {
        match body.control(id) {
            None => deny.push(Reason::UnknownControl { id: id.clone() }),
            Some(c) if !c.output.contains(value) => deny.push(Reason::UndisclosedValue {
                id: id.clone(),
                value: value.clone(),
            }),
            Some(_) => {}
        }
    }
    for control in &body.controls {
        let Some(required) = control.required.get(&claim.os) else {
            continue;
        };
        let id = control.id.clone();
        let required = required.clone();
        match claim.results.get(&control.id) {
            None => deny.push(Reason::Missing { id, os: claim.os }),
            Some(value) if required.contains(value) || !control.output.contains(value) => {}
            Some(value) if value == "unknown" => warn.push(Reason::Unknown {
                id,
                required,
                grace: body.unknown_grace.clone(),
            }),
            Some(value) => {
                let failed = Reason::Failed {
                    id,
                    value: value.clone(),
                    required,
                    grace: control.grace.clone(),
                };
                if control.grace.is_zero() {
                    deny.push(failed)
                } else {
                    warn.push(failed)
                }
            }
        }
    }

    if deny.is_empty() {
        Decision::Allow { warnings: warn }
    } else {
        Decision::Deny { reasons: deny }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{Pseudonym, PublicKey, Virtualized, dev_key};

    const DEMO: &str = include_str!("../../../examples/manifest.toml");

    fn now() -> DateTime<Utc> {
        "2026-10-12T09:00:00Z".parse().unwrap()
    }

    fn manifest() -> Manifest {
        Manifest::parse(DEMO.as_bytes()).unwrap()
    }

    fn claim(results: &[(&str, &str)]) -> Claim {
        let device_key = PublicKey::from(&dev_key::generate());
        Claim {
            manifest: manifest().hash().clone(),
            device: Pseudonym::of(&device_key),
            device_key,
            nonce: "n".into(),
            time: now(),
            client: "test".into(),
            os: Os::Macos,
            trust_level: TrustLevel::L0,
            virtualized: Virtualized::No,
            results: results
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            csr_pem: None,
            log_checkpoint: None,
        }
    }

    const PASSING: [(&str, &str); 4] = [
        ("disk_encryption", "full"),
        ("firewall", "on"),
        ("screen_lock", "le_5min"),
        ("os_supported", "yes"),
    ];

    fn with(overrides: &[(&str, &str)]) -> Claim {
        let mut c = claim(&PASSING);
        for (k, v) in overrides {
            c.results.insert(k.to_string(), v.to_string());
        }
        c
    }

    fn reasons(decision: Decision) -> Vec<String> {
        match decision {
            Decision::Deny { reasons } => reasons.iter().map(ToString::to_string).collect(),
            Decision::Allow { warnings } => panic!("expected deny, got allow with {warnings:?}"),
        }
    }

    #[test]
    fn allows_compliant_claim() {
        assert_eq!(
            evaluate(&manifest(), &claim(&PASSING), now()),
            Decision::Allow { warnings: vec![] }
        );
    }

    #[test]
    fn denies_failed_check_without_grace() {
        assert_eq!(
            reasons(evaluate(
                &manifest(),
                &with(&[("disk_encryption", "none")]),
                now()
            )),
            ["disk_encryption = none, full required"]
        );
    }

    #[test]
    fn denies_missing_required_check() {
        let mut c = claim(&PASSING);
        c.results.remove("firewall");
        assert_eq!(
            reasons(evaluate(&manifest(), &c, now())),
            ["firewall missing, required on macos"]
        );
    }

    #[test]
    fn allows_check_not_required_on_this_os() {
        let toml = DEMO.replace(
            r#"required = { macos = "on", windows = "on", linux = "on" }"#,
            "required = { windows = \"on\" }",
        );
        let m = Manifest::parse(toml.as_bytes()).unwrap();
        let mut c = with(&[("firewall", "off")]);
        c.manifest = m.hash().clone();
        assert_eq!(
            evaluate(&m, &c, now()),
            Decision::Allow { warnings: vec![] }
        );
    }

    #[test]
    fn denies_result_key_not_in_manifest() {
        assert_eq!(
            reasons(evaluate(
                &manifest(),
                &with(&[("installed_apps", "slack")]),
                now()
            )),
            ["installed_apps is not in the manifest"]
        );
        let Decision::Deny { reasons } =
            evaluate(&manifest(), &with(&[("installed_apps", "slack")]), now())
        else {
            unreachable!()
        };
        assert!(reasons[0].breaks_disclosure_contract());
    }

    #[test]
    fn denies_value_outside_output_set() {
        assert_eq!(
            reasons(evaluate(
                &manifest(),
                &with(&[("disk_encryption", "FileVault on, disk0s2")]),
                now()
            )),
            ["disk_encryption = FileVault on, disk0s2 is not an output the manifest allows"]
        );
    }

    #[test]
    fn stateless_grace_warns_instead_of_denying_failed_check_with_grace() {
        let Decision::Allow { warnings } =
            evaluate(&manifest(), &with(&[("firewall", "off")]), now())
        else {
            panic!("expected allow");
        };
        let text: Vec<String> = warnings.iter().map(ToString::to_string).collect();
        assert_eq!(text, ["firewall = off, on required (grace 1d)"]);
    }

    #[test]
    fn stateless_unknown_grace_warns_even_when_grace_is_zero() {
        let Decision::Allow { warnings } =
            evaluate(&manifest(), &with(&[("disk_encryption", "unknown")]), now())
        else {
            panic!("expected allow");
        };
        let text: Vec<String> = warnings.iter().map(ToString::to_string).collect();
        assert_eq!(
            text,
            ["disk_encryption = unknown, full required (unknown_grace 7d)"]
        );
    }

    #[test]
    fn denies_claim_for_another_manifest() {
        let mut c = claim(&PASSING);
        c.manifest = ManifestHash::of(b"other");
        assert_eq!(reasons(evaluate(&manifest(), &c, now())).len(), 1);
    }

    #[test]
    fn denies_before_valid_from() {
        let early = "2026-09-30T23:59:59Z".parse().unwrap();
        let mut c = claim(&PASSING);
        c.time = early;
        assert_eq!(
            reasons(evaluate(&manifest(), &c, early)),
            ["manifest is valid from 2026-10-01"]
        );
    }

    #[test]
    fn denies_trust_level_below_minimum() {
        let toml = DEMO.replace(r#"min_trust_level = "L0""#, r#"min_trust_level = "L1""#);
        let m = Manifest::parse(toml.as_bytes()).unwrap();
        let mut c = claim(&PASSING);
        c.manifest = m.hash().clone();
        assert_eq!(
            reasons(evaluate(&m, &c, now())),
            ["trust_level = L0, L1 required"]
        );
    }

    #[test]
    fn denies_claim_older_than_claim_max_age() {
        let mut c = claim(&PASSING);
        c.time = now() - TimeDelta::hours(24);
        assert_eq!(
            evaluate(&manifest(), &c, now()),
            Decision::Allow { warnings: vec![] }
        );
        c.time = now() - TimeDelta::hours(24) - TimeDelta::seconds(1);
        assert_eq!(
            reasons(evaluate(&manifest(), &c, now())),
            ["claim time 2026-10-11 08:59:59 UTC is older than claim_max_age 24h"]
        );
    }

    #[test]
    fn denies_claim_from_the_future() {
        let mut c = claim(&PASSING);
        c.time = now() + TimeDelta::minutes(5);
        assert_eq!(
            evaluate(&manifest(), &c, now()),
            Decision::Allow { warnings: vec![] }
        );
        c.time = now() + TimeDelta::minutes(6);
        assert_eq!(
            reasons(evaluate(&manifest(), &c, now())),
            ["claim time 2026-10-12 09:06:00 UTC is more than 5 minutes in the future"]
        );
    }
}
