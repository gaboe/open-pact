use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, NaiveDate, TimeDelta, Utc};

use crate::{Accepted, Claim, Manifest, ManifestHash, Metadata, Os, Span, TrustLevel};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow { warnings: Vec<Reason> },
    Deny { reasons: Vec<Reason> },
}

/// When each required control of one device under one manifest started to fail or report
/// `unknown`, as the gateway observed it. Keyed by control id.
pub type FirstFailures = BTreeMap<String, DateTime<Utc>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub decision: Decision,
    /// What the gateway stores for the next claim of this device.
    pub first_failures: FirstFailures,
}

/// Where a failing control stands against its grace period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grace {
    /// The grace is `0d`: the failure denies at once.
    None,
    /// Access continues for this long.
    Left(TimeDelta),
    /// The grace ran out.
    Ended(Span),
}

impl Grace {
    fn of(span: &Span, first_failure: DateTime<Utc>, now: DateTime<Utc>) -> Grace {
        if span.is_zero() {
            return Grace::None;
        }
        let Some(length) = span.min_duration() else {
            return Grace::Left(TimeDelta::MAX);
        };
        let elapsed = (now - first_failure).max(TimeDelta::zero());
        if elapsed > length {
            Grace::Ended(span.clone())
        } else {
            Grace::Left(length - elapsed)
        }
    }

    fn denies(&self) -> bool {
        !matches!(self, Grace::Left(_))
    }

    fn describe(&self, name: &str) -> String {
        match self {
            Grace::None => String::new(),
            Grace::Left(left) => format!(", access ends in {}", Remaining(*left)),
            Grace::Ended(span) => format!(", {name} {span} ended"),
        }
    }
}

/// Minutes under an hour, hours under two days, then days and hours. Rounded down.
struct Remaining(TimeDelta);

impl fmt::Display for Remaining {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (hours, days) = (self.0.num_hours(), self.0.num_days());
        match (days, hours % 24) {
            _ if hours < 1 => write!(f, "{}m", self.0.num_minutes()),
            _ if hours < 48 => write!(f, "{hours}h"),
            (d, 0) => write!(f, "{d}d"),
            (d, h) => write!(f, "{d}d {h}h"),
        }
    }
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
    #[error("client must be \"open-pact-client <major>.<minor>.<patch>\"")]
    BadClient,
    #[error("claim time {0} is more than 5 minutes in the future")]
    FromFuture(DateTime<Utc>),
    #[error("manifest is valid from {0}")]
    NotYetValid(NaiveDate),
    #[error(
        "min_trust_level {min:?} needs attestation, which is not available: \
         every claim counts as {verified:?} (this one asserts {asserted:?})"
    )]
    TrustLevelTooLow {
        asserted: TrustLevel,
        verified: TrustLevel,
        min: TrustLevel,
    },
    #[error("{0} is not in disclosed_metadata")]
    UndisclosedMetadata(Metadata),
    #[error("{id} is not in the manifest")]
    UnknownControl { id: String },
    #[error("{id} = {value} is not an output the manifest allows")]
    UndisclosedValue { id: String, value: String },
    #[error("{id} missing, required on {os}")]
    Missing { id: String, os: Os },
    #[error("{id} = {value}, {required} required{}", .grace.describe("grace"))]
    Failed {
        id: String,
        value: String,
        required: Accepted,
        grace: Grace,
    },
    #[error("{id} = unknown, {required} required{}", .grace.describe("unknown_grace"))]
    Unknown {
        id: String,
        required: Accepted,
        grace: Grace,
    },
}

impl Reason {
    /// The claim carried data the manifest does not allow, so the gateway must not keep it.
    pub fn breaks_disclosure_contract(&self) -> bool {
        matches!(
            self,
            Reason::UnknownControl { .. }
                | Reason::UndisclosedValue { .. }
                | Reason::UndisclosedMetadata(_)
                | Reason::BadClient
        )
    }
}

/// The trust level the gateway can verify. A claim's `trust_level` is the client's own assertion: a
/// Secure Enclave key protects against key theft, but nothing proves to the gateway that the key is
/// in hardware. Until attestation exists, every claim counts as L0.
pub fn verified_trust_level(_claim: &Claim) -> TrustLevel {
    TrustLevel::L0
}

/// `open-pact-client 1.2.3` with canonical `u32` components and nothing else, so the field cannot carry free text off the device.
fn is_client_version(client: &str) -> bool {
    let Some(version) = client.strip_prefix("open-pact-client ") else {
        return false;
    };
    let parts: Vec<&str> = version.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| p.parse::<u32>().is_ok_and(|n| n.to_string() == *p))
}

/// Grace is measured from the first failure the gateway saw, in `first_failures`. A failure keeps
/// its start when it changes between a failed value and `unknown`; only a passing value clears it.
/// The map moves only for a claim whose envelope (client, manifest, time, trust level and
/// disclosure) is clean, so a claim the gateway refuses outright cannot reset or plant state.
pub fn evaluate(
    manifest: &Manifest,
    claim: &Claim,
    now: DateTime<Utc>,
    first_failures: &FirstFailures,
) -> Evaluation {
    let body = manifest.body();
    let mut deny = Vec::new();
    let mut warn = Vec::new();

    if !is_client_version(&claim.client) {
        deny.push(Reason::BadClient);
    }
    for (field, sent) in [
        (Metadata::Virtualized, claim.virtualized.is_some()),
        (Metadata::LogCheckpoint, claim.log_checkpoint.is_some()),
    ] {
        if sent && !body.discloses(field) {
            deny.push(Reason::UndisclosedMetadata(field));
        }
    }
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
    let verified = verified_trust_level(claim);
    if verified < body.min_trust_level {
        deny.push(Reason::TrustLevelTooLow {
            asserted: claim.trust_level,
            verified,
            min: body.min_trust_level,
        });
    }
    for (id, value) in &claim.results {
        match body.control(id) {
            None => deny.push(Reason::UnknownControl { id: id.clone() }),
            Some(c) if !c.output.contains(value) => deny.push(Reason::UndisclosedValue {
                id: id.clone(),
                value: value.to_string(),
            }),
            Some(_) => {}
        }
    }
    let envelope_clean = deny.is_empty();

    let mut next = FirstFailures::new();
    for control in &body.controls {
        let Some(required) = control.required.get(&claim.os) else {
            continue;
        };
        let id = control.id.clone();
        let required = required.clone();
        let since = first_failures.get(&id).copied();
        let Some(value) = claim.results.get(&control.id) else {
            if let Some(since) = since {
                next.insert(id.clone(), since);
            }
            deny.push(Reason::Missing { id, os: claim.os });
            continue;
        };
        if required.contains(value) || !control.output.contains(value) {
            continue;
        }
        let since = since.unwrap_or(now);
        next.insert(id.clone(), since);
        let unknown = value == "unknown";
        let span = if unknown {
            &body.unknown_grace
        } else {
            &control.grace
        };
        let grace = Grace::of(span, since, now);
        let denies = grace.denies();
        let reason = if unknown {
            Reason::Unknown {
                id,
                required,
                grace,
            }
        } else {
            Reason::Failed {
                id,
                value: value.to_string(),
                required,
                grace,
            }
        };
        if denies {
            deny.push(reason);
        } else {
            warn.push(reason);
        }
    }

    let decision = if deny.is_empty() {
        Decision::Allow { warnings: warn }
    } else {
        Decision::Deny { reasons: deny }
    };
    Evaluation {
        decision,
        first_failures: if envelope_clean {
            next
        } else {
            first_failures.clone()
        },
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
            client: "open-pact-client 0.0.1".into(),
            os: Os::Macos,
            trust_level: TrustLevel::L0,
            virtualized: Some(Virtualized::No),
            results: std::iter::once(("os_patch_age_days".into(), 14.into()))
                .chain(results.iter().map(|(k, v)| (k.to_string(), (*v).into())))
                .collect::<BTreeMap<_, _>>(),
            csr_sha256: None,
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
            c.results.insert(k.to_string(), (*v).into());
        }
        c
    }

    fn decide(m: &Manifest, c: &Claim, now: DateTime<Utc>) -> Decision {
        evaluate(m, c, now, &FirstFailures::new()).decision
    }

    fn texts(rs: &[Reason]) -> Vec<String> {
        rs.iter().map(ToString::to_string).collect()
    }

    fn warnings(decision: Decision) -> Vec<String> {
        match decision {
            Decision::Allow { warnings } => texts(&warnings),
            Decision::Deny { reasons } => panic!("expected allow, got deny with {reasons:?}"),
        }
    }

    fn reasons(decision: Decision) -> Vec<String> {
        match decision {
            Decision::Deny { reasons } => reasons.iter().map(ToString::to_string).collect(),
            Decision::Allow { warnings } => panic!("expected deny, got allow with {warnings:?}"),
        }
    }

    #[test]
    fn client_must_be_a_bare_version_and_is_not_stored_otherwise() {
        let m = manifest();
        for ok in ["open-pact-client 0.0.1", "open-pact-client 10.20.30"] {
            assert!(is_client_version(ok), "{ok}");
        }
        for bad in [
            "open-pact-client 0.4.1 sha256:77ac",
            "open-pact-client 1.2",
            "open-pact-client 1.2.x",
            "open-pact-client 1..2",
            "my-client 1.2.3",
            "open-pact-client 1.2.3 hello from the owner",
            &format!("open-pact-client {}.2.3", "7".repeat(65_536)),
            "open-pact-client 0001.2.3",
            "open-pact-client 4294967296.0.0",
        ] {
            let mut c = claim(&[]);
            c.client = bad.into();
            let Decision::Deny { reasons } = decide(&m, &c, Utc::now()) else {
                panic!("{bad} was allowed");
            };
            assert!(reasons.contains(&Reason::BadClient), "{bad}");
            assert!(reasons.iter().any(Reason::breaks_disclosure_contract));
            assert!(Reason::BadClient.to_string().starts_with("client must be"));
        }
    }

    #[test]
    fn denies_metadata_the_manifest_does_not_list_and_does_not_store_it() {
        let toml = DEMO.replace(r#", "log_checkpoint"]"#, "]");
        assert_ne!(toml, DEMO);
        let m = Manifest::parse(toml.as_bytes()).unwrap();
        let mut c = claim(&PASSING);
        c.manifest = m.hash().clone();
        c.log_checkpoint = Some(crate::LogCheckpoint {
            size: 1,
            root: crate::LogHash([0; 32]),
        });
        let Decision::Deny { reasons } = decide(&m, &c, now()) else {
            panic!("an unlisted log_checkpoint was allowed");
        };
        assert_eq!(
            texts(&reasons),
            ["log_checkpoint is not in disclosed_metadata"]
        );
        assert!(reasons[0].breaks_disclosure_contract());
    }

    #[test]
    fn allows_compliant_claim() {
        assert_eq!(
            decide(&manifest(), &claim(&PASSING), now()),
            Decision::Allow { warnings: vec![] }
        );
    }

    #[test]
    fn denies_failed_check_without_grace() {
        assert_eq!(
            reasons(decide(
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
            reasons(decide(&manifest(), &c, now())),
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
        assert_eq!(decide(&m, &c, now()), Decision::Allow { warnings: vec![] });
    }

    #[test]
    fn denies_result_key_not_in_manifest() {
        assert_eq!(
            reasons(decide(
                &manifest(),
                &with(&[("installed_apps", "slack")]),
                now()
            )),
            ["installed_apps is not in the manifest"]
        );
        let Decision::Deny { reasons } =
            decide(&manifest(), &with(&[("installed_apps", "slack")]), now())
        else {
            unreachable!()
        };
        assert!(reasons[0].breaks_disclosure_contract());
    }

    #[test]
    fn denies_value_outside_output_set() {
        assert_eq!(
            reasons(decide(
                &manifest(),
                &with(&[("disk_encryption", "FileVault on, disk0s2")]),
                now()
            )),
            ["disk_encryption = FileVault on, disk0s2 is not an output the manifest allows"]
        );
    }

    fn since(hours: i64) -> FirstFailures {
        FirstFailures::from([("firewall".to_string(), now() - TimeDelta::hours(hours))])
    }

    #[test]
    fn a_new_failure_starts_its_grace_and_warns_with_the_time_left() {
        let e = evaluate(
            &manifest(),
            &with(&[("firewall", "off")]),
            now(),
            &FirstFailures::new(),
        );
        assert_eq!(
            warnings(e.decision),
            ["firewall = off, on required, access ends in 24h"]
        );
        assert_eq!(e.first_failures, since(0));
    }

    #[test]
    fn grace_counts_from_the_first_failure_and_denies_once_it_has_passed() {
        let m = manifest();
        let off = with(&[("firewall", "off")]);
        let e = evaluate(&m, &off, now(), &since(1));
        assert_eq!(
            warnings(e.decision),
            ["firewall = off, on required, access ends in 23h"]
        );
        assert_eq!(e.first_failures, since(1), "the start does not move");

        let exactly = evaluate(&m, &off, now(), &since(24));
        assert_eq!(
            warnings(exactly.decision),
            ["firewall = off, on required, access ends in 0m"]
        );

        let mut late = since(24);
        *late.get_mut("firewall").unwrap() -= TimeDelta::seconds(1);
        let e = evaluate(&m, &off, now(), &late);
        assert_eq!(
            reasons(e.decision),
            ["firewall = off, on required, grace 1d ended"]
        );
        assert_eq!(e.first_failures, late);
    }

    #[test]
    fn zero_grace_denies_on_the_first_claim() {
        let e = evaluate(
            &manifest(),
            &with(&[("disk_encryption", "none")]),
            now(),
            &FirstFailures::new(),
        );
        assert_eq!(
            reasons(e.decision),
            ["disk_encryption = none, full required"]
        );
    }

    #[test]
    fn unknown_uses_unknown_grace_even_on_a_zero_grace_control_and_then_denies() {
        let m = manifest();
        let at = |t: DateTime<Utc>| {
            let mut c = with(&[("disk_encryption", "unknown")]);
            c.time = t;
            c
        };
        let e = evaluate(&m, &at(now()), now(), &FirstFailures::new());
        assert_eq!(
            warnings(e.decision),
            ["disk_encryption = unknown, full required, access ends in 7d"]
        );
        let started = e.first_failures;
        let t = now() + TimeDelta::hours(25);
        assert_eq!(
            warnings(evaluate(&m, &at(t), t, &started).decision),
            ["disk_encryption = unknown, full required, access ends in 5d 23h"]
        );
        let t = now() + TimeDelta::days(7) + TimeDelta::seconds(1);
        assert_eq!(
            reasons(evaluate(&m, &at(t), t, &started).decision),
            ["disk_encryption = unknown, full required, unknown_grace 7d ended"]
        );
    }

    #[test]
    fn switching_between_failed_and_unknown_keeps_the_clock() {
        let m = manifest();
        let e = evaluate(&m, &with(&[("firewall", "unknown")]), now(), &since(30));
        assert_eq!(e.first_failures, since(30));
        let e = evaluate(&m, &with(&[("firewall", "off")]), now(), &e.first_failures);
        assert_eq!(
            reasons(e.decision),
            ["firewall = off, on required, grace 1d ended"]
        );
    }

    #[test]
    fn only_a_passing_value_clears_the_clock() {
        let m = manifest();
        let passed = evaluate(&m, &with(&[]), now(), &since(5));
        assert_eq!(passed.decision, Decision::Allow { warnings: vec![] });
        assert_eq!(passed.first_failures, FirstFailures::new());

        let mut c = with(&[]);
        c.results.remove("firewall");
        let missing = evaluate(&m, &c, now(), &since(5));
        assert_eq!(
            reasons(missing.decision),
            ["firewall missing, required on macos"]
        );
        assert_eq!(
            missing.first_failures,
            since(5),
            "a missing result keeps the clock"
        );
    }

    #[test]
    fn a_claim_with_a_broken_envelope_leaves_the_clock_alone() {
        let m = manifest();
        for broken in [
            {
                let mut c = with(&[]);
                c.manifest = ManifestHash::of(b"other");
                c
            },
            with(&[("installed_apps", "slack")]),
            with(&[("screen_lock", "never, set by admin")]),
            {
                let mut c = with(&[]);
                c.time = now() - TimeDelta::days(2);
                c
            },
        ] {
            let e = evaluate(&m, &broken, now(), &since(5));
            assert!(matches!(e.decision, Decision::Deny { .. }));
            assert_eq!(e.first_failures, since(5));
        }
        let fresh = evaluate(
            &m,
            &with(&[("installed_apps", "x"), ("firewall", "off")]),
            now(),
            &FirstFailures::new(),
        );
        assert_eq!(
            fresh.first_failures,
            FirstFailures::new(),
            "a refused claim plants nothing"
        );
    }

    #[test]
    fn remaining_time_is_rounded_down() {
        let r = |d: TimeDelta| Remaining(d).to_string();
        assert_eq!(r(TimeDelta::minutes(59)), "59m");
        assert_eq!(r(TimeDelta::minutes(61)), "1h");
        assert_eq!(r(TimeDelta::hours(47) + TimeDelta::minutes(59)), "47h");
        assert_eq!(r(TimeDelta::hours(48)), "2d");
        assert_eq!(r(TimeDelta::hours(14 * 24 - 1)), "13d 23h");
    }

    #[test]
    fn denies_claim_for_another_manifest() {
        let mut c = claim(&PASSING);
        c.manifest = ManifestHash::of(b"other");
        assert_eq!(reasons(decide(&manifest(), &c, now())).len(), 1);
    }

    #[test]
    fn denies_before_valid_from() {
        let early = "2026-09-30T23:59:59Z".parse().unwrap();
        let mut c = claim(&PASSING);
        c.time = early;
        assert_eq!(
            reasons(decide(&manifest(), &c, early)),
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
            reasons(decide(&m, &c, now())),
            [
                "min_trust_level L1 needs attestation, which is not available: \
              every claim counts as L0 (this one asserts L0)"
            ]
        );
    }

    #[test]
    fn an_asserted_trust_level_without_attestation_counts_as_l0() {
        for min in ["L1", "L2"] {
            let toml = DEMO.replace(
                r#"min_trust_level = "L0""#,
                &format!("min_trust_level = \"{min}\""),
            );
            let m = Manifest::parse(toml.as_bytes()).unwrap();
            let mut c = claim(&PASSING);
            c.manifest = m.hash().clone();
            c.trust_level = TrustLevel::L2;
            let Decision::Deny { reasons } = decide(&m, &c, now()) else {
                panic!("an asserted L2 met min_trust_level {min}");
            };
            assert_eq!(
                texts(&reasons),
                [format!(
                    "min_trust_level {min} needs attestation, which is not available: \
                     every claim counts as L0 (this one asserts L2)"
                )]
            );
        }
    }

    #[test]
    fn denies_claim_older_than_claim_max_age() {
        let mut c = claim(&PASSING);
        c.time = now() - TimeDelta::hours(24);
        assert_eq!(
            decide(&manifest(), &c, now()),
            Decision::Allow { warnings: vec![] }
        );
        c.time = now() - TimeDelta::hours(24) - TimeDelta::seconds(1);
        assert_eq!(
            reasons(decide(&manifest(), &c, now())),
            ["claim time 2026-10-11 08:59:59 UTC is older than claim_max_age 24h"]
        );
    }

    #[test]
    fn denies_claim_from_the_future() {
        let mut c = claim(&PASSING);
        c.time = now() + TimeDelta::minutes(5);
        assert_eq!(
            decide(&manifest(), &c, now()),
            Decision::Allow { warnings: vec![] }
        );
        c.time = now() + TimeDelta::minutes(6);
        assert_eq!(
            reasons(decide(&manifest(), &c, now())),
            ["claim time 2026-10-12 09:06:00 UTC is more than 5 minutes in the future"]
        );
    }
}
