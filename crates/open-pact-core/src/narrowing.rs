use std::collections::BTreeSet;

use crate::{Manifest, Metadata, OnConnect, Os, Output, Place, Schedule};

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
    #[error("control {id} widens or changes its output kind")]
    OutputWidened { id: String },
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
    #[error("control {id} changes remote patterns")]
    RemotesChanged { id: String },
    #[error("unknown_grace is shorter")]
    UnknownGraceShorter,
    #[error("claim_max_age is shorter")]
    MaxAgeShorter,
    #[error("min_trust_level is higher")]
    TrustLevelHigher,
    #[error("the [log] witness policy changed")]
    WitnessPolicyChanged,
    #[error(
        "the [schedule] adds automatic claims, sends them more often or in more places, or checks more often"
    )]
    ScheduleWidened,
}

fn added<T: Ord + Clone>(old: &BTreeSet<T>, new: &BTreeSet<T>) -> Vec<T> {
    new.difference(old).cloned().collect()
}

/// True when the new schedule asks more of the owner than the one the owner signed. It counts as
/// more when a send or check period rises at the VPN or elsewhere, when the VPN interval is shorter
/// as written, when it probes another address, or when it sends a claim at once on connect where
/// the old one waited for its interval. A rate that falls, or a removed part, is never a widening.
pub fn schedule_widened(old: Option<&Schedule>, new: Option<&Schedule>) -> bool {
    new.is_some_and(|now| {
        old.is_none_or(|was| {
            let at = [Place::Vpn, Place::Elsewhere];
            let sends_more = at
                .into_iter()
                .any(|place| rises(was.period(place), now.period(place)))
                || rises(was.vpn_interval(), now.vpn_interval());
            let checks_more = at
                .into_iter()
                .any(|place| rises(was.check_period(place), now.check_period(place)));
            let new_probe = now.probe().is_some() && was.probe() != now.probe();
            let connects_sooner = was.on_connect() == Some(OnConnect::WaitForInterval)
                && now.on_connect() == Some(OnConnect::Send);
            sends_more || checks_more || new_probe || connects_sooner
        })
    })
}

/// Whether a rate rises: it appears where there was none, or it gets shorter. A rate that goes
/// away does not rise.
fn rises<T: Ord>(was: Option<T>, now: Option<T>) -> bool {
    match (was, now) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(was), Some(now)) => now < was,
    }
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
        let old_remotes: BTreeSet<_> = o.remotes.iter().collect();
        let new_remotes: BTreeSet<_> = c.remotes.iter().collect();
        if old_remotes != new_remotes {
            v.push(Violation::RemotesChanged { id: c.id.clone() });
        }
        if !c.output.is_subset_of(&o.output) {
            match (&c.output, &o.output) {
                (Output::Enumerated(now), Output::Enumerated(old)) => {
                    v.push(Violation::OutputsAdded {
                        id: c.id.clone(),
                        added: now.iter().filter(|x| !old.contains(x)).cloned().collect(),
                    })
                }
                _ => v.push(Violation::OutputWidened { id: c.id.clone() }),
            }
        }
        for os in Os::ALL {
            let stricter = match (o.required.get(&os), c.required.get(&os)) {
                (_, None) => false,
                (None, Some(_)) => true,
                (Some(was), Some(now)) => !now.is_superset_of(was),
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
    if new.log != old.log {
        v.push(Violation::WitnessPolicyChanged);
    }
    if schedule_widened(old.schedule.as_ref(), new.schedule.as_ref()) {
        v.push(Violation::ScheduleWidened);
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
    fn any_witness_policy_change_needs_the_owner() {
        let listed = DEMO
            .lines()
            .find(|l| l.starts_with("witnesses = "))
            .unwrap();
        rejected(
            &[
                (listed, "witnesses = []\nallow_split_views = true"),
                ("witness_quorum = 1", "witness_quorum = 0"),
            ],
            Violation::WitnessPolicyChanged,
        );
        rejected(
            &[(
                r#"checkpoint_max_age = "1h""#,
                r#"checkpoint_max_age = "2h""#,
            )],
            Violation::WitnessPolicyChanged,
        );
    }

    #[test]
    fn a_wider_schedule_needs_the_owner_and_a_narrower_one_does_not() {
        rejected(
            &[(r#"interval = "55m""#, r#"interval = "30m""#)],
            Violation::ScheduleWidened,
        );
        rejected(
            &[(
                r#"vpn_probe = "10.0.0.1:443""#,
                r#"vpn_probe = "10.0.0.2:443""#,
            )],
            Violation::ScheduleWidened,
        );
        assert_eq!(
            check(&[(r#"interval = "55m""#, r#"interval = "2h""#)]),
            Ok(())
        );
        let without = DEMO.find("\n[schedule]").unwrap();
        let old = Manifest::parse(&DEMO.as_bytes()[..without]).unwrap();
        let new = Manifest::parse(DEMO.as_bytes()).unwrap();
        assert_eq!(
            is_narrowing(&old, &new),
            Err(vec![Violation::ScheduleWidened])
        );
        assert_eq!(is_narrowing(&new, &old), Ok(()));
    }

    #[test]
    fn schedule_widening_matches_the_signed_schedule_policy() {
        let vpn_55m: Schedule =
            toml::from_str("mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"55m\"")
                .unwrap();
        let vpn_30m: Schedule =
            toml::from_str("mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"30m\"")
                .unwrap();
        let vpn_2h: Schedule =
            toml::from_str("mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"2h\"")
                .unwrap();
        let vpn_other_probe: Schedule =
            toml::from_str("mode = \"vpn\"\nvpn_probe = \"10.0.0.2:443\"\ninterval = \"55m\"")
                .unwrap();
        let vpn_other_name: Schedule = toml::from_str(
            "mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\nvpn_probe_name = \"other.example.org\"\ninterval = \"55m\"",
        )
        .unwrap();
        let always_55m: Schedule = toml::from_str("mode = \"always\"\ninterval = \"55m\"").unwrap();

        assert!(schedule_widened(None, Some(&vpn_55m)));
        assert!(!schedule_widened(Some(&vpn_55m), None));
        assert!(schedule_widened(Some(&vpn_55m), Some(&always_55m)));
        assert!(schedule_widened(Some(&always_55m), Some(&vpn_55m)));
        assert!(schedule_widened(Some(&vpn_55m), Some(&vpn_other_probe)));
        assert!(schedule_widened(Some(&vpn_55m), Some(&vpn_other_name)));
        assert!(schedule_widened(Some(&vpn_55m), Some(&vpn_30m)));
        assert!(!schedule_widened(Some(&vpn_55m), Some(&vpn_2h)));
        assert!(!schedule_widened(Some(&vpn_55m), Some(&vpn_55m)));
        assert!(!schedule_widened(None, None));
    }

    fn places(table: &str) -> Schedule {
        toml::from_str(table).unwrap()
    }

    const VPN: &str = "[vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"1h\"\n";

    #[test]
    fn the_place_form_widens_when_it_sends_more_or_checks_more() {
        let base = places(VPN);
        let always = |interval: &str| format!("[always]\ninterval = \"{interval}\"\n");
        let widened = |old: &Schedule, new: &Schedule| schedule_widened(Some(old), Some(new));

        assert!(!widened(&base, &base));
        // A shorter send interval on the VPN.
        assert!(widened(
            &base,
            &places("[vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"30m\"\n")
        ));
        assert!(!widened(
            &base,
            &places("[vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"2h\"\n")
        ));
        // A shorter check period on the VPN, a longer one, and the same one written out.
        let checks = |check: &str| {
            places(&format!(
                "[vpn]\nprobe = \"10.0.0.1:443\"\ncheck = \"{check}\"\ninterval = \"1h\"\n"
            ))
        };
        assert!(widened(&base, &checks("1m")));
        assert!(widened(&checks("10m"), &checks("9m")));
        assert!(!widened(&base, &checks("5m")));
        assert!(!widened(&base, &checks("10m")));
        // Adding the part for any network, shortening it, and lengthening it.
        let both = |interval: &str| places(&format!("{VPN}{}", always(interval)));
        assert!(widened(&base, &both("24h")));
        assert!(!widened(&both("24h"), &base));
        assert!(widened(&both("24h"), &both("12h")));
        assert!(!widened(&both("12h"), &both("24h")));
        // Dropping the VPN part keeps the cadence on the VPN and narrows the rest.
        assert!(!widened(&both("24h"), &places(&always("24h"))));
        assert!(widened(&places(&always("24h")), &places(&always("12h"))));
        assert!(!widened(&places(&always("12h")), &places(&always("24h"))));
        // A new probe, or a new TLS name, needs the owner.
        assert!(widened(
            &base,
            &places("[vpn]\nprobe = \"10.0.0.2:443\"\ninterval = \"1h\"\n")
        ));
        assert!(widened(
            &base,
            &places(
                "[vpn]\nprobe = \"10.0.0.1:443\"\nprobe_name = \"vpn.example.org\"\ninterval = \"1h\"\n"
            )
        ));
        // A part for any network is wider than none, in either order of forms.
        assert!(schedule_widened(None, Some(&base)));
        assert!(!schedule_widened(Some(&base), None));
    }

    #[test]
    fn the_flat_form_widens_into_the_place_form_only_where_it_sends_more() {
        let flat_vpn = places("mode = \"vpn\"\nvpn_probe = \"10.0.0.1:443\"\ninterval = \"1h\"");
        let flat_always = places("mode = \"always\"\ninterval = \"1h\"");
        let widened = |old: &Schedule, new: &Schedule| schedule_widened(Some(old), Some(new));

        // The same interval, but the connect claim no longer waits for it.
        assert!(widened(&flat_vpn, &places(VPN)));
        // Even with a longer interval and the same check period: the owner never agreed to it.
        assert!(widened(
            &flat_vpn,
            &places("[vpn]\nprobe = \"10.0.0.1:443\"\ncheck = \"5m\"\ninterval = \"2h\"\n")
        ));
        // Adding any network to a flat VPN schedule widens.
        assert!(widened(
            &flat_vpn,
            &places(&format!("{VPN}[always]\ninterval = \"24h\"\n"))
        ));
        // The flat form for any network rewritten as the place form is the same schedule.
        assert!(!widened(
            &flat_always,
            &places("[always]\ninterval = \"1h\"\n")
        ));
        assert!(widened(
            &flat_always,
            &places("[always]\ninterval = \"30m\"\n")
        ));
        // The place form never widens into the flat form by itself: it sends no sooner on connect.
        assert!(!widened(&places(VPN), &flat_vpn));
    }

    #[test]
    fn a_manifest_that_adds_the_part_for_any_network_needs_the_owner() {
        let start = DEMO.find("\n[schedule]").unwrap();
        let head = &DEMO[..start];
        let vpn = format!("{head}\n[schedule.vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"1h\"\n");
        let both = format!("{vpn}\n[schedule.always]\ninterval = \"24h\"\n");
        let (vpn, both) = (
            Manifest::parse(vpn.as_bytes()).unwrap(),
            Manifest::parse(both.as_bytes()).unwrap(),
        );
        assert_eq!(
            is_narrowing(&vpn, &both),
            Err(vec![Violation::ScheduleWidened])
        );
        assert_eq!(is_narrowing(&both, &vpn), Ok(()));
    }

    #[test]
    fn removing_the_vpn_part_widens_when_the_any_network_part_checks_more() {
        // The any-network part checks every 5 minutes wherever it applies, so dropping a VPN part
        // that checked every 10 minutes raises the check rate on the VPN.
        let old = places(
            "[vpn]\nprobe = \"10.0.0.1:443\"\ncheck = \"10m\"\ninterval = \"1h\"\n[always]\ninterval = \"1h\"\n",
        );
        assert!(schedule_widened(
            Some(&old),
            Some(&places("[always]\ninterval = \"1h\"\n"))
        ));
        assert!(schedule_widened(
            Some(&old),
            Some(&places("mode = \"always\"\ninterval = \"1h\""))
        ));
        // With the default check period the same removal checks no more and sends no more.
        let default_check = places(
            "[vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"1h\"\n[always]\ninterval = \"1h\"\n",
        );
        assert!(!schedule_widened(
            Some(&default_check),
            Some(&places("[always]\ninterval = \"1h\"\n"))
        ));
    }

    #[test]
    fn a_shorter_vpn_interval_widens_even_when_the_any_network_interval_is_shorter() {
        let old = places(
            "[vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"1h\"\n[always]\ninterval = \"5m\"\n",
        );
        let new = places(
            "[vpn]\nprobe = \"10.0.0.1:443\"\ninterval = \"30m\"\n[always]\ninterval = \"5m\"\n",
        );
        assert!(schedule_widened(Some(&old), Some(&new)));
        assert!(!schedule_widened(Some(&new), Some(&old)));
    }

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
        let extra = "\n[[control]]\nid = \"fictional_new_control\"\nsource = \"standard\"\ncheck = \"builtin:fictional_new_control@1\"\noutput = [\"on\", \"off\"]\nrequired = {}\ngrace = \"0d\"\n";
        rejected(
            &[("grace = \"14d\"\n", &format!("grace = \"14d\"\n{extra}"))],
            Violation::NewControl {
                id: "fictional_new_control".into(),
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
