//! Fictional reports for pictures and tests, built as values of the client library's types. A
//! picture of a screen needs a report in a known state, and the library has no fixture files.

use open_pact_client::status::{
    ApprovalEvidence, ClaimEvidence, Issue, ManifestEvidence, Report, ScheduleEvidence,
    ScheduledClaim, Urgency, Verdict,
};
use open_pact_client::{
    AcceptPreview, ClaimReport, ControlReport, JobStatus, JoinPreview, ManifestChange, Notice,
    PreviewCompany, PreviewControl,
};
use open_pact_core::{ControlValue, DeviceStatus, ManifestHash, Schedule};
use std::collections::BTreeMap;

/// A manifest hash from its first hex digits; the rest is zeros.
pub fn hash(digits: &str) -> ManifestHash {
    ManifestHash::try_from(format!("sha256:{digits:0<64}")).expect("a fictional hash")
}

fn issue(
    urgency: Urgency,
    message: &str,
    fix: &str,
    command: Option<&str>,
    deadline: &str,
) -> Issue {
    Issue {
        urgency,
        message: message.into(),
        fix: Some(fix.into()),
        command: command.map(str::to_owned),
        stop_job_command: None,
        deadline: deadline.into(),
    }
}

fn base() -> Report {
    Report {
        schema_version: 1,
        observed_at: "2026-11-16T15:00:00Z".into(),
        mode: "local",
        verdict: Verdict::ActionNeeded,
        exit_code: 2,
        online_command: None,
        current_compliance: "unknown; status does not run checks or send a claim",
        approval: ApprovalEvidence {
            state: Some(DeviceStatus::Approved),
            live: false,
            source: "saved on this device; not refreshed".into(),
        },
        last_claim: Some(ClaimEvidence {
            sent_at: Some("2026-11-16T10:53:00Z".into()),
            response_at: "2026-11-16T10:53:00Z".into(),
            response: "accepted".into(),
            warnings: Vec::new(),
            reasons: Vec::new(),
            manifest: None,
            os: None,
            results: BTreeMap::from([("password_min_length".into(), ControlValue::Integer(4))]),
        }),
        manifest: Some(ManifestEvidence {
            signed: hash("97e1594a7b1c"),
            enforced: None,
            agreement: "unknown; gateway not checked".into(),
        }),
        schedule: ScheduleEvidence {
            owner_consented: Some(true),
            policy: "every 55 min on VPN".into(),
            policy_defined: true,
            job: "OS job not checked".into(),
            job_status: None,
            system_job: false,
            vpn: "not checked".into(),
            last_scheduled_claim: Some(ScheduledClaim {
                answered_at: "2026-11-16T10:53:00Z".into(),
                response: Some("accepted".into()),
            }),
            last_job_note: None,
            last_job_log_line: None,
            last_job_log_note: None,
        },
        log: "not verified by status".into(),
        issues: vec![
            issue(
                Urgency::Action,
                "Password is 4 characters, 10 needed",
                "Change it in System Settings › Users & Groups.",
                None,
                "Exact deadline unavailable.",
            ),
            issue(
                Urgency::Warning,
                "Antimalware signatures are 4 days old, 3 allowed",
                "Install updates in System Settings › General › Software Update.",
                None,
                "Exact deadline unavailable.",
            ),
        ],
        limitations: vec!["Local mode makes no network or OS job queries.".into()],
        update: None,
    }
}

/// A device that is approved and has sent a claim, with two things to fix.
pub fn report(verdict: Verdict, issues: usize) -> Report {
    let mut report = base();
    report.verdict = verdict;
    report.issues.truncate(issues);
    report
}

/// Everything in order: no issue, and the gateway agrees.
pub fn report_good() -> Report {
    report(Verdict::NoKnownProblem, 0)
}

/// An approved device that has not sent its first claim.
pub fn report_approved_without_claim() -> Report {
    let mut report = base();
    report.approval.live = true;
    report.last_claim = None;
    report
}

fn online() -> Report {
    let mut report = base();
    report.mode = "online";
    report.approval.live = true;
    report.approval.source = "gateway refreshed now".into();
    report.manifest = Some(ManifestEvidence {
        signed: hash("97e1594a7b1c"),
        enforced: Some(hash("97e1594a7b1c")),
        agreement: "yes; gateway checked now".into(),
    });
    report.last_claim = Some(ClaimEvidence {
        sent_at: Some("2026-11-16T14:10:35Z".into()),
        response_at: "2026-11-16T14:10:35Z".into(),
        response: "accepted".into(),
        warnings: vec![
            "antimalware_signature_age_days = 4, <= 3 required, access ends in 19h".into(),
            "password_min_length = 4, >= 10 required, access ends in 19h".into(),
        ],
        reasons: Vec::new(),
        manifest: None,
        os: None,
        results: BTreeMap::from([
            ("password_min_length".into(), ControlValue::Integer(4)),
            (
                "antimalware_signature_age_days".into(),
                ControlValue::Integer(4),
            ),
        ]),
    });
    report.schedule.policy = "only while vpn.example.test answers at 192.0.2.1:443, every 55 minutes, and at once when a check result changes".into();
    report.schedule.job = "installed and current; OS checked now".into();
    report.schedule.job_status = Some(JobStatus::Current);
    report.schedule.vpn = "probe failed now; automatic sending pauses".into();
    report.schedule.last_scheduled_claim = None;
    report.log = "checkpoint verified now; own-entry proofs not requested".into();
    report
}

fn vpn_issue() -> Issue {
    issue(
        Urgency::Action,
        "The signed VPN probe failed.",
        "Connect the company VPN, then retry.",
        Some("open-pact-client check"),
        "No grace deadline follows from the VPN probe.",
    )
}

/// Four items with buttons: an out of date job, a failed VPN probe, and two gateway findings.
pub fn report_needs_action() -> Report {
    let mut report = online();
    report.schedule.job = "out of date; OS checked now".into();
    report.schedule.job_status = Some(JobStatus::Outdated);
    report.limitations = vec![
        "Exact grace deadlines are unavailable; the gateway returns text, not first-failure times."
            .into(),
    ];
    let finding = |text: &str, fix: &str| {
        issue(
            Urgency::Warning,
            text,
            fix,
            Some("open-pact-client check"),
            "about 2026-11-17T09:10:35Z (gateway said 'access ends in 19h' at 2026-11-16T14:10:35Z)",
        )
    };
    report.issues = vec![
        issue(
            Urgency::Action,
            "Automatic sending is on, but its job needs installation or update.",
            "Install the job for the signed schedule.",
            Some("open-pact-client schedule on"),
            "Before the next automatic claim can run.",
        ),
        vpn_issue(),
        finding(
            "Gateway at 2026-11-16T14:10:35Z: antimalware_signature_age_days = 4, <= 3 required, access ends in 19h",
            "Install security data updates in System Settings > General > Software Update > Automatic Updates.",
        ),
        finding(
            "Gateway at 2026-11-16T14:10:35Z: password_min_length = 4, >= 10 required, access ends in 19h",
            "Ask IT to push a password policy with a minimum length, then run the check again.",
        ),
    ];
    report
}

/// Only the failed VPN probe.
pub fn report_vpn_only() -> Report {
    let mut report = online();
    report
        .last_claim
        .as_mut()
        .expect("a claim")
        .warnings
        .clear();
    report.issues = vec![vpn_issue()];
    report.limitations = vec![
        "Exact grace deadlines are unavailable; the gateway returns text, not first-failure times."
            .into(),
    ];
    report
}

/// A status with a newer command line tool. `command` is what updates it, or `None` when the
/// app update brings it.
pub fn report_with_update(command: Option<&'static str>) -> Report {
    let mut report = base();
    report.update = Some(Notice {
        current: "0.6.0".into(),
        latest: "0.6.1".into(),
        command,
    });
    report
}

/// A first claim the company did not accept.
pub fn denied_check() -> ClaimReport {
    ClaimReport {
        sent_at: "2026-11-16T11:48:00Z".into(),
        accepted: false,
        warnings: Vec::new(),
        reasons: vec![
            "client must be \"open-pact-client <major>.<minor>.<patch>\"".into(),
            "antimalware_signature_age_days = 6, <= 3 required, grace 1d ended".into(),
            "password_min_length = 4, >= 10 required, grace 1d ended".into(),
        ],
        controls: vec![
            ControlReport {
                id: "password_min_length".into(),
                value: ControlValue::Integer(4),
                ok: Some(false),
            },
            ControlReport {
                id: "antimalware_signature_age_days".into(),
                value: ControlValue::Integer(6),
                ok: Some(false),
            },
        ],
    }
}

/// What joining Example Company would sign.
pub fn preview() -> JoinPreview {
    let control = |id: &str, title: &str, requirement: &str| PreviewControl {
        id: id.into(),
        title: title.into(),
        requirement: requirement.into(),
        rationale: None,
    };
    JoinPreview {
        company: PreviewCompany {
            name: "Example Company".into(),
            key_fingerprint: "7f3a 91c2 04e8".into(),
            matches_invitation: true,
        },
        gateway: "https://gateway.example.invalid".into(),
        manifest_hash: hash("97e1594a"),
        controls: vec![
            control("disk_encryption", "Disk encryption", "on"),
            control("firewall", "Firewall", "on"),
            control("screen_lock", "Screen locks after", "5 min or less"),
            control(
                "password_min_length",
                "Password length",
                "10 characters or more",
            ),
            control(
                "antimalware",
                "Antimalware signatures",
                "3 days old or less",
            ),
        ],
        disclosed_metadata: vec![
            "check results".into(),
            "client version".into(),
            "OS".into(),
            "a pseudonym for this device".into(),
        ],
        schedule: Some(
            serde_json::from_value::<Schedule>(serde_json::json!({
                "mode": "vpn",
                "vpn_probe": "10.0.0.1:443",
                "interval": "55m",
            }))
            .expect("a fictional schedule"),
        ),
        folders: vec!["~/Documents".into()],
    }
}

/// The manifest the company enforces changed two lines against the one this device signed.
pub fn changes() -> AcceptPreview {
    AcceptPreview {
        signed_hash: hash("a1"),
        published_hash: hash("b2"),
        changes: vec![
            ManifestChange::new("Password length", Some("8".into()), Some("10".into())),
            ManifestChange::new(
                "Send results automatically",
                Some("2h".into()),
                Some("55m".into()),
            ),
        ],
        schedule_widened: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sample_builds() {
        report_good();
        report_approved_without_claim();
        report_needs_action();
        report_vpn_only();
        report_with_update(None);
        denied_check();
        assert_eq!(changes().changes.len(), 2);
        assert!(preview().schedule.is_some());
    }
}
