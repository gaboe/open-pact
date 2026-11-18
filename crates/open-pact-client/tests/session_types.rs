//! The status result of a Session, and the enums and evidence it holds, can be named from outside
//! the crate. An app keeps them in its own state, so a missing public path fails to compile here.

use std::path::PathBuf;

use open_pact_client::status::{
    ApprovalEvidence, ClaimEvidence, Issue, ManifestEvidence, Report, ScheduleEvidence,
    ScheduledClaim, Urgency, Verdict,
};
use open_pact_client::{JobStatus, Notice, Session};

#[tokio::test]
async fn the_status_result_and_its_enums_have_a_public_path() {
    let home = tempfile::tempdir().unwrap();
    let session = Session::open(
        Some(home.path().to_path_buf()),
        PathBuf::from(env!("CARGO_BIN_EXE_open-pact-client")),
    )
    .unwrap();

    let report: Report = session.status(false).await.unwrap();

    let verdict: Verdict = report.verdict;
    let urgencies: Vec<Urgency> = report
        .issues
        .iter()
        .map(|issue: &Issue| issue.urgency)
        .collect();
    let approval: &ApprovalEvidence = &report.approval;
    let _last_claim: Option<&ClaimEvidence> = report.last_claim.as_ref();
    let _manifest: Option<&ManifestEvidence> = report.manifest.as_ref();
    let schedule: &ScheduleEvidence = &report.schedule;
    let _scheduled: Option<&ScheduledClaim> = schedule.last_scheduled_claim.as_ref();
    let job: Option<JobStatus> = schedule.job_status;
    let update: Option<&Notice> = report.update.as_ref();

    // A device that never joined: its report names the state, and one action is due.
    match verdict {
        Verdict::NoKnownProblem | Verdict::ActionNeeded | Verdict::Alarm | Verdict::Unknown => {}
    }
    assert_eq!(verdict, Verdict::Unknown, "{report:?}");
    assert_eq!(urgencies, [Urgency::Action]);
    assert_eq!(approval.source, "not enrolled");
    assert_eq!(job, None);
    assert!(update.is_none());
}
