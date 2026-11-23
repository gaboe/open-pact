//! Plain-words wording for the typed reports of the client library. No UI code lives here.

use crate::text::{Headline, Tone, humanize, readable_local};
use crate::zone;
use open_pact_client::ControlReport;
use open_pact_client::JobStatus;
use open_pact_client::machine::MachineState;
use open_pact_client::status::{ClaimEvidence, Issue, Report, ScheduleEvidence, Verdict};
use open_pact_core::timestamp::{parse_rfc3339, seconds};
use open_pact_core::{ControlValue, DeviceStatus};
use time::macros::format_description;
use time::{Duration, OffsetDateTime};

pub fn headline(status: &Report) -> Headline {
    let last = status.last_claim.as_ref().map(|claim| {
        let at = readable_local(&claim.response_at);
        match claim.response.as_str() {
            "denied" => format!("The company denied access on {at}."),
            "accepted" => format!("The company accepted the last check on {at}."),
            other => format!("Last result {at}, {other}."),
        }
    });
    // The heading counts every row the screen lists under it. A failed VPN probe alone gets its own heading.
    let off_vpn = status.issues.iter().any(is_vpn_probe);
    let count = status.issues.len();
    let fixes = status
        .issues
        .iter()
        .filter(|issue| !is_vpn_probe(issue))
        .count();
    match status.verdict {
        Verdict::NoKnownProblem => Headline {
            tone: Tone::Good,
            heading: "All good".into(),
            detail: last.unwrap_or_else(|| "No result saved on this device yet.".into()),
        },
        Verdict::ActionNeeded => Headline {
            tone: Tone::Warn,
            heading: match (count, off_vpn) {
                (0, _) => "Action needed".into(),
                (1, true) => "Not on the company VPN".into(),
                (1, false) => "Fix 1 thing".into(),
                (n, _) => format!("Fix {n} things"),
            },
            // What happened, what to do, then why the next check may not arrive.
            detail: [
                last,
                (fixes > 0 || !off_vpn)
                    .then(|| "Fix the items below, then press Check now.".into()),
                off_vpn.then(|| {
                    "Connect the company VPN, so that the next check reaches the company.".into()
                }),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" "),
        },
        Verdict::Alarm => Headline {
            tone: Tone::Bad,
            heading: "Tell IT now".into(),
            detail: status
                .issues
                .first()
                .and_then(|issue| issue.fix.clone())
                .unwrap_or_else(|| "Keep the last checkpoint and tell IT.".into()),
        },
        Verdict::Unknown => Headline {
            tone: Tone::Idle,
            heading: "Not checked yet".into(),
            detail: "Press Check now to see where this device stands.".into(),
        },
    }
}

pub fn deadline_text(issue: &Issue) -> Option<String> {
    let lower = issue.deadline.to_lowercase();
    (!lower.is_empty() && !lower.contains("unavailable") && !lower.starts_with("unknown"))
        .then(|| issue.deadline.clone())
}

/// What an action item can do with a button. The CLI names the command of each item, so the
/// choice follows the end of `Issue::command`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueAction {
    /// `schedule on`
    InstallJob,
    /// `schedule off`
    TurnOffJob,
    /// `status --online`
    Retry,
    /// `accept`: the manifest review.
    Review,
}

impl IssueAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::InstallJob => "Install job",
            Self::TurnOffJob => "Turn off job",
            Self::Retry => "Retry",
            Self::Review => "Review changes",
        }
    }
}

/// The CLI gives a failed VPN probe the command `check`, which would send a claim. A probe is
/// retried with `status --online`. The status JSON has no stable kind field, so this is the one
/// item found by its message.
pub fn is_vpn_probe(issue: &Issue) -> bool {
    issue.message.starts_with("The signed VPN probe failed")
}

pub fn issue_action(issue: &Issue) -> Option<IssueAction> {
    if is_vpn_probe(issue) {
        return Some(IssueAction::Retry);
    }
    let command = issue.command.as_deref()?;
    let ends = |action: &str| command.ends_with(&format!(" {action}"));
    if ends("schedule on") {
        Some(IssueAction::InstallJob)
    } else if ends("schedule off") {
        Some(IssueAction::TurnOffJob)
    } else if ends("status --online") {
        Some(IssueAction::Retry)
    } else if ends("accept") {
        Some(IssueAction::Review)
    } else {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueView {
    pub title: String,
    pub fix: Option<String>,
    pub note: Option<String>,
    pub action: Option<IssueAction>,
}

/// A gateway answer such as `Gateway at <time>: <id> = <value>, <required> required, access ends in 19h`.
struct Finding<'a> {
    at: &'a str,
    id: &'a str,
    value: &'a str,
    required: &'a str,
    span: Option<&'a str>,
}

fn parse_finding(message: &str) -> Option<Finding<'_>> {
    let (at, body) = message.strip_prefix("Gateway at ")?.split_once(": ")?;
    let (id, rest) = body.split_once(" = ")?;
    if id.contains(' ') {
        return None;
    }
    let (value, rest) = rest.split_once(", ")?;
    let (required, tail) = rest.split_once(" required")?;
    Some(Finding {
        at,
        id,
        value,
        required,
        span: tail.strip_prefix(", access ends in "),
    })
}

/// "19h", "30m", "3d" or "2d 5h" as the gateway prints the time left.
pub(crate) fn span_delta(span: &str) -> Option<Duration> {
    let mut total = Duration::ZERO;
    let mut parts = 0;
    for part in span.split(' ') {
        let (number, unit) = part.split_at(part.len().checked_sub(1)?);
        let number: i64 = number.parse().ok()?;
        total += match unit {
            "m" => seconds(number.checked_mul(60)?)?,
            "h" => seconds(number.checked_mul(3600)?)?,
            "d" => seconds(number.checked_mul(86_400)?)?,
            _ => return None,
        };
        parts += 1;
    }
    (1..=2).contains(&parts).then_some(total)
}

const MEASURES: &[(&str, &str)] = &[
    (
        "password_min_length",
        "Password policy allows {} characters",
    ),
    ("os_patch_age_days", "System updates are {} days old"),
    (
        "antimalware_signature_age_days",
        "Antimalware signatures are {} days old",
    ),
    (
        "antimalware_full_scan_age_days",
        "The last malware scan was {} days ago",
    ),
    ("log_oldest_record_days", "The event log covers {} days"),
];

const CONTROL_NAMES: &[(&str, &str)] = &[
    ("os_auto_updates", "Automatic updates"),
    ("antimalware_realtime", "Real-time malware protection"),
    ("antimalware_active_threats", "Active threats"),
    ("disk_encryption", "Disk encryption"),
    ("firewall", "Firewall"),
    ("screen_lock", "Screen lock"),
    ("os_supported", "Operating system support"),
    ("os_patch_age_days", "System update age"),
    ("password_set", "Password"),
    ("password_min_length", "Password length"),
    ("auto_login", "Automatic login"),
    ("secure_boot", "Secure boot"),
    ("antimalware_active", "Malware protection"),
    ("preboot_auth", "Boot-time sign-in"),
    ("antimalware_signature_age_days", "Malware signature age"),
    ("antimalware_full_scan_age_days", "Malware scan age"),
    ("web_protection", "Web protection"),
    ("log_oldest_record_days", "Event log history"),
    ("process_audit", "Process auditing"),
    ("remote_wipe", "Remote wipe"),
    ("powershell_logging", "PowerShell logging"),
    ("log_cleared", "Cleared event log"),
];

fn finding_title(finding: &Finding) -> String {
    let name = CONTROL_NAMES
        .iter()
        .find(|(id, _)| *id == finding.id)
        .map_or_else(|| humanize(finding.id), |(_, name)| (*name).to_owned());
    if finding.value == "unknown" {
        return format!("{name} could not be read");
    }
    let measure = MEASURES
        .iter()
        .find(|(id, _)| *id == finding.id)
        .map(|(_, sentence)| sentence.replace("{}", finding.value));
    if let Some(sentence) = measure {
        if let Some(limit) = finding.required.strip_prefix(">= ") {
            return format!("{sentence}, at least {limit} needed");
        }
        if let Some(limit) = finding.required.strip_prefix("<= ") {
            return format!("{sentence}, at most {limit} allowed");
        }
    }
    let required = match finding.required {
        "le_5min" => "5 minutes or less".to_owned(),
        other => other.replace('_', " "),
    };
    format!("{name} is {}, it must be {required}", finding.value)
}

/// The words for one action item. The raw CLI text stays in the command log.
pub fn issue_view(
    issue: &Issue,
    now: OffsetDateTime,
    zone: impl Fn(OffsetDateTime) -> OffsetDateTime,
) -> IssueView {
    let action = issue_action(issue);
    let Some(finding) = parse_finding(&issue.message) else {
        let message = issue.message.as_str();
        let title = message
            .strip_prefix("Gateway at ")
            .and_then(|rest| rest.split_once(": "))
            .map_or(message, |(_, text)| text);
        return IssueView {
            title: title.to_owned(),
            fix: issue.fix.clone(),
            note: deadline_text(issue),
            action,
        };
    };
    let at = parse_rfc3339(finding.at);
    let when = |time: OffsetDateTime| {
        zone(time)
            .format(format_description!(
                "[day padding:none] [month repr:short], [hour]:[minute]"
            ))
            .unwrap_or_default()
    };
    let note = match (finding.span, at) {
        (Some(span), Some(at)) => {
            span_delta(span)
                .and_then(|left| at.checked_add(left))
                .map(|deadline| {
                    if deadline < now {
                        format!("Access ended {}", when(deadline))
                    } else {
                        format!("Access ends {} unless fixed", when(deadline))
                    }
                })
        }
        (None, Some(at)) => Some(format!("Refused by the gateway on {}", when(at))),
        _ => None,
    };
    IssueView {
        title: finding_title(&finding),
        fix: issue.fix.clone(),
        note,
        action,
    }
}

/// `issue_view` in the time zone of this computer. `now` is an RFC 3339 time that a fixture sets
/// so that a picture does not change with the day; the app passes `None`.
pub fn issue_view_local(issue: &Issue, now: Option<&str>) -> IssueView {
    let now = now
        .and_then(parse_rfc3339)
        .unwrap_or_else(OffsetDateTime::now_utc);
    issue_view(issue, now, zone::to_local)
}

/// The title, value and verdict of one control of a claim. A control the manifest does not require
/// here has no verdict and reads as fine.
pub fn result_control(control: &ControlReport) -> (String, String, bool) {
    let value = match &control.value {
        ControlValue::Null => String::new(),
        other => other.to_string(),
    };
    (humanize(&control.id), value, control.ok.unwrap_or(true))
}

/// The verdict of a status in a few words, for the operation log.
pub fn verdict_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::NoKnownProblem => "no known problem",
        Verdict::ActionNeeded => "action needed",
        Verdict::Alarm => "alarm",
        Verdict::Unknown => "unknown",
    }
}

/// The words for an approval state.
pub fn approval_word(state: DeviceStatus) -> &'static str {
    match state {
        DeviceStatus::Pending => "pending",
        DeviceStatus::Approved => "approved",
        DeviceStatus::Revoked => "revoked",
    }
}

/// Whether the status reports a claim sent after `check_sent_at`, so the check the app kept is
/// old. A status claim with no sent time, or none at all, supersedes nothing, and an older status
/// claim does not supersede a newer check.
pub fn check_is_superseded(check_sent_at: &str, status_claim: Option<&ClaimEvidence>) -> bool {
    let Some(status_sent) = status_claim.and_then(|claim| claim.sent_at.as_deref()) else {
        return false;
    };
    match (parse_rfc3339(status_sent), parse_rfc3339(check_sent_at)) {
        (Some(status_at), Some(check_at)) => status_at > check_at,
        _ => status_sent != check_sent_at,
    }
}

/// The join resumes when IT approves a device while the app is closed. A saved "pending" or a
/// live "approved" with no claim yet means the wizard steps for the first claim are still open.
/// Returns the automatic-sending choice to resume with.
pub fn resume_join(status: &Report) -> Option<bool> {
    let open = match status.approval.state {
        Some(DeviceStatus::Pending) => true,
        Some(DeviceStatus::Approved) => status.last_claim.is_none(),
        _ => false,
    };
    open.then(|| status.schedule.owner_consented == Some(true))
}

/// How the app turns on automatic sending, from the owner's choice that the report holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobInstall {
    /// The owner wants a user job. The library installs it.
    User,
    /// The owner wants a SYSTEM job, or chose it and it is not installed yet. Only the machine
    /// client installs it, through the administrator prompt.
    System,
    /// The owner chose a SYSTEM job and it cannot be installed from here now: the machine client is
    /// missing or unusable, or a task that is not ours is in the way. A user job must not
    /// take its place.
    Blocked,
}

/// What `Schedule on` does for this report. A pending SYSTEM choice counts as the choice: the
/// wizard saved it, and a user job would drop it.
pub fn job_install(schedule: &ScheduleEvidence) -> JobInstall {
    let pending = schedule.system_job_pending;
    if !schedule.system_job && !pending {
        return JobInstall::User;
    }
    let task = if pending {
        schedule.pending_job_status
    } else {
        schedule.job_status
    };
    let usable = matches!(
        schedule.machine_client,
        Some(MachineState::Current | MachineState::Outdated)
    );
    if usable && task != Some(JobStatus::NotOurs) {
        JobInstall::System
    } else {
        JobInstall::Blocked
    }
}

/// True when the switch for automatic sending cannot turn it on from here: the pending SYSTEM
/// choice waits for an administrator step that the status screen names.
pub fn enable_blocked(schedule: &ScheduleEvidence) -> bool {
    schedule.system_job_pending && job_install(schedule) == JobInstall::Blocked
}

/// True when the "Install job" button shows. A SYSTEM job runs the machine client, so the button
/// needs a usable machine client (current or outdated), no task of another owner, and either a
/// pending choice or a job that is missing, out of date or not confirmed. A user job keeps the
/// rule of its job text.
pub fn install_button_shown(schedule: &ScheduleEvidence, job_text: &str) -> bool {
    match job_install(schedule) {
        JobInstall::User => crate::text::job_needs_install(job_text),
        JobInstall::Blocked => false,
        JobInstall::System => {
            schedule.system_job_pending
                || matches!(
                    schedule.job_status,
                    Some(JobStatus::Missing | JobStatus::Outdated | JobStatus::SystemUnconfirmed)
                )
        }
    }
}

/// The button of an issue. While a SYSTEM choice is pending, the issue about the user job that
/// runs now keeps its text and loses its Install job button: the user install would drop the
/// choice. The pending issue and the Scheduled job row carry the SYSTEM action.
pub fn issue_action_shown(
    schedule: &ScheduleEvidence,
    action: Option<IssueAction>,
) -> Option<IssueAction> {
    action.filter(|action| !(schedule.system_job_pending && *action == IssueAction::InstallJob))
}

/// The fixes of the schedule that no issue shows already, as (label, text). The client puts the
/// same block in an issue and in the schedule, and the screen shows each block once.
pub fn schedule_fix_rows<'a>(
    schedule: &'a ScheduleEvidence,
    issues: &[Issue],
) -> Vec<(&'static str, &'a str)> {
    let shown = |text: &str| {
        issues
            .iter()
            .any(|issue| issue.fix.as_deref() == Some(text))
    };
    [
        ("Job check", schedule.job_fix.as_deref()),
        ("Machine client", schedule.machine_fix.as_deref()),
    ]
    .into_iter()
    .filter_map(|(label, text)| text.map(|text| (label, text)))
    .filter(|(_, text)| !shown(text))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::samples::{self, report};
    use open_pact_client::status::Urgency;
    use time::UtcOffset;

    fn system_schedule(
        pending: bool,
        machine: Option<MachineState>,
        task: Option<JobStatus>,
    ) -> ScheduleEvidence {
        let mut schedule = crate::samples::report_good().schedule;
        schedule.system_job = !pending;
        schedule.system_job_pending = pending;
        schedule.machine_client = machine;
        if pending {
            schedule.pending_job_status = task;
            // The user job runs until the switch succeeds.
            schedule.job_status = Some(JobStatus::Current);
        } else {
            schedule.job_status = task;
        }
        schedule
    }

    #[test]
    fn a_pending_system_choice_installs_through_the_machine_client_not_a_user_job() {
        use JobInstall::*;
        use MachineState::*;
        for machine in [Current, Outdated] {
            let schedule = system_schedule(true, Some(machine), Some(JobStatus::Missing));
            assert_eq!(job_install(&schedule), System, "{machine:?}");
            assert!(install_button_shown(&schedule, "installed and current"));
            assert!(!enable_blocked(&schedule));
        }
        // With the machine client missing the status shows its fix and no Install, and the switch
        // does not fall back to a user job, which would drop the choice.
        for machine in [Some(Missing), Some(Unprotected), Some(Unknown), None] {
            let schedule = system_schedule(true, machine, Some(JobStatus::Missing));
            assert_eq!(job_install(&schedule), Blocked, "{machine:?}");
            assert!(!install_button_shown(&schedule, "missing; OS checked now"));
            assert!(enable_blocked(&schedule));
        }
        // A known task of another owner blocks the action, whatever the machine client is.
        let schedule = system_schedule(true, Some(Current), Some(JobStatus::NotOurs));
        assert_eq!(job_install(&schedule), Blocked);
        assert!(!install_button_shown(&schedule, ""));
        assert!(enable_blocked(&schedule));
    }

    #[test]
    fn a_pending_system_choice_leaves_no_user_install_button_on_the_job_issue() {
        use MachineState::*;
        for machine in [Some(Current), Some(Missing)] {
            let schedule = system_schedule(true, machine, Some(JobStatus::Missing));
            assert_eq!(
                issue_action_shown(&schedule, Some(IssueAction::InstallJob)),
                None,
                "{machine:?}"
            );
            // The row keeps the one SYSTEM action, only with a usable machine client.
            assert_eq!(
                install_button_shown(&schedule, "missing; OS checked now"),
                machine == Some(Current)
            );
            assert_eq!(
                issue_action_shown(&schedule, Some(IssueAction::Retry)),
                Some(IssueAction::Retry)
            );
        }
        let user = system_schedule(false, None, None);
        assert_eq!(
            issue_action_shown(&user, Some(IssueAction::InstallJob)),
            Some(IssueAction::InstallJob)
        );
    }

    #[test]
    fn a_system_job_offers_install_only_with_a_usable_machine_client() {
        use MachineState::*;
        let shown = |machine, task| {
            install_button_shown(&system_schedule(false, Some(machine), Some(task)), "")
        };
        assert!(shown(Current, JobStatus::Missing));
        assert!(shown(Outdated, JobStatus::SystemUnconfirmed));
        assert!(shown(Current, JobStatus::Outdated));
        assert!(!shown(Current, JobStatus::NotOurs));
        assert!(!shown(Missing, JobStatus::Missing));
        assert!(!shown(Unprotected, JobStatus::Missing));
        assert!(!shown(Current, JobStatus::Current));
        let mut user = system_schedule(false, None, None);
        user.system_job = false;
        assert_eq!(job_install(&user), JobInstall::User);
        assert!(install_button_shown(&user, "missing; OS checked now"));
        assert!(!install_button_shown(
            &user,
            "installed and current; OS checked now"
        ));
        assert!(!enable_blocked(&user));
    }

    #[test]
    fn a_fix_that_an_issue_shows_is_not_shown_again_in_the_schedule() {
        let mut schedule = system_schedule(false, Some(MachineState::Missing), None);
        schedule.machine_fix = Some("Install block".into());
        schedule.job_fix = Some("Task fix".into());
        let issue = |fix: &str| Issue {
            urgency: open_pact_client::status::Urgency::Action,
            message: "m".into(),
            fix: Some(fix.into()),
            command: None,
            stop_job_command: None,
            deadline: "d".into(),
        };
        assert_eq!(
            schedule_fix_rows(&schedule, &[]),
            [
                ("Job check", "Task fix"),
                ("Machine client", "Install block")
            ]
        );
        assert_eq!(
            schedule_fix_rows(&schedule, &[issue("Install block")]),
            [("Job check", "Task fix")]
        );
        assert!(
            schedule_fix_rows(&schedule, &[issue("Install block"), issue("Task fix")]).is_empty()
        );
    }

    #[test]
    fn headlines_keep_uncertainty_in_plain_words() {
        let action = headline(&report(Verdict::ActionNeeded, 2));
        assert_eq!(action.heading, "Fix 2 things");
        assert_eq!(action.tone, Tone::Warn);
        assert!(action.detail.contains("then press Check now."));
        assert!(!action.detail.contains("VPN"));
        assert_eq!(
            headline(&report(Verdict::ActionNeeded, 1)).heading,
            "Fix 1 thing"
        );
        assert_eq!(
            headline(&report(Verdict::NoKnownProblem, 0)).heading,
            "All good"
        );
        assert_eq!(headline(&report(Verdict::Alarm, 0)).tone, Tone::Bad);
        assert_eq!(
            headline(&report(Verdict::Unknown, 0)).heading,
            "Not checked yet"
        );
    }

    #[test]
    fn an_approval_that_came_while_the_app_was_closed_resumes_the_join() {
        // The saved state is approved and a claim exists: nothing to resume.
        assert_eq!(resume_join(&report(Verdict::ActionNeeded, 2)), None);
        // IT approved while the app was closed: the live state is approved and there is no claim yet.
        let approved = samples::report_approved_without_claim();
        assert_eq!(approved.approval.state, Some(DeviceStatus::Approved));
        assert!(approved.approval.live && approved.last_claim.is_none());
        assert_eq!(resume_join(&approved), Some(true));
        let mut declined = samples::report_approved_without_claim();
        declined.schedule.owner_consented = Some(false);
        assert_eq!(resume_join(&declined), Some(false));
        let mut pending = report(Verdict::ActionNeeded, 0);
        pending.approval.state = Some(DeviceStatus::Pending);
        assert_eq!(resume_join(&pending), Some(true));
        pending.approval.state = Some(DeviceStatus::Revoked);
        assert_eq!(resume_join(&pending), None);
    }

    #[test]
    fn an_issue_without_an_exact_deadline_has_no_deadline_note() {
        let shown = report(Verdict::ActionNeeded, 1);
        assert_eq!(deadline_text(&shown.issues[0]), None);
    }

    #[test]
    fn control_results_read_plainly() {
        let check = samples::denied_check();
        let (title, value, ok) = result_control(&check.controls[0]);
        assert_eq!(
            (title.as_str(), value.as_str(), ok),
            ("Password min length", "4", false)
        );
        let unrequired = ControlReport {
            id: "disk_encryption".into(),
            value: ControlValue::Text("on".into()),
            ok: None,
        };
        assert_eq!(
            result_control(&unrequired),
            ("Disk encryption".into(), "on".into(), true)
        );
    }

    #[test]
    fn a_check_is_superseded_only_by_a_later_status_claim() {
        let claim = |sent: Option<&str>| {
            let mut claim = samples::report_good().last_claim.unwrap();
            claim.sent_at = sent.map(str::to_owned);
            claim
        };
        let kept = "2026-11-16T10:53:00Z";
        // The same instant written with another offset is the same claim.
        assert!(!check_is_superseded(kept, Some(&claim(Some(kept)))));
        assert!(!check_is_superseded(
            "2026-11-16T11:53:00+01:00",
            Some(&claim(Some(kept)))
        ));
        // A status claim from before the check does not supersede it.
        assert!(!check_is_superseded(
            "2026-11-16T11:48:00Z",
            Some(&claim(Some(kept)))
        ));
        // A later status claim supersedes the check.
        assert!(check_is_superseded(
            kept,
            Some(&claim(Some("2026-11-16T14:10:35Z")))
        ));
        // Without a status claim, or without its sent time, nothing is superseded.
        assert!(!check_is_superseded(kept, None));
        assert!(!check_is_superseded(kept, Some(&claim(None))));
    }

    fn issue(message: &str, command: Option<&str>) -> Issue {
        Issue {
            urgency: Urgency::Action,
            message: message.into(),
            fix: Some("Fix it.".into()),
            command: command.map(str::to_owned),
            stop_job_command: None,
            deadline: "Exact deadline unavailable.".into(),
        }
    }

    fn at(text: &str) -> OffsetDateTime {
        parse_rfc3339(text).unwrap()
    }

    fn prague() -> impl Fn(OffsetDateTime) -> OffsetDateTime {
        |time| time.to_offset(UtcOffset::from_hms(1, 0, 0).unwrap())
    }

    #[test]
    fn gateway_findings_read_in_plain_words_with_local_dates() {
        let now = at("2026-11-16T15:00:00Z");
        let view = issue_view(
            &issue(
                "Gateway at 2026-11-16T14:10:35Z: password_min_length = 4, >= 10 required, access ends in 19h",
                Some("open-pact-client check"),
            ),
            now,
            prague(),
        );
        assert_eq!(
            view.title,
            "Password policy allows 4 characters, at least 10 needed"
        );
        assert_eq!(
            view.note.as_deref(),
            Some("Access ends 17 Nov, 10:10 unless fixed")
        );
        assert_eq!(view.action, None);
        let view = issue_view(
            &issue(
                "Gateway at 2026-11-16T14:10:35Z: antimalware_signature_age_days = 4, <= 3 required, access ends in 19h",
                None,
            ),
            now,
            prague(),
        );
        assert_eq!(
            view.title,
            "Antimalware signatures are 4 days old, at most 3 allowed"
        );
        let view = issue_view(
            &issue(
                "Gateway at 2026-11-16T09:00:00Z: firewall = off, on required, access ends in 2h",
                None,
            ),
            now,
            prague(),
        );
        assert_eq!(view.title, "Firewall is off, it must be on");
        assert_eq!(view.note.as_deref(), Some("Access ended 16 Nov, 12:00"));
        let view = issue_view(
            &issue(
                "Gateway at 2026-11-16T09:00:00Z: disk_encryption = unknown, full required",
                None,
            ),
            now,
            prague(),
        );
        assert_eq!(view.title, "Disk encryption could not be read");
        assert_eq!(
            view.note.as_deref(),
            Some("Refused by the gateway on 16 Nov, 10:00")
        );
    }

    #[test]
    fn other_items_keep_their_message_and_get_a_button_by_command() {
        let now = at("2026-11-16T15:00:00Z");
        let job = issue(
            "Automatic sending is on, but its job needs installation or update.",
            Some("open-pact-client schedule on"),
        );
        let view = issue_view(&job, now, prague());
        assert_eq!(view.title, job.message);
        assert_eq!(view.action, Some(IssueAction::InstallJob));
        assert_eq!(
            issue_action(&issue(
                "x",
                Some("'/a b/open-pact-client' --home /h accept")
            )),
            Some(IssueAction::Review)
        );
        assert_eq!(
            issue_action(&issue("x", Some("open-pact-client status --online"))),
            Some(IssueAction::Retry)
        );
        assert_eq!(
            issue_action(&issue("x", Some("open-pact-client check"))),
            None
        );
        assert_eq!(
            issue_action(&issue("x", Some("open-pact-client status"))),
            None
        );
        let probe = issue(
            "The signed VPN probe failed.",
            Some("open-pact-client check"),
        );
        assert_eq!(issue_action(&probe), Some(IssueAction::Retry));
    }

    #[test]
    fn the_heading_counts_every_listed_item_the_vpn_probe_too() {
        let mut shown = report(Verdict::ActionNeeded, 2);
        shown.issues.push(issue(
            "The signed VPN probe failed.",
            Some("open-pact-client check"),
        ));
        let both = headline(&shown);
        assert_eq!(both.heading, "Fix 3 things");
        assert!(both.detail.contains("then press Check now."));
        assert!(
            both.detail
                .ends_with("so that the next check reaches the company.")
        );
        shown.issues.truncate(1);
        shown.issues.remove(0);
        shown.issues.push(issue(
            "The signed VPN probe failed.",
            Some("open-pact-client check"),
        ));
        let vpn = headline(&shown);
        assert_eq!(vpn.heading, "Not on the company VPN");
        assert!(!vpn.detail.contains("Check now"));
        let sample = samples::report_needs_action();
        assert_eq!(
            headline(&sample).heading,
            format!("Fix {} things", sample.issues.len())
        );
    }
}
