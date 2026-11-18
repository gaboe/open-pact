//! Plain-words wording for the typed reports of the client library. No UI code lives here.

use crate::text::{Headline, Tone, humanize, readable_local};
use crate::zone;
use open_pact_client::ControlReport;
use open_pact_client::status::{Issue, Report, Verdict};
use open_pact_core::timestamp::{parse_rfc3339, seconds};
use open_pact_core::{ControlValue, DeviceStatus};
use time::macros::format_description;
use time::{Duration, OffsetDateTime};

pub fn headline(status: &Report) -> Headline {
    let last = status.last_claim.as_ref().map(|claim| {
        format!(
            "Last result {}, {}.",
            readable_local(&claim.response_at),
            claim.response
        )
    });
    let unchecked = status.current_compliance.starts_with("unknown");
    // A VPN probe that failed is not something to fix on this device.
    let off_vpn = status.issues.iter().any(is_vpn_probe);
    let count = status
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
                (0, true) => "Not on the company VPN".into(),
                (0, false) => "Action needed".into(),
                (1, false) => "Fix 1 thing".into(),
                (n, false) => format!("Fix {n} things"),
                (1, true) => "Fix 1 thing · not on VPN".into(),
                (n, true) => format!("Fix {n} things · not on VPN"),
            },
            detail: [
                last,
                unchecked.then(|| "Not checked again since then.".into()),
                Some("After a fix, check again.".into()),
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
fn span_delta(span: &str) -> Option<Duration> {
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
        "The last full malware scan was {} days ago",
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
    ("antimalware_full_scan_age_days", "Full malware scan age"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::samples::{self, report};
    use open_pact_client::status::Urgency;
    use time::UtcOffset;

    #[test]
    fn headlines_keep_uncertainty_in_plain_words() {
        let action = headline(&report(Verdict::ActionNeeded, 2));
        assert_eq!(action.heading, "Fix 2 things");
        assert_eq!(action.tone, Tone::Warn);
        assert!(action.detail.contains("Not checked again since then."));
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
    fn a_failed_vpn_probe_is_not_counted_as_a_fix() {
        let mut shown = report(Verdict::ActionNeeded, 2);
        shown.issues.push(issue(
            "The signed VPN probe failed.",
            Some("open-pact-client check"),
        ));
        assert_eq!(headline(&shown).heading, "Fix 2 things · not on VPN");
        shown.issues.truncate(1);
        shown.issues.remove(0);
        shown.issues.push(issue(
            "The signed VPN probe failed.",
            Some("open-pact-client check"),
        ));
        assert_eq!(headline(&shown).heading, "Not on the company VPN");
    }
}
