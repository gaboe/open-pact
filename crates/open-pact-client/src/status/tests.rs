use super::*;
use std::path::Path;

use crate::fake_gateway::{Company, DEMO_MANIFEST, FakeGateway, Witness, not_found, snapshot};
use open_pact_core::{Claim, ControlValue, Os, Pseudonym, TrustLevel};
use serde_json::json;

const STATES: &[&str] = &[
    "approved_ok",
    "grace_warning",
    "denied",
    "pending_approval",
    "revoked",
    "accept_pending",
    "off_vpn",
    "log_alarm",
    "auto_off",
    "auto_on",
    "job_missing",
    "job_leftover",
    "no_claim",
    "not_enrolled",
    "lost_response",
    "damaged_log",
    "stale_claim",
];

struct Fixture {
    _dir: tempfile::TempDir,
    home: Home,
    gateway: FakeGateway,
    signed: ManifestHash,
    enforced: ManifestHash,
    job: JobStatus,
    _closed: tokio::net::TcpSocket,
    probe: String,
    now: time::OffsetDateTime,
}

fn fixture_manifest(witness: &Witness, vpn: Option<&str>) -> String {
    let header = &DEMO_MANIFEST[..DEMO_MANIFEST.find("[[control]]").unwrap()];
    let policy = vpn
        .map(|probe| format!("mode = \"vpn\"\nvpn_probe = \"{probe}\""))
        .unwrap_or_else(|| "mode = \"always\"".into());
    format!(
        r#"{header}
[[control]]
id = "firewall"
source = "company_policy"
check = "builtin:firewall@1"
output = ["on", "off", "unknown"]
required = {{ macos = "on", windows = "on", linux = "on" }}
grace = "1d"

[log]
witnesses = [{{ name = "witness.example.org/test", key = "{}" }}]
witness_quorum = 1
checkpoint_max_age = "1h"

[schedule]
{policy}
interval = "55m"
"#,
        witness.key.vkey()
    )
}

impl Fixture {
    async fn new(state: &str) -> Self {
        let now = open_pact_core::timestamp::parse_rfc3339("2026-11-16T10:00:00Z")
            .unwrap()
            .to_offset(time::UtcOffset::UTC);
        let company = Company::new();
        let witness = Witness::new();
        let closed = tokio::net::TcpSocket::new_v4().unwrap();
        closed.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let probe = closed.local_addr().unwrap().to_string();
        let toml = fixture_manifest(&witness, (state == "off_vpn").then_some(probe.as_str()));
        let manifest = Manifest::parse(toml.as_bytes()).unwrap();
        let enforced_toml = if state == "accept_pending" {
            toml.replace("company.example", "new-policy.example")
        } else {
            toml.clone()
        };
        let signed = manifest.hash().clone();
        let enforced = ManifestHash::of(enforced_toml.as_bytes());
        let published = Company::published(&enforced_toml, &company.key);
        let published = if state == "bad_company_signature" {
            let mut body: serde_json::Value = serde_json::from_str(&published).unwrap();
            body["toml"] = json!(enforced_toml.replace("company.example", "other.example"));
            body.to_string()
        } else {
            published
        };
        let entry = open_pact_core::Entry {
            index: 0,
            kind: open_pact_core::EntryKind::ManifestPublished,
            data: json!({"manifest":signed.as_str()}),
        };
        let mut checkpoint = company.sign(&crate::fake_gateway::checkpoint_of(
            company.log.origin(),
            &[entry],
            1,
        ));
        witness.cosign(
            &mut checkpoint,
            u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
        );
        let stored_checkpoint = checkpoint.to_string();
        let checkpoint = if state == "proof_unavailable" {
            let mut newer = company.sign(&crate::fake_gateway::checkpoint_of(
                company.log.origin(),
                &[
                    open_pact_core::Entry {
                        index: 0,
                        kind: open_pact_core::EntryKind::ManifestPublished,
                        data: json!({"manifest":signed.as_str()}),
                    },
                    open_pact_core::Entry {
                        index: 1,
                        kind: open_pact_core::EntryKind::ManifestPublished,
                        data: json!({"manifest":signed.as_str()}),
                    },
                ],
                2,
            ));
            witness.cosign(
                &mut newer,
                u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
            );
            newer.to_string()
        } else if state == "log_alarm" {
            "not a checkpoint".into()
        } else {
            stored_checkpoint.clone()
        };
        let log = company.log.vkey();
        let approval = match state {
            "pending_approval" => "pending",
            "revoked" => "revoked",
            _ => "approved",
        };
        let gateway = FakeGateway::start(move |line, _| match line {
            "GET /v1/manifest" => (200, published.clone()),
            "GET /v1/log/key" => (200, log.clone()),
            "GET /v1/log/checkpoint" => (200, checkpoint.clone()),
            "POST /v1/nonce" => (200, json!({"nonce":"status-nonce"}).to_string()),
            "POST /v1/device/status" => (200, json!({"state":approval}).to_string()),
            "GET /v1/log/proof/consistency?from=1&to=2" => (503, "try later".into()),
            _ => not_found(),
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let home = Home(dir.path().to_path_buf());
        let device = crate::DeviceKey::load_or_create(dir.path(), true).unwrap();
        let last_status = match state {
            "pending_approval" => DeviceStatus::Pending,
            "revoked" => DeviceStatus::Revoked,
            _ => DeviceStatus::Approved,
        };
        let enrolment = Enrolment {
            gateway: gateway.url.clone(),
            manifest: signed.clone(),
            device: Pseudonym::of(&device.public_key()),
            salt: "00".repeat(32),
            log_entries: None,
            last_status: Some(last_status),
        };
        if state != "not_enrolled" {
            home.write("enrolment.json", &serde_json::to_vec(&enrolment).unwrap())
                .unwrap();
            home.write("manifest.toml", toml.as_bytes()).unwrap();
            home.write(crate::LOG_CHECKPOINT, stored_checkpoint.as_bytes())
                .unwrap();
            Pins {
                company: company.fingerprint(),
                log: company.log.clone(),
            }
            .save(&home)
            .unwrap();
        }
        let auto_send = !matches!(state, "auto_off" | "job_leftover" | "not_enrolled");
        DeviceConfig {
            auto_send,
            setup_answered: true,
            ..Default::default()
        }
        .save(&home)
        .unwrap();
        let job = match state {
            "job_missing" => JobStatus::Missing,
            "job_leftover" => JobStatus::Leftover,
            "auto_off" | "not_enrolled" => JobStatus::Absent,
            _ => JobStatus::Current,
        };
        if matches!(job, JobStatus::Current | JobStatus::Leftover) {
            home.write(
                crate::schedule::APPLIED,
                br#"{"run_as":"user","executable":"/usr/local/bin/open-pact-client"}"#,
            )
            .unwrap();
        }
        if !matches!(state, "no_claim" | "not_enrolled") {
            let time = now
                - if state == "stale_claim" {
                    time::Duration::days(2)
                } else {
                    time::Duration::minutes(10)
                };
            let value = if matches!(state, "grace_warning" | "denied") {
                "off"
            } else {
                "on"
            };
            let claim = Claim {
                manifest: signed.clone(),
                device: enrolment.device,
                device_key: device.public_key(),
                nonce: "claim-nonce".into(),
                time,
                client: "open-pact-client 0.5.0".into(),
                os: Os::Macos,
                trust_level: TrustLevel::L0,
                virtualized: None,
                results: [("firewall".into(), ControlValue::from(value))].into(),
                csr_sha256: None,
                log_checkpoint: None,
            };
            let sent = json!({"jws": device.sign_claim(&claim).unwrap()});
            let response = match state {
                "grace_warning" => {
                    json!({"status":"accepted","warnings":["firewall = off, on required, access ends in 23h"],"certificate_pem":null,"ca_pem":""})
                }
                "denied" => {
                    json!({"status":"denied","reasons":["firewall = off, on required, grace 1d ended"]})
                }
                "lost_response" => json!({"unconfirmed":true}),
                _ => json!({"status":"accepted","warnings":[],"certificate_pem":null,"ca_pem":""}),
            };
            locallog::append_with_status(
                &home.file("claims.jsonl"),
                &serde_json::to_vec(&sent).unwrap(),
                &serde_json::to_vec(&response).unwrap(),
                Some(if state == "denied" { 403 } else { 200 }),
            )
            .unwrap();
            let mut records = locallog::read(&home.file("claims.jsonl")).unwrap();
            records[0].time = timestamp(time);
            records[0].response_incomplete = state == "lost_response";
            let mut line = serde_json::to_string(&records[0]).unwrap() + "\n";
            if state == "damaged_log" {
                line.push_str("{damaged\n");
            }
            home.write("claims.jsonl", line.as_bytes()).unwrap();
            if !matches!(state, "auto_off" | "not_enrolled") {
                let note = if state == "log_alarm" {
                    Some("alarm the saved checkpoint did not verify")
                } else {
                    None
                };
                home.write("report-state.json", &serde_json::to_vec(&json!({"vpn_up":state != "off_vpn", "last_success":time.unix_timestamp(), "last_note":note})).unwrap()).unwrap();
                if state == "log_alarm" {
                    home.write("schedule.log", b"2026-11-16T09:50:00Z TRANSPARENCY LOG ALARM: the saved checkpoint did not verify\n").unwrap();
                }
            }
        }
        Self {
            _dir: dir,
            home,
            gateway,
            signed,
            enforced,
            job,
            _closed: closed,
            probe,
            now,
        }
    }

    async fn report(&self, online: bool) -> Report {
        let before = snapshot(&self.home.0);
        let report = collect_with(&self.home, online, false, self.now, |_, _| Ok(self.job))
            .await
            .unwrap();
        assert_eq!(
            snapshot(&self.home.0),
            before,
            "status must not write files"
        );
        assert!(
            !self
                .gateway
                .requests()
                .iter()
                .any(|line| line.contains("/v1/claim")),
            "status must not send a claim"
        );
        report
    }

    fn normalize(&self, text: &str) -> String {
        text.replace(
            &self.home.0.to_string_lossy().to_string(),
            "/home/example/pact",
        )
        .replace(self.signed.as_str(), "sha256:<signed>")
        .replace(self.enforced.as_str(), "sha256:<enforced>")
        .replace(&self.probe, "127.0.0.1:7443")
    }
}

fn check_snapshot(name: &str, rendered: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/status/{name}.txt"));
    if std::env::var_os("STATUS_UPDATE_SNAPSHOTS").is_some() {
        std::fs::write(&path, rendered).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n"),
        rendered.replace("\r\n", "\n"),
        "{}",
        path.display()
    );
}

async fn snapshot_case(state: &str) {
    let fixture = Fixture::new(state).await;
    let report = fixture.report(true).await;
    check_snapshot(state, &fixture.normalize(&report.render()));
    assert_eq!(
        serde_json::to_value(&report).unwrap()["exit_code"],
        report.exit_code
    );
}

macro_rules! snapshots {
    ($($state:ident),+ $(,)?) => {$ (
        #[tokio::test]
        async fn $state() { snapshot_case(stringify!($state)).await; }
    )+};
}
snapshots!(
    approved_ok,
    grace_warning,
    denied,
    pending_approval,
    revoked,
    accept_pending,
    off_vpn,
    log_alarm,
    auto_off,
    auto_on,
    job_missing,
    job_leftover,
    no_claim,
    not_enrolled,
    lost_response,
    damaged_log,
    stale_claim
);

#[tokio::test]
async fn local_snapshot_points_to_the_online_command() {
    let fixture = Fixture::new("approved_ok").await;
    let report = fixture.report(false).await;
    check_snapshot("local_approved_ok", &fixture.normalize(&report.render()));
}

#[tokio::test]
async fn local_mode_makes_no_requests_and_leaves_live_answers_unknown() {
    for state in STATES {
        let fixture = Fixture::new(state).await;
        let report = fixture.report(false).await;
        assert!(fixture.gateway.requests().is_empty(), "{state}");
        assert!(
            report
                .manifest
                .as_ref()
                .is_none_or(|manifest| manifest.enforced.is_none())
        );
        assert_ne!(
            report.exit_code, 0,
            "a file-only report must not promise live OK: {state}"
        );
    }
}

#[tokio::test]
async fn status_authentication_sends_only_the_device_status_statement() {
    let fixture = Fixture::new("approved_ok").await;
    assert_eq!(fixture.report(true).await.exit_code, 0);
    assert_eq!(
        fixture.gateway.posts(),
        ["POST /v1/nonce", "POST /v1/device/status"]
    );
    let body: serde_json::Value =
        serde_json::from_str(&fixture.gateway.bodies("POST /v1/device/status")[0]).unwrap();
    assert!(body["pseudonym"].is_string());
    assert!(body.get("claim").is_none());
}

#[tokio::test]
async fn an_alarm_does_not_authenticate_or_claim_live_approval() {
    let fixture = Fixture::new("log_alarm").await;
    let report = fixture.report(true).await;
    assert_eq!(report.exit_code, 2);
    assert!(fixture.gateway.posts().is_empty());
    assert!(report.approval.source.contains("not refreshed"));
    assert!(report.manifest.unwrap().enforced.is_none());
}

#[tokio::test]
async fn online_approval_replaces_a_stale_saved_revocation_without_writing_it() {
    let fixture = Fixture::new("approved_ok").await;
    let mut enrolment = fixture.home.enrolment().unwrap();
    enrolment.last_status = Some(DeviceStatus::Revoked);
    fixture
        .home
        .write("enrolment.json", &serde_json::to_vec(&enrolment).unwrap())
        .unwrap();
    assert_eq!(fixture.report(false).await.exit_code, 1);
    assert_eq!(fixture.report(true).await.exit_code, 0);
    assert_eq!(
        fixture.home.enrolment().unwrap().last_status,
        Some(DeviceStatus::Revoked)
    );
}

#[tokio::test]
async fn damaged_history_does_not_turn_an_older_accepted_claim_into_ok() {
    let fixture = Fixture::new("damaged_log").await;
    let report = fixture.report(true).await;
    assert_eq!(report.exit_code, 1);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.message.contains("latest outcome is unknown"))
    );
}

#[tokio::test]
async fn an_unreachable_gateway_retains_local_evidence_and_reports_unknown_live_state() {
    let fixture = Fixture::new("grace_warning").await;
    let mut enrolment = fixture.home.enrolment().unwrap();
    enrolment.gateway = format!("http://{}", fixture.probe);
    fixture
        .home
        .write("enrolment.json", &serde_json::to_vec(&enrolment).unwrap())
        .unwrap();
    let report = fixture.report(true).await;
    assert_eq!(report.exit_code, 1);
    assert!(report.last_claim.unwrap().warnings[0].contains("23h"));
    assert!(
        report
            .limitations
            .iter()
            .any(|text| text.contains("Gateway refresh failed"))
    );
}

#[tokio::test]
async fn a_relative_deadline_becomes_an_absolute_time() {
    let fixture = Fixture::new("grace_warning").await;
    let report = fixture.report(true).await;
    let warning = report
        .issues
        .iter()
        .find(|issue| issue.urgency == Urgency::Warning)
        .unwrap();
    assert!(warning.message.contains("2026-11-16T09:50:00Z"));
    assert!(warning.message.contains("access ends in 23h"));
    assert_eq!(
        warning.deadline,
        "about 2026-11-17T08:50:00Z (gateway said 'access ends in 23h' at 2026-11-16T09:50:00Z)"
    );
}

#[tokio::test]
async fn a_deadline_in_the_past_is_reported_as_passed() {
    let fixture = Fixture::new("grace_warning").await;
    let later = fixture.now + time::Duration::hours(30);
    let report = collect_with(&fixture.home, false, false, later, |_, _| Ok(fixture.job))
        .await
        .unwrap();
    assert!(report.render().contains(
        "   Deadline passed at about 2026-11-17T08:50:00Z (gateway said 'access ends in 23h' at 2026-11-16T09:50:00Z)\n"
    ));
}

#[test]
fn access_spans_cover_the_gateway_formats() {
    let at = |text| access_span(text).map(|(_, span)| span.whole_minutes());
    assert_eq!(at("firewall = off, access ends in 30m"), Some(30));
    assert_eq!(at("firewall = off, access ends in 23h"), Some(23 * 60));
    assert_eq!(at("firewall = off, access ends in 7d"), Some(7 * 24 * 60));
    assert_eq!(
        at("firewall = off, access ends in 2d 5h"),
        Some((2 * 24 + 5) * 60)
    );
    assert_eq!(at("firewall = off, on required"), None);
    assert_eq!(at("firewall = off, access ends in soon"), None);
    assert!(
        warning_deadline(
            "firewall = off",
            "2026-11-16T09:50:00Z",
            time::OffsetDateTime::now_utc()
        )
        .starts_with("Exact deadline unknown")
    );
}

#[tokio::test]
async fn a_nearby_manual_claim_does_not_supply_the_scheduled_result() {
    let fixture = Fixture::new("approved_ok").await;
    let path = fixture.home.file("claims.jsonl");
    let first = locallog::read(&path).unwrap().remove(0);
    locallog::append_with_status(
        &path,
        &first.sent().unwrap(),
        &serde_json::to_vec(&json!({"status":"denied","reasons":["firewall = off, on required"]}))
            .unwrap(),
        Some(403),
    )
    .unwrap();
    let mut records = locallog::read(&path).unwrap();
    records[1].time = "2026-11-16T09:50:30Z".into();
    let lines: String = records
        .iter()
        .map(|record| serde_json::to_string(record).unwrap() + "\n")
        .collect();
    fixture
        .home
        .write("claims.jsonl", lines.as_bytes())
        .unwrap();
    let text = fixture.report(false).await.render();
    assert!(text.contains("Last claim response: 2026-11-16T09:50:30Z, denied."));
    assert!(text.contains("Last answered scheduled claim: 2026-11-16T09:50:00Z."));
    assert!(
        fixture
            .report(false)
            .await
            .schedule
            .last_scheduled_claim
            .unwrap()
            .response
            .is_none()
    );
}

#[tokio::test]
async fn resolved_manifest_notes_do_not_require_action() {
    let fixture = Fixture::new("approved_ok").await;
    fixture
        .home
        .write(
            "report-state.json",
            &serde_json::to_vec(
                &json!({"vpn_up":true,"last_note":format!("changed {}",fixture.signed)}),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(fixture.report(true).await.exit_code, 0);
    assert!(
        !fixture
            .report(false)
            .await
            .issues
            .iter()
            .any(|issue| issue.message.contains("changed manifest"))
    );
    fixture.home.write("report-state.json", &serde_json::to_vec(&json!({"vpn_up":true,"last_note":format!("changed {}",ManifestHash::of(b"old policy"))})).unwrap()).unwrap();
    assert!(
        fixture
            .report(false)
            .await
            .issues
            .iter()
            .any(|issue| issue.message.contains("changed manifest"))
    );
    assert_eq!(fixture.report(true).await.exit_code, 0);
}

#[tokio::test]
async fn damaged_optional_files_preserve_text_and_json_reports() {
    for file in [
        "report-state.json",
        "device.json",
        "schedule.log",
        "claims.jsonl",
    ] {
        let fixture = Fixture::new("approved_ok").await;
        if file == "claims.jsonl" {
            std::fs::remove_file(fixture.home.file(file)).unwrap();
            locallog::append_with_status(&fixture.home.file(file), b"not json", b"{}", Some(200))
                .unwrap();
        } else {
            fixture.home.write(file, b"\xff{").unwrap();
        }
        for online in [false, true] {
            let report = fixture.report(online).await;
            assert!(
                report.render().contains(&format!("damaged: {file}")),
                "{file}"
            );
            assert!(
                serde_json::to_string(&report)
                    .unwrap()
                    .contains(&format!("damaged: {file}")),
                "{file}"
            );
            assert!(report.manifest.is_some());
            assert_eq!(report.exit_code, 1);
        }
    }
}

#[tokio::test]
async fn damaged_enrolment_still_renders_an_unknown_report() {
    let fixture = Fixture::new("approved_ok").await;
    fixture.home.write("enrolment.json", b"{").unwrap();
    let report = fixture.report(false).await;
    assert_eq!(report.exit_code, 3);
    assert!(report.render().contains("damaged: enrolment.json"));
    assert!(
        serde_json::to_string(&report)
            .unwrap()
            .contains("damaged: enrolment.json")
    );
}

#[tokio::test]
async fn lasting_manifest_mismatch_shows_the_accept_fix() {
    let fixture = Fixture::new("approved_ok").await;
    let text = fixture
        .home
        .read_text("manifest.toml")
        .unwrap()
        .unwrap()
        .replace("company.example", "next.example");
    fixture
        .home
        .write("manifest.toml", text.as_bytes())
        .unwrap();
    let report = fixture.report(false).await;
    let rendered = report.render();
    assert_eq!(report.exit_code, 1);
    assert!(rendered.contains("The signed local manifest is unavailable"));
    assert!(rendered.contains("accept"));
    assert!(!rendered.contains("busy:"));
}

#[tokio::test]
async fn generation_reads_retry_only_when_enrolment_changes() {
    let fixture = Fixture::new("approved_ok").await;
    let before = std::fs::read(fixture.home.file("enrolment.json")).unwrap();
    let manifest = fixture
        .home
        .read_text("manifest.toml")
        .unwrap()
        .unwrap()
        .replace("company.example", "next.example")
        .into_bytes();
    let mut enrolled = fixture.home.enrolment().unwrap();
    enrolled.manifest = ManifestHash::of(&manifest);
    let after = serde_json::to_vec(&enrolled).unwrap();
    let mut reads = std::collections::VecDeque::from([
        ("enrolment.json", before.clone()),
        ("manifest.toml", manifest.clone()),
        ("enrolment.json", after.clone()),
        ("enrolment.json", after.clone()),
        ("manifest.toml", manifest.clone()),
        ("enrolment.json", after.clone()),
    ]);
    let result = read_generation(|file| {
        let (expected, bytes) = reads.pop_front().expect("too many reads");
        assert_eq!(file, expected);
        Ok(Some(bytes))
    })
    .unwrap();
    let Generation::Enrolled(generation) = result else {
        panic!("expected the stable second generation")
    };
    assert_eq!(generation.enrolment.manifest, enrolled.manifest);
    assert_eq!(generation.manifest.unwrap().hash(), &enrolled.manifest);
    assert!(reads.is_empty());

    let mut reads = std::collections::VecDeque::from([
        ("enrolment.json", before.clone()),
        ("manifest.toml", manifest.clone()),
        ("enrolment.json", before.clone()),
    ]);
    let result = read_generation(|file| {
        let (expected, bytes) = reads.pop_front().expect("too many reads");
        assert_eq!(file, expected);
        Ok(Some(bytes))
    })
    .unwrap();
    let Generation::Enrolled(generation) = result else {
        panic!("expected the stable enrolment")
    };
    assert_eq!(
        generation.enrolment.manifest,
        fixture.home.enrolment().unwrap().manifest
    );
    assert!(generation.manifest.is_err());
    assert!(reads.is_empty());
}

#[tokio::test]
async fn generation_reads_stop_after_three_changed_enrolments() {
    let fixture = Fixture::new("approved_ok").await;
    let manifest = std::fs::read(fixture.home.file("manifest.toml")).unwrap();
    let mut enrolment_reads = 0;
    let mut manifest_reads = 0;
    let result = read_generation(|file| {
        if file == "enrolment.json" {
            enrolment_reads += 1;
            Ok(Some(vec![enrolment_reads]))
        } else {
            assert_eq!(file, "manifest.toml");
            manifest_reads += 1;
            Ok(Some(manifest.clone()))
        }
    })
    .unwrap();
    assert!(matches!(result, Generation::Busy));
    assert_eq!(enrolment_reads, 6);
    assert_eq!(manifest_reads, 3);
}

#[tokio::test]
async fn unreadable_optional_files_preserve_the_report() {
    for file in [
        "device.json",
        "report-state.json",
        "schedule.log",
        "claims.jsonl",
    ] {
        let fixture = Fixture::new("approved_ok").await;
        let _ = std::fs::remove_file(fixture.home.file(file));
        std::fs::create_dir(fixture.home.file(file)).unwrap();
        for online in [false, true] {
            let report = fixture.report(online).await;
            assert!(
                report.render().contains(&format!("damaged: {file}")),
                "{file}"
            );
            assert!(report.manifest.is_some());
            assert_eq!(report.exit_code, 1);
            if file == "device.json" {
                assert!(report.render().contains("Automatic sending: unknown."));
                assert!(
                    serde_json::to_value(&report).unwrap()["schedule"]["owner_consented"].is_null()
                );
            }
        }
    }
}

#[tokio::test]
async fn damaged_checkpoint_is_a_local_problem_not_a_network_fix() {
    let fixture = Fixture::new("approved_ok").await;
    fixture
        .home
        .write(crate::LOG_CHECKPOINT, b"not a checkpoint")
        .unwrap();
    let report = fixture.report(true).await;
    assert_eq!(report.exit_code, 1);
    assert!(report.render().contains("damaged: log-checkpoint.txt"));
    assert!(!report.render().contains("Connect the company network"));
    assert!(
        !fixture
            .gateway
            .requests()
            .iter()
            .any(|line| line.starts_with("POST "))
    );
}

#[tokio::test]
async fn unavailable_consistency_proof_is_not_a_log_alarm() {
    let fixture = Fixture::new("proof_unavailable").await;
    let report = fixture.report(true).await;
    assert_eq!(report.exit_code, 1);
    assert!(report.render().contains("consistency proof"));
    assert!(!report.render().contains("ALARM"));
    assert!(
        !fixture
            .gateway
            .requests()
            .iter()
            .any(|line| line.starts_with("POST "))
    );
    assert!(
        fixture
            .gateway
            .requests()
            .iter()
            .any(|line| line.contains("/proof/consistency"))
    );
}

#[tokio::test]
async fn accept_restores_missing_or_damaged_signed_manifest() {
    for state in ["missing", "damaged", "different"] {
        let fixture = Fixture::new("approved_ok").await;
        let original = fixture.home.read_text("manifest.toml").unwrap().unwrap();
        match state {
            "missing" => std::fs::remove_file(fixture.home.file("manifest.toml")).unwrap(),
            _ => {
                let text = if state == "different" {
                    original.replace("company.example", "other.example")
                } else {
                    "not a manifest".into()
                };
                fixture
                    .home
                    .write("manifest.toml", text.as_bytes())
                    .unwrap();
            }
        }
        let enrolment = std::fs::read(fixture.home.file("enrolment.json")).unwrap();
        assert_eq!(
            crate::accept(&fixture.home, true, false).await.unwrap(),
            ExitCode::SUCCESS
        );
        assert_eq!(
            fixture.home.read_text("manifest.toml").unwrap().unwrap(),
            original
        );
        assert_eq!(
            std::fs::read(fixture.home.file("enrolment.json")).unwrap(),
            enrolment
        );
        assert!(
            !fixture
                .gateway
                .requests()
                .iter()
                .any(|line| line.starts_with("POST "))
        );
        assert_eq!(fixture.report(true).await.exit_code, 0);
    }
}

#[tokio::test]
async fn accept_refuses_a_manifest_the_company_did_not_sign() {
    let fixture = Fixture::new("bad_company_signature").await;
    std::fs::remove_file(fixture.home.file("manifest.toml")).unwrap();
    let enrolment = std::fs::read(fixture.home.file("enrolment.json")).unwrap();
    assert!(crate::accept(&fixture.home, true, false).await.is_err());
    assert!(!fixture.home.file("manifest.toml").exists());
    assert_eq!(
        std::fs::read(fixture.home.file("enrolment.json")).unwrap(),
        enrolment
    );
    assert!(
        !fixture
            .gateway
            .requests()
            .iter()
            .any(|line| line.starts_with("POST "))
    );
}

#[tokio::test]
async fn saved_alarm_keeps_exit_2_when_enrolment_is_damaged() {
    let fixture = Fixture::new("approved_ok").await;
    fixture
        .home
        .write(
            "report-state.json",
            &serde_json::to_vec(&json!({"vpn_up":true,"last_note":"alarm checkpoint kept"}))
                .unwrap(),
        )
        .unwrap();
    fixture.home.write("enrolment.json", b"{").unwrap();
    let report = fixture.report(false).await;
    assert_eq!(report.exit_code, 2);
    assert!(
        report
            .render()
            .contains("Saved scheduled log alarm: checkpoint kept")
    );
}

#[tokio::test]
async fn local_mode_names_the_online_command_only_when_online_can_answer() {
    for state in STATES {
        let fixture = Fixture::new(state).await;
        let report = fixture.report(false).await;
        let line = "status --online` for current approval and manifest.";
        assert_eq!(
            report.render().contains(line),
            *state != "not_enrolled",
            "{state}"
        );
        assert!(
            !fixture.report(true).await.render().contains(line),
            "{state}"
        );
    }
}

#[tokio::test]
async fn a_revoked_device_is_told_to_contact_it_and_the_job_command_is_secondary() {
    let fixture = Fixture::new("revoked").await;
    let report = fixture.report(true).await;
    let issue = &report.issues[0];
    assert!(
        issue
            .message
            .ends_with("It cannot send claims. Contact IT.")
    );
    assert_eq!(issue.command, None);
    assert!(
        issue
            .stop_job_command
            .as_ref()
            .unwrap()
            .ends_with("schedule off")
    );
}

#[tokio::test]
async fn send_time_and_response_time_are_distinct_evidence() {
    let fixture = Fixture::new("approved_ok").await;
    let mut records = locallog::read(&fixture.home.file("claims.jsonl")).unwrap();
    records[0].time = "2026-11-16T09:51:00Z".into();
    fixture
        .home
        .write(
            "claims.jsonl",
            (serde_json::to_string(&records[0]).unwrap() + "\n").as_bytes(),
        )
        .unwrap();
    let report = fixture.report(false).await;
    let claim = report.last_claim.as_ref().unwrap();
    assert_eq!(claim.sent_at.as_deref(), Some("2026-11-16T09:50:00Z"));
    assert_eq!(claim.response_at, "2026-11-16T09:51:00Z");
}

#[tokio::test]
async fn a_system_job_without_inspection_cannot_produce_ok() {
    let fixture = Fixture::new("approved_ok").await;
    let report = collect_with(&fixture.home, true, false, fixture.now, |_, _| {
        Ok(JobStatus::SystemUnconfirmed)
    })
    .await
    .unwrap();
    assert_eq!(report.exit_code, 3);
    assert!(
        report
            .limitations
            .iter()
            .any(|line| line.contains("SYSTEM job installation is unconfirmed"))
    );
}

#[tokio::test]
async fn a_changed_company_key_stops_before_device_authentication() {
    let fixture = Fixture::new("approved_ok").await;
    let attacker = Company::new();
    let published = Company::published(
        &std::fs::read_to_string(fixture.home.file("manifest.toml")).unwrap(),
        &attacker.key,
    );
    let gateway = FakeGateway::start(move |line, _| match line {
        "GET /v1/manifest" => (200, published.clone()),
        _ => not_found(),
    })
    .await;
    let mut enrolment = fixture.home.enrolment().unwrap();
    enrolment.gateway = gateway.url.clone();
    fixture
        .home
        .write("enrolment.json", &serde_json::to_vec(&enrolment).unwrap())
        .unwrap();
    let report = fixture.report(true).await;
    assert_eq!(report.exit_code, 2);
    assert_eq!(gateway.requests(), ["GET /v1/manifest"]);
}

#[tokio::test]
async fn an_update_notice_is_the_last_text_line_and_a_json_field() {
    let fixture = Fixture::new("approved_ok").await;
    let mut report = fixture.report(true).await;
    assert!(serde_json::to_value(&report).unwrap()["update"].is_null());
    assert!(!report.render().contains("is available"));
    report.update = Some(crate::update::Notice {
        current: "0.6.0".into(),
        latest: "0.6.1".into(),
        command: Some("brew upgrade open-pact"),
    });
    assert!(report.render().ends_with(&format!(
        "Exit: {}\nopen-pact-client 0.6.1 is available. Update: brew upgrade open-pact\n",
        report.exit_code
    )));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["update"]["current"], "0.6.0");
    assert_eq!(json["update"]["latest"], "0.6.1");
    assert_eq!(json["update"]["command"], "brew upgrade open-pact");
}
