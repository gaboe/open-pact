#[cfg(unix)]
use runner::{
    Runner,
    admin::Admin,
    client::{Client, JoinEvent},
};
use runner::{
    admin::Settings,
    manifest::{self, Filter, Form, Os, Output, Requirement, Span, date_text, parse_date},
};
#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[cfg(unix)]
fn client() -> Client {
    Client {
        runner: Runner::default(),
        executable: fixture("bin/open-pact-client"),
    }
}

#[test]
#[cfg(unix)]
fn client_screens_use_json_and_keep_actionable_status() {
    let client = client();
    let preview = client.preview("opi1:fictional").unwrap();
    assert!(preview.company.matches_invitation);
    assert_eq!(preview.folders, ["~/Documents"]);
    assert!(
        client
            .preview("opi1:expired")
            .unwrap_err()
            .starts_with("This invitation expired")
    );
    let mut events = Vec::new();
    client
        .join("opi1:fictional", &preview.folders, true, |e| events.push(e))
        .unwrap();
    assert!(matches!(events.last(), Some(JoinEvent::Result { .. })));
    assert_eq!(events.len(), 7);
    let status = client.status().unwrap();
    assert_eq!(status.verdict, "action_needed");
    assert!(!status.approval.live);
    assert_eq!(status.issues.len(), 2);
    assert!(client.check().unwrap().accepted);
    assert!(client.changes().unwrap().schedule_widened);
    client.accept().unwrap();
    client.schedule(false).unwrap();
    client.schedule(true).unwrap();
    let logs = client.runner.logs();
    assert!(logs.iter().any(|log| log.exit == Some(2)));
    assert!(logs.iter().any(|log| {
        log.args
            .windows(2)
            .any(|w| w == ["--folder", "~/Documents"])
    }));
    assert!(logs.iter().all(|log| log.exit.is_some()));
}

#[test]
#[cfg(unix)]
fn admin_screens_use_context_namespace_and_gateway_json() {
    let mut admin = Admin::new(
        Runner::default(),
        Settings {
            context: "fictional-cluster".into(),
            namespace: "open-pact".into(),
            ..Settings::default()
        },
    );
    admin.kubectl = fixture("bin/kubectl");
    assert!(!admin.gateway().unwrap().auto_approve);
    let devices = admin.devices().unwrap();
    assert_eq!(devices.len(), 3);
    assert!(devices.iter().any(|d| d.state == "pending"));
    assert!(runner::admin::ready(&admin.deployment().unwrap()));
    assert!(
        admin
            .invite("72h", "Fictional note; $(ignored)")
            .unwrap()
            .invitation
            .starts_with("opi1:")
    );
    admin.device_action("approve", "0a1b2c3d").unwrap();
    admin.device_action("revoke", "fictional-a").unwrap();
    for log in admin.runner.logs() {
        assert_eq!(
            &log.args[..4],
            ["--context", "fictional-cluster", "-n", "open-pact"]
        );
    }
}

const MANIFEST: &str = include_str!("../../../tests/fixtures/manifest.toml");
const MANIFEST_V2: &str = include_str!("../../../tests/fixtures/manifest-v2.toml");

fn form(text: &str) -> Form {
    Form::parse(text).unwrap()
}

#[test]
fn durations_round_trip_exactly() {
    for text in ["24h", "1mo", "7d", "55m", "0d", "2w", "90m"] {
        assert_eq!(Span::parse(text).unwrap().print(), text);
    }
    for text in ["", "h", "5", "5x", "-1d", "1 d"] {
        assert!(Span::parse(text).is_none(), "{text}");
    }
    let hour = Span::parse("1mo").unwrap();
    assert_eq!(hour.words(), "1 month");
    assert_eq!(Span::parse("24h").unwrap().words(), "24 hours");
    assert_eq!(Span::parse("1d").unwrap().short(), "1 d");
    assert_eq!(date_text("2026-10-01"), "1 Oct 2026");
    assert_eq!(parse_date("1 Oct 2026"), parse_date("2026-10-01"));
}

#[test]
fn requirements_read_as_words() {
    let form = form(MANIFEST);
    let control = |id: &str| form.control(id).unwrap();
    assert_eq!(
        control("screen_lock").requirement_text(Os::Macos),
        "≤ 5 min"
    );
    assert_eq!(
        control("os_patch_age_days").requirement_text(Os::Linux),
        "≤ 30 days"
    );
    assert_eq!(
        control("password_min_length").requirement_text(Os::Windows),
        "≥ 10"
    );
    assert_eq!(
        control("disk_encryption").requirement_text(Os::Macos),
        "Full"
    );
    assert_eq!(
        control("preboot_auth").requirement_text(Os::Macos),
        "User secret"
    );
    assert_eq!(
        control("antimalware_full_scan_age_days").requirement_text(Os::Macos),
        "reported"
    );
    assert_eq!(
        control("log_oldest_record_days").requirement_text(Os::Windows),
        "≥ 90 days"
    );
    assert_eq!(
        control("log_oldest_record_days").requirement_text(Os::Macos),
        "n/a"
    );
    assert_eq!(
        control("log_oldest_record_days").requirement_text(Os::Linux),
        "reported"
    );
    assert_eq!(control("screen_lock").name(), "Screen lock");
    assert_eq!(control("screen_lock").grace_text(), "1 d");
    assert_eq!(
        control("disk_encryption").reference,
        "Client contract, security annex, 4.2"
    );
    assert!(control("firewall").reference.is_empty());
    let multiple = Requirement::Values(vec!["le_5min".into(), "le_15min".into()]);
    assert_eq!(
        manifest::requirement_text(control("screen_lock"), &multiple),
        "≤ 5 min or ≤ 15 min"
    );
    assert_eq!(
        manifest::value_label("screen_lock", "le_5min", true),
        "Locks within 5 min"
    );
}

#[test]
fn the_form_reads_every_section() {
    let form = form(MANIFEST);
    assert_eq!(form.issuer, "Example Company, IT security");
    assert_eq!(form.max_age, "24h");
    assert_eq!(form.retention, "1mo");
    assert_eq!(form.unknown_grace, "7d");
    assert_eq!(form.trust, "L0");
    assert_eq!(
        form.recipients,
        ["Company IT security", "Auditor on request"]
    );
    assert!(!form.metadata.contains(&"virtualized".to_owned()));
    let schedule = form.schedule.as_ref().unwrap();
    let vpn = schedule.vpn.as_ref().unwrap();
    assert_eq!((vpn.interval.as_str(), vpn.check.as_str()), ("55m", "5m"));
    assert_eq!(vpn.probe, "10.0.0.1:443");
    assert!(schedule.always.is_none());
    assert_eq!(form.controls.len(), 21);
    let (all, required, reported) = form.counts();
    assert_eq!(all, required + reported);
    assert!(reported > 0 && required > reported);
    assert_eq!(form.visible(Filter::All, "").len(), all);
    assert_eq!(form.visible(Filter::Required, "").len(), required);
    assert_eq!(form.visible(Filter::Reported, "").len(), reported);
    assert_eq!(form.visible(Filter::All, "SCREEN"), [2]);
    assert_eq!(form.visible(Filter::All, "os_patch"), [3]);
    assert_eq!(
        form.visible(Filter::All, "no such check"),
        Vec::<usize>::new()
    );
    assert!(Form::parse("name = ").is_err());
}

#[test]
fn edits_keep_comments_and_order() {
    let mut text = MANIFEST.to_owned();
    text = manifest::set_top_text(&text, "issuer", "Example Company, Security").unwrap();
    text = manifest::set_top_text(&text, "min_trust_level", "L1").unwrap();
    text = manifest::set_top_list(&text, "claim_recipients", &["One".to_owned()]).unwrap();
    text = manifest::set_send_text(&text, manifest::SendPart::Vpn, "interval", "2h").unwrap();
    text = manifest::set_control_text(&text, 0, "grace", "2d").unwrap();
    text = manifest::set_requirement(&text, 3, Os::Windows, &Requirement::Max(21)).unwrap();
    text = manifest::set_requirement(
        &text,
        2,
        Os::Linux,
        &Requirement::Values(vec!["le_15min".into()]),
    )
    .unwrap();
    text = manifest::set_requirement(&text, 1, Os::Macos, &Requirement::Reported).unwrap();
    for kept in [
        "# Example manifest. Fictional.",
        "# demo only: software device keys are L0",
        "# Illustrative V3.1 baseline.",
        "# Demo only: this witness key comes from a public seed",
    ] {
        assert!(text.contains(kept), "{kept}\n{text}");
    }
    assert!(
        text.contains("min_trust_level = \"L1\"               # demo only"),
        "{text}"
    );
    assert!(text.contains("claim_recipients = [\"One\"]"), "{text}");
    assert!(text.contains("interval = \"2h\""), "{text}");
    assert!(
        text.contains(
            "required = { macos = { max = 30 }, windows = { max = 21 }, linux = { max = 30 } }"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "required = { macos = \"le_5min\", windows = \"le_5min\", linux = \"le_15min\" }"
        ),
        "{text}"
    );
    assert!(
        text.contains("required = { windows = \"on\", linux = \"on\" }"),
        "{text}"
    );
    let after = form(&text);
    assert_eq!(after.issuer, "Example Company, Security");
    assert_eq!(after.controls[0].grace, "2d");
    assert_eq!(
        after.controls[1].requirement(Os::Macos),
        &Requirement::Reported
    );
    let order =
        |text: &str| -> Vec<String> { form(text).controls.into_iter().map(|c| c.id).collect() };
    assert_eq!(order(&text), order(MANIFEST));
    // A written control takes the current key names and drops source, and the sending section
    // takes its parts, so those keys are compared apart. Every other key keeps its place.
    let keys = |text: &str| -> Vec<String> {
        text.split(
            "
[schedule",
        )
        .next()
        .unwrap_or(text)
        .lines()
        .filter_map(|line| line.split_once(" = ").map(|(key, _)| key.to_owned()))
        .filter(|key| {
            !matches!(
                key.as_str(),
                "source" | "source_ref" | "rationale" | "description" | "reference"
            )
        })
        .collect()
    };
    assert_eq!(keys(&text), keys(MANIFEST));
    assert!(manifest::set_control_text(&text, 0, "id", "firewall").is_err());
    assert!(manifest::set_control_text(&text, 99, "grace", "1d").is_err());
}

#[test]
fn optional_text_is_removed_when_cleared() {
    let text = manifest::set_control_text(MANIFEST, 0, "reference", "").unwrap();
    assert!(form(&text).controls[0].reference.is_empty());
    assert!(!text.contains("security annex"));
    let text = manifest::set_control_text(&text, 1, "description", "Keep it on.").unwrap();
    assert_eq!(form(&text).controls[1].description, "Keep it on.");
}

#[test]
fn a_check_is_added_as_reported_and_removed_again() {
    let before = form(MANIFEST);
    let addable = manifest::addable(&before);
    let ids: Vec<_> = addable.iter().map(|known| known.id).collect();
    assert_eq!(
        ids,
        [
            "password_set",
            "web_protection",
            "process_audit",
            "remote_wipe",
            "powershell_logging"
        ]
    );
    let (text, index) = manifest::add_control(MANIFEST, "remote_wipe").unwrap();
    let after = form(&text);
    assert_eq!(index, 21);
    let added = &after.controls[index];
    assert_eq!(added.id, "remote_wipe");
    assert_eq!(added.check, "builtin:remote_wipe@1");
    assert_eq!(
        added.output,
        Output::Choices(["on", "off", "n/a", "unknown"].map(String::from).into())
    );
    assert!(!added.is_required());
    assert!(added.reference.is_empty());
    assert!(text.contains("required = {}"), "{text}");
    assert!(text.contains("# Demo only: this witness key"));
    assert!(manifest::add_control(&text, "remote_wipe").is_err());
    assert!(manifest::add_control(MANIFEST, "unknown_check").is_err());
    let integer = manifest::add_control(MANIFEST, "password_set").unwrap().0;
    assert!(form(&integer).controls.last().is_some());
    let removed = manifest::remove_control(&text, index).unwrap();
    assert_eq!(form(&removed), before);
    assert!(removed.contains("# Illustrative V3.1 baseline."));
    assert!(manifest::remove_control(&removed, index).is_err());
    assert_eq!(
        manifest::changes(&before, &after),
        ["Added check: Remote wipe"]
    );
    assert_eq!(
        manifest::changes(&after, &before),
        ["Removed check: Remote wipe"]
    );
}

#[test]
fn changed_rows_and_the_change_list_are_in_words() {
    let (before, after) = (form(MANIFEST), form(MANIFEST_V2));
    assert_eq!(
        manifest::changes(&before, &after),
        ["OS updates: macOS 30 → 14 days"]
    );
    assert_eq!(
        manifest::changed_controls(&before, &after),
        ["os_patch_age_days"]
    );
    assert!(manifest::changes(&before, &before).is_empty());
    let mut text = manifest::set_top_text(MANIFEST, "claim_max_age", "12h").unwrap();
    text = manifest::set_top_text(&text, "valid_from", "2026-11-02").unwrap();
    text = manifest::set_control_text(&text, 2, "description", "Lock at once.").unwrap();
    text = manifest::set_control_text(&text, 2, "grace", "2w").unwrap();
    text = manifest::set_requirement(&text, 2, Os::Windows, &Requirement::Reported).unwrap();
    text = manifest::set_top_list(
        &text,
        "disclosed_metadata",
        &form(&text)
            .metadata
            .into_iter()
            .filter(|key| key != "log_checkpoint")
            .chain(["virtualized".to_owned()])
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(
        manifest::changes(&before, &form(&text)),
        [
            "Valid from: 1 Oct 2026 → 2 Nov 2026",
            "A result is valid for: 24 hours → 12 hours",
            "Sent with each result: added Runs in a virtual machine",
            "Sent with each result: removed Log checkpoint",
            "Screen lock: description changed",
            "Screen lock: Windows ≤ 5 min → reported",
            "Screen lock: time to fix 1 day → 2 weeks",
        ]
    );
}

#[test]
fn the_overview_lists_live_devices_by_newest_result() {
    use runner::admin::{Device, latest_results};
    let mut devices: Vec<Device> =
        serde_json::from_str(include_str!("../../../tests/fixtures/devices.json")).unwrap();
    let device = |pseudonym: &str, state: &str, claim: Option<&str>| {
        let mut device = devices[0].clone();
        device.pseudonym = pseudonym.into();
        device.state = state.into();
        device.last_claim_at = claim.map(str::to_owned);
        device.last_result = claim.map(|_| serde_json::json!("accepted"));
        device
    };
    devices.splice(
        0..0,
        [
            device("revoked-new", "revoked", Some("2026-11-16T13:00:00Z")),
            device("revoked-none", "revoked", None),
            device("approved-none", "approved", None),
            device("approved-newest", "approved", Some("2026-11-16T12:30:00Z")),
        ],
    );
    let names: Vec<_> = latest_results(&devices)
        .iter()
        .map(|d| d.pseudonym.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "approved-newest",
            "fictional-a",
            "fictional-b",
            "approved-none",
            "fictional-c"
        ]
    );
    assert!(latest_results(&[]).is_empty());
}

#[test]
#[cfg(unix)]
fn terminal_path_preserves_existing_profile_and_is_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let profile = temp.path().join("profile");
    std::fs::write(&profile, "export EXAMPLE=kept").unwrap();
    runner::client::terminal_path(&profile, std::path::Path::new("/fictional path/tool's/bin"))
        .unwrap();
    let first = std::fs::read_to_string(&profile).unwrap();
    assert!(first.starts_with("export EXAMPLE=kept\n"));
    assert!(first.contains("tool'\\''s/bin"));
    runner::client::terminal_path(&profile, std::path::Path::new("/fictional path/tool's/bin"))
        .unwrap();
    assert_eq!(std::fs::read_to_string(profile).unwrap(), first);
}

#[test]
#[cfg(unix)]
fn bundled_install_keeps_an_executable_and_checks_version() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("bundled");
    std::fs::write(&source, "#!/bin/sh\nprintf 'open-pact-client 0.6.0\\n'\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
    let destination = temp.path().join("local/bin/open-pact-client");
    runner::client::install(&Runner::default(), &source, &destination).unwrap();
    assert_eq!(
        runner::client::version(&Runner::default(), &destination).unwrap(),
        "open-pact-client 0.6.0"
    );
}

#[cfg(unix)]
fn executable(path: &std::path::Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
#[cfg(unix)]
fn failed_commands_keep_errors_and_never_interpret_shell_input() {
    let temp = tempfile::tempdir().unwrap();
    let program = temp.path().join("fake");
    executable(
        &program,
        "#!/bin/sh\nprintf '%s\\n' '{\"error\":\"Fictional failure\"}'\nprintf '%s\\n' \"$1\" >&2\nexit 7\n",
    );
    let runner = Runner::default();
    assert_eq!(
        runner
            .run(&program, &["$(touch forbidden); spaces".into()])
            .unwrap_err(),
        "Fictional failure"
    );
    let log = runner.logs().pop().unwrap();
    assert_eq!(log.exit, Some(7));
    assert_eq!(log.stderr.trim(), "$(touch forbidden); spaces");
    assert!(
        runner
            .run(&temp.path().join("missing"), &[])
            .unwrap_err()
            .contains("Install the command")
    );
    assert_eq!(runner.logs().len(), 2);
}

#[test]
fn local_backups_keep_the_exact_toml_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let mut admin = runner::admin::Admin::new(runner::Runner::default(), Settings::default());
    admin.backup_root = temp.path().into();
    let folder = admin.backup_dir();
    std::fs::create_dir_all(&folder).unwrap();
    let text = "name = \"Fictional\"";
    std::fs::write(folder.join("example.toml"), text).unwrap();
    std::fs::write(folder.join("ignore.txt"), "ignored").unwrap();
    let backups = admin.backups().unwrap();
    assert_eq!(backups.len(), 1);
    assert_eq!(backups[0].manifest_hash, runner::admin::hash(text));
    assert_eq!(
        admin
            .restore_text(&runner::admin::Restore::Local(backups[0].clone()))
            .unwrap(),
        text
    );
    std::fs::write(&backups[0].path, "changed = true").unwrap();
    assert!(
        admin
            .restore_text(&runner::admin::Restore::Local(backups[0].clone()))
            .is_err()
    );
}

#[cfg(unix)]
fn isolated_admin() -> (tempfile::TempDir, Admin) {
    let temp = tempfile::tempdir().unwrap();
    let fixtures = temp.path().join("fixtures");
    std::fs::create_dir_all(fixtures.join("bin")).unwrap();
    for entry in std::fs::read_dir(fixture("")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), fixtures.join(entry.file_name())).unwrap();
        }
    }
    std::fs::copy(fixture("bin/kubectl"), fixtures.join("bin/kubectl")).unwrap();
    let mut admin = Admin::new(
        Runner::default(),
        Settings {
            context: "test-cluster".into(),
            namespace: "open-pact".into(),
            ..Settings::default()
        },
    );
    admin.backup_root = temp.path().join("backups");
    admin.kubectl = fixtures.join("bin/kubectl");
    (temp, admin)
}

#[test]
#[cfg(unix)]
fn history_sync_only_downloads_missing_verified_versions() {
    let (_temp, admin) = isolated_admin();
    let first = admin.sync().unwrap();
    assert_eq!(first.versions.len(), 2);
    assert_eq!(first.backups.len(), 2);
    assert!(first.backups.iter().any(|backup| {
        backup
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("-v2-")
    }));
    let count = || {
        admin
            .runner
            .logs()
            .iter()
            .filter(|entry| {
                entry
                    .args
                    .windows(3)
                    .any(|args| args == ["manifest", "get", "--version"])
            })
            .count()
    };
    assert_eq!(count(), 2);
    let second = admin.sync().unwrap();
    assert_eq!(second.backups.len(), 2);
    assert_eq!(count(), 2);
    std::fs::write(&second.backups[0].path, "corrupt = true").unwrap();
    let third = admin.sync().unwrap();
    assert_eq!(third.backups.len(), 1);
    assert_eq!(third.warnings.len(), 1);
    assert!(third.warnings[0].contains("does not match"));
}

#[test]
#[cfg(unix)]
fn apply_and_both_restore_paths_backup_before_writing_and_confirm_the_hash() {
    use runner::admin::{Restore, hash};
    let (_temp, admin) = isolated_admin();
    let active = admin.manifest(None).unwrap();
    let next = active.replace("min = 10", "min = 12");
    let timeout = std::time::Duration::from_secs(1);
    assert_eq!(
        admin
            .apply(&next, "Fictional change", &hash(&active), timeout)
            .unwrap()
            .hash,
        hash(&next)
    );
    assert!(
        admin
            .backups()
            .unwrap()
            .iter()
            .any(|backup| std::fs::read_to_string(&backup.path).unwrap() == active)
    );
    assert_eq!(admin.manifest(None).unwrap(), next);
    let versions = admin.history().unwrap();
    let original = versions
        .iter()
        .find(|version| version.version == 1)
        .unwrap();
    assert_eq!(
        admin
            .restore(&Restore::Server(original.clone()), &hash(&next), timeout)
            .unwrap()
            .hash,
        hash(&active)
    );
    let local = active.replace("min = 10", "min = 14");
    let path = admin.backup_dir().join("older-local.toml");
    std::fs::write(&path, &local).unwrap();
    let backup = runner::admin::Backup {
        path,
        manifest_hash: hash(&local),
    };
    assert_eq!(
        admin
            .restore(&Restore::Local(backup), &hash(&active), timeout)
            .unwrap()
            .hash,
        hash(&local)
    );
    let logs = admin.runner.logs();
    let inputs: Vec<_> = logs.iter().filter(|log| log.stdin.is_some()).collect();
    assert_eq!(inputs.len(), 2);
    assert!(inputs[0].args.contains(&"-i".into()));
    assert_eq!(inputs[0].stdin.as_deref(), Some(next.as_str()));
    assert!(
        inputs[1]
            .args
            .iter()
            .any(|arg| arg == "--note=restore older-local.toml")
    );
    assert!(logs.iter().any(|log| {
        log.args
            .windows(3)
            .any(|args| args == ["manifest", "activate", "1"])
    }));
    assert!(
        admin
            .apply(&next, "stale review", &hash(&active), timeout)
            .unwrap_err()
            .to_string()
            .contains("active manifest changed")
    );
}

#[test]
#[cfg(unix)]
fn timeout_reports_an_unconfirmed_write_instead_of_success() {
    let (_temp, admin) = isolated_admin();
    let error = admin
        .wait_for("sha256:unknown", std::time::Duration::ZERO)
        .unwrap_err();
    assert!(error.contains("unconfirmed"));
    assert!(error.contains("Refresh status"));
}

#[cfg(unix)]
fn isolated_fixtures() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let fixtures = temp.path().join("fixtures");
    std::fs::create_dir_all(fixtures.join("bin")).unwrap();
    for entry in std::fs::read_dir(fixture("")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), fixtures.join(entry.file_name())).unwrap();
        }
    }
    for name in ["kubectl", "open-pact-client"] {
        std::fs::copy(
            fixture(&format!("bin/{name}")),
            fixtures.join("bin").join(name),
        )
        .unwrap();
    }
    (temp, fixtures)
}

#[cfg(unix)]
fn isolated_client() -> (tempfile::TempDir, PathBuf, Client) {
    let (temp, fixtures) = isolated_fixtures();
    let client = Client {
        runner: Runner::default(),
        executable: fixtures.join("bin/open-pact-client"),
    };
    (temp, fixtures, client)
}

#[test]
#[cfg(unix)]
fn status_asks_the_gateway_and_a_denied_check_is_a_report() {
    let (_temp, fixtures, client) = isolated_client();
    client.status().unwrap();
    assert!(
        client
            .runner
            .logs()
            .iter()
            .any(|log| log.args == ["status", "--online", "--json"])
    );
    std::fs::write(fixtures.join("denied"), "").unwrap();
    let check = client.check().unwrap();
    assert!(!check.accepted);
    assert_eq!(check.reasons, ["Password is 4 characters, 10 needed"]);
    assert_eq!(client.runner.logs().last().unwrap().exit, Some(1));
}

#[test]
#[cfg(unix)]
fn a_preview_with_a_wrong_company_key_is_shown_not_failed() {
    let (_temp, _fixtures, client) = isolated_client();
    let preview = client.preview("opi1:mismatch").unwrap();
    assert!(!preview.company.matches_invitation);
    assert!(
        client
            .preview("opi1:expired")
            .unwrap_err()
            .starts_with("This invitation expired")
    );
    let log = &client.runner.logs()[0];
    assert_eq!(log.args, ["join", "--preview", "--", "opi1:mismatch"]);
}

#[test]
#[cfg(unix)]
fn join_reads_a_denied_result_and_the_last_error_line() {
    let (_temp, _fixtures, client) = isolated_client();
    let mut events = Vec::new();
    client
        .join("opi1:denied", &[], false, |event| events.push(event))
        .unwrap();
    assert!(matches!(
        events.last(),
        Some(JoinEvent::Result { result, .. }) if result == "denied"
    ));
    let mut steps = 0;
    let error = client
        .join("opi1:broken", &[], false, |_| steps += 1)
        .unwrap_err();
    assert_eq!(
        error,
        "The VPN probe failed, so the first check was not sent."
    );
    assert_eq!(steps, 2);
    let words = &client.runner.logs()[1].args;
    assert_eq!(words[words.len() - 2..], ["--", "opi1:broken"]);
}

#[test]
fn installed_cli_is_used_when_it_is_as_new_as_the_bundled_one() {
    use runner::client::at_least;
    assert!(at_least("open-pact-client 0.6.0", "open-pact-client 0.6.0"));
    assert!(at_least("open-pact-client 0.7.1", "open-pact-client 0.6.0"));
    assert!(at_least(
        "open-pact-client 0.10.0",
        "open-pact-client 0.9.9"
    ));
    assert!(!at_least(
        "open-pact-client 0.5.9",
        "open-pact-client 0.6.0"
    ));
    assert!(!at_least(
        "open-pact-client 0.7.0-rc.1",
        "open-pact-client 0.7.0"
    ));
    assert!(at_least(
        "open-pact-client 0.7.0",
        "open-pact-client 0.7.0-rc.1"
    ));
    assert!(at_least("garbage", "garbage"));
    assert!(!at_least("garbage", "open-pact-client 0.6.0"));
}

#[test]
fn the_admin_app_tries_the_cli_bundled_with_it_first() {
    use runner::client::{cli_candidates, cli_name};
    let temp = tempfile::tempdir().unwrap();
    let macos = temp.path().join("open-pact-admin.app/Contents/MacOS");
    let helpers = temp.path().join("open-pact-admin.app/Contents/Helpers");
    std::fs::create_dir_all(&macos).unwrap();
    std::fs::create_dir_all(&helpers).unwrap();
    let app = macos.join("open-pact-admin");
    let bundled = helpers.join(cli_name());
    std::fs::write(&app, "").unwrap();
    std::fs::write(&bundled, "").unwrap();
    assert_eq!(cli_candidates(Some(&app)).first(), Some(&bundled));

    let zip = temp.path().join("zip");
    std::fs::create_dir_all(&zip).unwrap();
    let flat_app = zip.join("open-pact-admin");
    let flat_cli = zip.join(cli_name());
    std::fs::write(&flat_app, "").unwrap();
    std::fs::write(&flat_cli, "").unwrap();
    assert_eq!(cli_candidates(Some(&flat_app)).first(), Some(&flat_cli));
}

#[test]
fn shown_commands_are_quoted_for_a_posix_shell() {
    use runner::{shell_line, shell_quote};
    assert_eq!(shell_quote("--note=plain"), "--note=plain");
    assert_eq!(shell_quote("a b"), "'a b'");
    assert_eq!(shell_quote("$(touch x)"), "'$(touch x)'");
    assert_eq!(shell_quote("it's"), "'it'\\''s'");
    assert_eq!(shell_quote(""), "''");
    assert_eq!(
        shell_line(&["kubectl", "--note=Update `x`"]),
        "kubectl '--note=Update `x`'"
    );
}

#[test]
#[cfg(unix)]
fn login_shell_path_is_read_once_with_a_time_limit() {
    use runner::{compose_path, login_path};
    use std::ffi::OsString;
    use std::time::Duration;
    let temp = tempfile::tempdir().unwrap();
    let shell = temp.path().join("shell");
    executable(
        &shell,
        "#!/bin/sh\nprintf 'welcome\\n'\nprintf %s '/fictional/bin:/other/bin'\n",
    );
    assert_eq!(
        login_path(&shell, Duration::from_secs(5)),
        Some(OsString::from("/fictional/bin:/other/bin"))
    );
    let slow = temp.path().join("slow");
    executable(&slow, "#!/bin/sh\nexec sleep 5\n");
    let started = std::time::Instant::now();
    assert_eq!(login_path(&slow, Duration::from_millis(200)), None);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(
        login_path(&temp.path().join("missing"), Duration::from_secs(1)),
        None
    );
    let joined = compose_path(Some("/a:/b".into()), Some("/b:/c".into()));
    assert_eq!(
        joined,
        OsString::from("/a:/b:/c:/opt/homebrew/bin:/usr/local/bin")
    );
    let fallback = compose_path(None, Some("/usr/bin".into()));
    assert_eq!(
        fallback,
        OsString::from("/usr/bin:/opt/homebrew/bin:/usr/local/bin")
    );
    // The Homebrew directories are added to a login PATH that lacks them, and never twice.
    assert_eq!(
        compose_path(Some("/usr/local/bin:/a".into()), None),
        OsString::from("/usr/local/bin:/a:/opt/homebrew/bin")
    );
}

#[test]
#[cfg(unix)]
fn commands_run_with_the_tool_path_and_stop_after_the_limit() {
    let temp = tempfile::tempdir().unwrap();
    let show = temp.path().join("show");
    executable(&show, "#!/bin/sh\nprintf %s \"$PATH\"\n");
    let log = Runner::default().run(&show, &[]).unwrap();
    assert_eq!(log.stdout.trim(), runner::tool_path().to_string_lossy());
    let hang = temp.path().join("hang");
    executable(&hang, "#!/bin/sh\nexec sleep 5\n");
    let runner = Runner::default().with_timeout(std::time::Duration::from_millis(200));
    let started = std::time::Instant::now();
    let error = runner.run(&hang, &[]).unwrap_err();
    assert!(error.contains("did not finish within"));
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
}

#[test]
fn login_bash_reads_bash_profile_before_profile() {
    use runner::client::profile_name;
    let home = tempfile::tempdir().unwrap();
    assert_eq!(profile_name("/bin/zsh", home.path()), ".zprofile");
    assert_eq!(profile_name("/bin/bash", home.path()), ".profile");
    std::fs::write(home.path().join(".bash_profile"), "").unwrap();
    assert_eq!(profile_name("/bin/bash", home.path()), ".bash_profile");
    assert_eq!(profile_name("/bin/zsh", home.path()), ".zprofile");
}

#[test]
fn default_backup_folder_has_one_folder_per_cluster_and_namespace() {
    use std::path::PathBuf;
    let settings = |context: &str, namespace: &str| Settings {
        context: context.into(),
        namespace: namespace.into(),
        ..Settings::default()
    };
    let one = settings("arn:aws:eks:eu/prod", "open-pact").backup_folder();
    let two = settings("other", "open-pact").backup_folder();
    assert_ne!(one, two);
    assert!(one.ends_with("open-pact-admin/backups/arn_aws_eks_eu_prod/open-pact"));
    assert_eq!(
        one,
        Settings::backup_root().join("arn_aws_eks_eu_prod/open-pact")
    );
    assert_eq!(
        settings("x", "y").backup_folder_in(&PathBuf::from("/fictional/root")),
        PathBuf::from("/fictional/root/x/y")
    );
    // A settings file from an older version may still name a folder. It is ignored.
    let old: Settings = serde_json::from_str(
        r#"{"context":"x","namespace":"y","backup_dir":"/fictional/chosen","kubectl":""}"#,
    )
    .unwrap();
    assert_eq!(old.backup_folder(), settings("x", "y").backup_folder());
    assert_eq!(
        settings("x", "y").kubectl_program(),
        PathBuf::from("kubectl")
    );
    let with_path = Settings {
        kubectl: " /fictional/kubectl ".into(),
        ..settings("x", "y")
    };
    assert_eq!(
        with_path.kubectl_program(),
        PathBuf::from("/fictional/kubectl")
    );
}

#[test]
#[cfg(unix)]
fn another_admins_write_between_review_and_apply_is_reported() {
    use runner::admin::hash;
    let (temp, admin) = isolated_admin();
    let fixtures = temp.path().join("fixtures");
    let active = admin.manifest(None).unwrap();
    let other = active.replace("min = 10", "min = 99");
    std::fs::write(fixtures.join("race.toml"), &other).unwrap();
    let next = active.replace("min = 10", "min = 12");
    let written = admin
        .apply(
            &next,
            "Fictional change",
            &hash(&active),
            std::time::Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(written.hash, hash(&next));
    assert_eq!(written.overwritten, Some(hash(&other)));
}

#[test]
#[cfg(unix)]
fn refused_and_unconfirmed_writes_say_which_they_are() {
    use runner::admin::hash;
    let (_temp, admin) = isolated_admin();
    let active = admin.manifest(None).unwrap();
    let timeout = std::time::Duration::from_secs(1);
    let refused = admin
        .apply(&active, "stale", "sha256:other", timeout)
        .unwrap_err()
        .to_string();
    assert!(refused.contains("Nothing was written."));
    assert!(!refused.contains("unconfirmed"));
    let next = active.replace("min = 10", "min = 12");
    let unknown = admin
        .apply(&next, "slow", &hash(&active), std::time::Duration::ZERO)
        .unwrap_err();
    assert!(matches!(unknown, runner::admin::WriteError::Unknown(_)));
    assert!(unknown.to_string().contains("unconfirmed"));
}

#[test]
#[cfg(unix)]
fn a_gateway_refusal_reaches_the_apply_view_in_its_own_words() {
    use runner::admin::hash;
    let (temp, admin) = isolated_admin();
    let reason = "schedule.interval 4m must be whole minutes or hours from 5m to 24h";
    std::fs::write(temp.path().join("fixtures/refuse.txt"), reason).unwrap();
    let active = admin.manifest(None).unwrap();
    let next = active.replace("interval = \"55m\"", "interval = \"4m\"");
    let error = admin
        .apply(
            &next,
            "Too short",
            &hash(&active),
            std::time::Duration::from_secs(1),
        )
        .unwrap_err();
    assert!(error.to_string().contains(reason), "{error}");
    assert_eq!(admin.manifest(None).unwrap(), active);
}

#[test]
#[cfg(unix)]
fn notes_that_start_with_a_dash_stay_values() {
    let (_temp, admin) = isolated_admin();
    admin.invite("72h", "-Bob; $(x)").unwrap();
    let active = admin.manifest(None).unwrap();
    admin
        .apply(
            &active.replace("min = 10", "min = 12"),
            "-dash",
            &runner::admin::hash(&active),
            std::time::Duration::from_secs(1),
        )
        .unwrap();
    let logs = admin.runner.logs();
    assert!(
        logs.iter()
            .any(|log| log.args.contains(&"--note=-Bob; $(x)".into()))
    );
    assert!(
        logs.iter()
            .any(|log| log.args.contains(&"--note=-dash".into()))
    );
}

#[test]
#[cfg(unix)]
fn one_bad_backup_file_is_skipped_and_never_blocks_sync() {
    use runner::admin::{Restore, hash};
    let (_temp, admin) = isolated_admin();
    let first = admin.sync().unwrap();
    assert!(first.warnings.is_empty());
    let folder = admin.backup_dir();
    let text = "name = \"Fictional\"\n";
    let named = folder.join(format!("20261116T100000.000Z-{}.toml", &hash(text)[7..19]));
    std::fs::write(&named, "name = \"Truncated\"\n").unwrap();
    std::fs::write(folder.join("binary.toml"), [0xff, 0xfe, 0x00]).unwrap();
    std::fs::write(folder.join("notes.txt"), "ignored").unwrap();
    let second = admin.sync().unwrap();
    assert_eq!(second.backups.len(), 2);
    assert_eq!(second.warnings.len(), 2);
    assert!(
        second
            .warnings
            .iter()
            .any(|w| w.contains("does not match the hash in its name"))
    );
    let forged = runner::admin::Backup {
        path: named.clone(),
        manifest_hash: hash("name = \"Truncated\"\n"),
    };
    assert!(
        admin
            .restore_text(&Restore::Local(forged))
            .unwrap_err()
            .contains("does not match")
    );
    std::fs::write(&named, text).unwrap();
    let third = admin.sync().unwrap();
    assert_eq!(third.backups.len(), 3);
    assert_eq!(third.warnings.len(), 1);
}

#[test]
#[cfg(unix)]
fn backups_are_written_through_a_temporary_file() {
    use runner::admin::hash;
    let (_temp, admin) = isolated_admin();
    std::fs::create_dir_all(admin.backup_dir()).unwrap();
    std::fs::write(admin.backup_dir().join(".leftover.toml.part"), "partial").unwrap();
    let active = admin.manifest(None).unwrap();
    admin
        .apply(
            &active.replace("min = 10", "min = 12"),
            "Fictional change",
            &hash(&active),
            std::time::Duration::from_secs(1),
        )
        .unwrap();
    let backups = admin.backups().unwrap();
    assert!(
        backups
            .iter()
            .any(|backup| std::fs::read_to_string(&backup.path).unwrap() == active)
    );
    assert!(
        backups
            .iter()
            .all(|backup| backup.path.extension().is_some_and(|e| e == "toml"))
    );
    let partial = std::fs::read_dir(admin.backup_dir())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
        .count();
    assert_eq!(partial, 1);
}

#[test]
#[cfg(unix)]
fn the_cluster_dropdown_lists_kubectl_contexts_and_preselects_saved_then_current() {
    use runner::admin::{current_context, list_contexts, pick_context};
    let runner = Runner::default();
    let kubectl = fixture("bin/kubectl");
    let contexts = list_contexts(&runner, &kubectl).unwrap();
    assert_eq!(
        contexts,
        ["test-cluster", "staging-cluster", "locked-cluster"]
    );
    let current = current_context(&runner, &kubectl);
    assert_eq!(current.as_deref(), Some("staging-cluster"));
    assert_eq!(
        pick_context("test-cluster", &contexts, current.as_deref()).as_deref(),
        Some("test-cluster")
    );
    assert_eq!(
        pick_context("", &contexts, current.as_deref()).as_deref(),
        Some("staging-cluster")
    );
    assert_eq!(
        pick_context("gone-cluster", &contexts, current.as_deref()).as_deref(),
        Some("staging-cluster")
    );
    assert_eq!(pick_context("", &contexts, Some("not-listed")), None);
    let logs = runner.logs();
    assert_eq!(logs[0].args, ["config", "get-contexts", "-o", "name"]);
    assert_eq!(logs[1].args, ["config", "current-context"]);
}

#[test]
fn the_namespace_dropdown_prefers_saved_then_open_pact_then_the_first() {
    use runner::admin::pick_namespace;
    let list = |names: &[&str]| {
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>()
    };
    let with = list(&["default", "open-pact", "team-a"]);
    assert_eq!(pick_namespace("team-a", &with).as_deref(), Some("team-a"));
    assert_eq!(pick_namespace("", &with).as_deref(), Some("open-pact"));
    assert_eq!(pick_namespace("gone", &with).as_deref(), Some("open-pact"));
    let without = list(&["default", "team-a"]);
    assert_eq!(pick_namespace("", &without).as_deref(), Some("default"));
    assert_eq!(pick_namespace("", &[]), None);
}

#[test]
#[cfg(unix)]
fn changing_the_cluster_lists_the_namespaces_of_that_cluster() {
    use runner::admin::list_namespaces;
    let runner = Runner::default();
    let kubectl = fixture("bin/kubectl");
    assert_eq!(
        list_namespaces(&runner, &kubectl, "test-cluster").unwrap(),
        ["default", "kube-system", "open-pact"]
    );
    assert_eq!(
        list_namespaces(&runner, &kubectl, "staging-cluster").unwrap(),
        ["default", "team-a"]
    );
    let logs = runner.logs();
    assert_eq!(
        logs[0].args,
        [
            "get",
            "namespaces",
            "-o",
            "name",
            "--context",
            "test-cluster"
        ]
    );
    assert_eq!(
        logs[1].args,
        [
            "get",
            "namespaces",
            "-o",
            "name",
            "--context",
            "staging-cluster"
        ]
    );
}

#[test]
#[cfg(unix)]
fn a_namespace_list_that_fails_gives_one_short_kubectl_line() {
    use runner::admin::{list_namespaces, short_error};
    let runner = Runner::default();
    let kubectl = fixture("bin/kubectl");
    let error = list_namespaces(&runner, &kubectl, "locked-cluster").unwrap_err();
    assert!(error.contains("Forbidden"));
    let line = short_error(&error);
    assert!(!line.contains('\n'));
    assert!(line.starts_with("Error from server (Forbidden)"));
    assert!(line.chars().count() <= 140);
    let empty = list_namespaces(&runner, &kubectl, "empty-cluster").unwrap_err();
    assert_eq!(empty, "kubectl returned no namespaces.");
    assert_eq!(
        short_error("error: You must be logged in\nmore"),
        "You must be logged in"
    );
    assert_eq!(short_error(&"x".repeat(300)).chars().count(), 140);
}

#[test]
#[cfg(unix)]
fn an_approval_that_came_while_the_app_was_closed_resumes_the_join() {
    use runner::client::resume_join;
    let (_temp, fixtures, client) = isolated_client();
    // The saved state is approved and a claim exists: nothing to resume.
    assert_eq!(resume_join(&client.status().unwrap()), None);
    // IT approved while the app was closed: the live state is approved and there is no claim yet.
    std::fs::write(fixtures.join("approved-no-claim"), "").unwrap();
    let status = client.status().unwrap();
    assert_eq!(status.approval.state.as_deref(), Some("approved"));
    assert!(status.approval.live && status.last_claim.is_none());
    assert_eq!(resume_join(&status), Some(true));
    let mut pending = status.clone();
    pending.approval.state = Some("pending".into());
    pending.last_claim = Some(serde_json::json!({}));
    assert_eq!(resume_join(&pending), Some(true));
    let mut revoked = status;
    revoked.approval.state = Some("revoked".into());
    assert_eq!(resume_join(&revoked), None);
    // The resumed join has no invitation.
    client.join("", &[], true, |_| {}).unwrap();
    assert_eq!(
        client.runner.logs().last().unwrap().args,
        ["join", "--yes", "--json", "--auto-send", "on"]
    );
}

#[test]
#[cfg(unix)]
fn a_write_timeout_still_names_the_manifest_that_was_replaced() {
    use runner::admin::hash;
    let (temp, admin) = isolated_admin();
    let active = admin.manifest(None).unwrap();
    let other = active.replace("min = 10", "min = 99");
    std::fs::write(temp.path().join("fixtures/race.toml"), &other).unwrap();
    let error = admin
        .apply(
            &active.replace("min = 10", "min = 12"),
            "Fictional change",
            &hash(&active),
            std::time::Duration::ZERO,
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("unconfirmed"));
    assert!(error.contains(&hash(&other)));
    let after =
        runner::admin::WriteError::AfterWrite("The manifest was saved, then replaced.".into());
    assert!(!after.to_string().contains("unconfirmed"));
}

#[test]
#[cfg(feature = "desktop")]
fn closing_the_last_window_quits_both_apps() {
    use gpui::QuitMode;
    assert_eq!(runner::desktop::QUIT_MODE, QuitMode::LastWindowClosed);
}

#[test]
fn status_reports_a_newer_command_line_tool_only_when_the_field_has_its_shape() {
    use runner::client::Status;
    let parse = |text: &str| serde_json::from_str::<Status>(text).unwrap();
    assert!(
        parse(include_str!("../../../tests/fixtures/status.json"))
            .update
            .is_none()
    );
    let with = parse(include_str!(
        "../../../tests/fixtures/status-cli-update.json"
    ))
    .update
    .unwrap();
    assert_eq!(
        (with.current.as_str(), with.latest.as_str()),
        ("0.6.0", "0.6.1")
    );
    assert_eq!(
        with.command.as_deref(),
        Some("brew upgrade open-pact-client")
    );
    let bundled = parse(include_str!(
        "../../../tests/fixtures/status-cli-update-bundled.json"
    ))
    .update
    .unwrap();
    assert_eq!(bundled.command, None);
    assert!(
        parse(include_str!(
            "../../../tests/fixtures/status-cli-update-unknown.json"
        ))
        .update
        .is_none()
    );
}

mod results {
    use chrono::{TimeZone, Utc};
    use runner::results::{
        ClaimDetail, ClaimList, ControlStatus, Filters, OLD_GATEWAY, Period, ResultFilter,
        check_name, explain_error, failed_checks_text, result_tag, unreadable_text,
    };
    use runner::text::Tone;

    const LIST: &str = include_str!("../../../tests/fixtures/claims.json");
    const SHOW: &str = include_str!("../../../tests/fixtures/claim.json");

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 16, 12, 0, 0).unwrap()
    }

    fn words(filters: &Filters) -> Vec<String> {
        filters.list_words(now())
    }

    #[test]
    fn the_list_json_is_read_with_its_unreadable_count() {
        let list: ClaimList = serde_json::from_str(LIST).unwrap();
        assert_eq!(list.claims.len(), 6);
        assert_eq!(list.unreadable, 2);
        let first = &list.claims[0];
        assert_eq!(first.id, 4815);
        assert_eq!(first.code(), "0a1b2c3d4e5f");
        assert_eq!(
            first.device_note.as_deref(),
            Some("MacBook, Example Person")
        );
        assert_eq!(first.result.as_deref(), Some("accepted"));
        let last = &list.claims[5];
        assert_eq!(
            (last.result.as_deref(), last.device_note.as_deref()),
            (None, None)
        );
        let empty: ClaimList = serde_json::from_str(r#"{"claims":[],"unreadable":0}"#).unwrap();
        assert!(empty.claims.is_empty());
    }

    #[test]
    fn the_show_json_is_read_control_by_control() {
        let detail: ClaimDetail = serde_json::from_str(SHOW).unwrap();
        assert_eq!(detail.id, 4814);
        assert_eq!(detail.hash_text(), "97e1594a0000");
        assert_eq!(detail.os.as_deref(), Some("macos"));
        assert_eq!(detail.controls.len(), 7);
        let by_id = |id: &str| detail.controls.iter().find(|c| c.id == id).unwrap();
        let age = by_id("os_patch_age_days");
        assert_eq!(age.status, ControlStatus::Fail);
        assert_eq!(age.name(), "OS updates");
        assert_eq!(age.value_text(), "40");
        assert_eq!(age.required_text(), "≤ 30");
        assert_eq!(age.grace_text(), "1 d");
        assert_ne!(age.first_failed_text(), "–");
        assert_ne!(age.deadline_text(), "–");
        let lock = by_id("screen_lock");
        assert_eq!(lock.value_text(), "≤ 5 min");
        assert_eq!(lock.required_text(), "≤ 5 min");
        assert_eq!(lock.first_failed_text(), "–");
        assert_eq!(by_id("password_min_length").required_text(), "≥ 10");
        assert_eq!(by_id("antimalware_realtime").status, ControlStatus::Unknown);
        let skipped = by_id("secure_boot");
        assert_eq!(skipped.status, ControlStatus::NotRequired);
        assert_eq!(
            (
                skipped.value_text(),
                skipped.required_text(),
                skipped.grace_text()
            ),
            ("–".to_owned(), "–".to_owned(), "–".to_owned())
        );
    }

    #[test]
    fn a_status_the_app_does_not_know_reads_as_unknown() {
        let control: runner::results::ClaimControl =
            serde_json::from_str(r#"{"id":"firewall","value":"on","status":"something_new"}"#)
                .unwrap();
        assert_eq!(control.status, ControlStatus::Unknown);
    }

    #[test]
    fn failing_controls_come_first_and_each_group_keeps_its_order() {
        let detail: ClaimDetail = serde_json::from_str(SHOW).unwrap();
        let order: Vec<_> = detail.ordered().iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            order,
            [
                "password_min_length",
                "os_patch_age_days",
                "antimalware_realtime",
                "disk_encryption",
                "firewall",
                "screen_lock",
                "secure_boot",
            ]
        );
    }

    #[test]
    fn failed_checks_show_plain_names_three_at_most() {
        let ids = |list: &[&str]| list.iter().map(|id| (*id).to_owned()).collect::<Vec<_>>();
        assert_eq!(failed_checks_text(&[]), "–");
        assert_eq!(failed_checks_text(&ids(&["firewall"])), "Firewall");
        assert_eq!(
            failed_checks_text(&ids(&["firewall", "screen_lock", "disk_encryption"])),
            "Firewall, Screen lock, Disk encryption"
        );
        let list: ClaimList = serde_json::from_str(LIST).unwrap();
        assert_eq!(
            list.claims[2].failed_text(),
            "Disk encryption, Firewall, Screen lock +2"
        );
        assert_eq!(check_name("custom_vault_check"), "custom_vault_check");
    }

    #[test]
    fn unreadable_results_are_a_quiet_note() {
        assert_eq!(unreadable_text(0), None);
        assert_eq!(
            unreadable_text(1).as_deref(),
            Some("1 older result can no longer be read.")
        );
        assert_eq!(
            unreadable_text(2).as_deref(),
            Some("2 older results can no longer be read.")
        );
    }

    #[test]
    fn results_have_a_word_and_a_colour() {
        assert_eq!(
            result_tag(Some("accepted")),
            ("Accepted".to_owned(), Tone::Good)
        );
        assert_eq!(
            result_tag(Some("warnings")),
            ("Warnings".to_owned(), Tone::Warn)
        );
        assert_eq!(result_tag(Some("denied")), ("Denied".to_owned(), Tone::Bad));
        assert_eq!(result_tag(None), ("Unknown".to_owned(), Tone::Idle));
    }

    #[test]
    fn filters_become_gateway_flags() {
        let all = Filters::default();
        assert!(all.is_default());
        assert_eq!(words(&all), ["claims", "list", "--json", "--limit", "200"]);
        let device = Filters {
            device: Some("7c09e1f4a2b8".into()),
            ..Filters::default()
        };
        assert!(!device.is_default());
        assert_eq!(
            words(&device),
            [
                "claims",
                "list",
                "--json",
                "--device",
                "7c09e1f4a2b8",
                "--limit",
                "200"
            ]
        );
        let every_flag = Filters {
            device: Some("0a1b2c3d4e5f".into()),
            result: ResultFilter::Denied,
            period: Period::Day,
        };
        assert_eq!(
            words(&every_flag),
            [
                "claims",
                "list",
                "--json",
                "--device",
                "0a1b2c3d4e5f",
                "--result",
                "denied",
                "--since",
                "2026-11-15T12:00:00Z",
                "--limit",
                "200",
            ]
        );
        for (result, flag) in [
            (ResultFilter::Accepted, "accepted"),
            (ResultFilter::Warnings, "warnings"),
        ] {
            let filters = Filters {
                result,
                ..Filters::default()
            };
            assert_eq!(words(&filters)[3..5], ["--result", flag]);
        }
        for (period, since) in [
            (Period::Week, "2026-11-09T12:00:00Z"),
            (Period::Month, "2026-10-17T12:00:00Z"),
        ] {
            let filters = Filters {
                period,
                ..Filters::default()
            };
            assert_eq!(words(&filters)[3..5], ["--since", since]);
        }
    }

    #[test]
    fn the_gateway_error_for_an_unknown_subcommand_says_the_gateway_is_old() {
        assert_eq!(
            explain_error("error: unrecognized subcommand 'claims'"),
            OLD_GATEWAY
        );
        assert_eq!(explain_error("no claim with id 5"), "no claim with id 5");
        assert_eq!(
            OLD_GATEWAY,
            "The gateway is older than 0.7; results need gateway 0.7 or later."
        );
    }

    #[cfg(unix)]
    mod gateway {
        use super::*;
        use runner::{
            Runner,
            admin::{Admin, Settings},
        };

        fn admin(context: &str) -> Admin {
            let mut admin = Admin::new(
                Runner::default(),
                Settings {
                    context: context.into(),
                    namespace: "open-pact".into(),
                    ..Settings::default()
                },
            );
            admin.kubectl = super::super::fixture("bin/kubectl");
            admin
        }

        #[test]
        fn the_admin_lists_and_shows_results_through_kubectl_exec() {
            let admin = admin("fictional-cluster");
            let filters = Filters {
                device: Some("7c09e1f4a2b8".into()),
                result: ResultFilter::Warnings,
                period: Period::Week,
            };
            let list = admin.claims(&filters, now()).unwrap();
            assert_eq!(list.claims.len(), 6);
            let detail = admin.claim(4814).unwrap();
            assert_eq!(detail.controls.len(), 7);
            let logs = admin.runner.logs();
            assert_eq!(logs.len(), 2);
            assert_eq!(
                logs[0].args,
                [
                    "--context",
                    "fictional-cluster",
                    "-n",
                    "open-pact",
                    "exec",
                    "deploy/open-pact-gateway",
                    "--",
                    "open-pact-gateway",
                    "claims",
                    "list",
                    "--json",
                    "--device",
                    "7c09e1f4a2b8",
                    "--result",
                    "warnings",
                    "--since",
                    "2026-11-09T12:00:00Z",
                    "--limit",
                    "200",
                ]
            );
            assert_eq!(logs[1].args[8..], ["claims", "show", "4814", "--json"]);
            assert_eq!(
                Admin::claims_command(&filters, now()),
                "kubectl exec deploy/open-pact-gateway -- open-pact-gateway claims list --json --device 7c09e1f4a2b8 --result warnings --since 2026-11-09T12:00:00Z --limit 200"
            );
        }

        #[test]
        fn an_unknown_result_shows_the_gateway_error() {
            assert_eq!(
                admin("fictional-cluster").claim(5).unwrap_err(),
                "no claim with id 5"
            );
        }

        #[test]
        fn an_older_gateway_gets_the_version_hint_for_list_and_show() {
            let admin = admin("old-gateway-cluster");
            assert_eq!(
                admin.claims(&Filters::default(), now()).unwrap_err(),
                OLD_GATEWAY
            );
            assert_eq!(admin.claim(4814).unwrap_err(), OLD_GATEWAY);
        }
    }
}
