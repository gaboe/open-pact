#[cfg(unix)]
use runner::{
    Runner,
    admin::Admin,
    client::{Client, JoinEvent},
};
use runner::{
    admin::Settings,
    manifest::{self, Kind},
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

#[test]
fn every_toml_value_has_an_editable_control() {
    let text = "name = \"Example\"\nnumber = 3\nratio = 0.5\nactive = true\nlist = [1, 2]\n[table]\ninline = { threshold = 10 }\n[[controls]]\nid = \"disk\"\nrequired = true\n";
    let fields = manifest::fields(text).unwrap();
    assert_eq!(fields.len(), 8);
    for field in fields {
        let value = match field.kind {
            Kind::Text => "Changed",
            Kind::Number => "15",
            Kind::Bool => "false",
            Kind::List => "[3, 4]",
        };
        let changed = manifest::set_field(text, &field, value).unwrap();
        let new_fields = manifest::fields(&changed).unwrap();
        assert_eq!(
            new_fields
                .iter()
                .find(|f| f.path == field.path)
                .unwrap()
                .value,
            value
        );
    }
}

#[test]
fn form_labels_use_readable_names() {
    let text = "manifest_version = 1\n[schedule]\ninterval = \"55m\"\n[[controls]]\nid = \"disk\"\nrequire = { min = 10 }\n";
    let labels: Vec<_> = manifest::fields(text)
        .unwrap()
        .into_iter()
        .map(|field| (field.section, field.label))
        .collect();
    assert_eq!(
        labels,
        [
            ("Manifest", "Manifest version"),
            ("Automatic sending", "Interval"),
            ("Checks", "Check 1 · ID"),
            ("Checks", "Check 1 · Require · Min"),
        ]
        .map(|(section, label)| (section.to_owned(), label.to_owned()))
    );
}

#[test]
fn list_editor_adds_edits_and_removes_items() {
    use manifest::ListEdit;
    let text = "folders = [\"one\", \"two\"]\n";
    let field = manifest::fields(text).unwrap().remove(0);
    assert_eq!(manifest::list_items(&field).unwrap(), ["one", "two"]);
    let changed = manifest::edit_list(text, &field, ListEdit::Set(0, "new path")).unwrap();
    let changed = manifest::edit_list(&changed, &field, ListEdit::Remove(1)).unwrap();
    let changed = manifest::edit_list(&changed, &field, ListEdit::Add).unwrap();
    let items = manifest::list_items(&manifest::fields(&changed).unwrap().remove(0)).unwrap();
    assert_eq!(items, ["new path", ""]);
    assert!(manifest::edit_list(&changed, &field, ListEdit::Remove(9)).is_err());
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
    let settings = Settings {
        backup_dir: temp.path().into(),
        ..Settings::default()
    };
    let admin = runner::admin::Admin::new(runner::Runner::default(), settings);
    let text = "name = \"Fictional\"";
    std::fs::write(temp.path().join("example.toml"), text).unwrap();
    std::fs::write(temp.path().join("ignore.txt"), "ignored").unwrap();
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
            backup_dir: temp.path().join("backups"),
            ..Settings::default()
        },
    );
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
    let path = admin.settings.backup_dir.join("older-local.toml");
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
    assert_eq!(joined, OsString::from("/a:/b:/c"));
    let fallback = compose_path(None, Some("/usr/bin".into()));
    assert_eq!(
        fallback,
        OsString::from("/usr/bin:/opt/homebrew/bin:/usr/local/bin")
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
    let chosen = Settings {
        backup_dir: "/fictional/chosen".into(),
        ..settings("x", "y")
    };
    assert_eq!(chosen.backup_folder(), PathBuf::from("/fictional/chosen"));
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
