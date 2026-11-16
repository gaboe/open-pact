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
    assert!(admin.sync().unwrap_err().contains("does not match"));
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
            .unwrap(),
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
            .unwrap(),
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
            .unwrap(),
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
            .any(|arg| arg == "restore older-local.toml")
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
