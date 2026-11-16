//! The admin app asks the open-pact CLI whether a manifest draft is valid. The fixture CLI answers
//! by a marker comment in the draft; the other CLIs are small scripts.
#![cfg(unix)]
use runner::admin::{Admin, CLI_TOO_OLD, CheckError, Settings};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MANIFEST: &str = include_str!("../../../tests/fixtures/manifest.toml");

fn admin_with(client: &Path) -> Admin {
    let mut admin = Admin::new(runner::Runner::default(), Settings::default());
    admin.client = Some(client.to_path_buf());
    admin
}

fn fixture_cli() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/open-pact-client")
}

fn script(directory: &Path, name: &str, text: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = directory.join(name);
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn draft(marker: &str) -> String {
    format!("{MANIFEST}\n# fixture:{marker}\n")
}

#[test]
fn a_valid_draft_has_no_errors_and_the_draft_goes_in_through_stdin() {
    let admin = admin_with(&fixture_cli());
    assert_eq!(admin.check_manifest(MANIFEST), Ok(Vec::new()));
    let temp = tempfile::tempdir().unwrap();
    let echo = script(
        temp.path(),
        "echo",
        "#!/bin/sh\ncat > \"$0.stdin\"\nprintf '%s\\n' \"$*\" > \"$0.args\"\nprintf '%s\\n' '{\"ok\":true,\"errors\":[]}'\n",
    );
    assert_eq!(admin_with(&echo).check_manifest(MANIFEST), Ok(Vec::new()));
    assert_eq!(
        std::fs::read_to_string(temp.path().join("echo.stdin")).unwrap(),
        MANIFEST
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("echo.args"))
            .unwrap()
            .trim(),
        "manifest check --json"
    );
}

#[test]
fn an_error_with_a_key_keeps_its_key() {
    let errors = admin_with(&fixture_cli())
        .check_manifest(&draft("keys"))
        .unwrap();
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].key.as_deref(),
        Some("controls.os_patch_age_days.required.windows")
    );
    assert_eq!(errors[0].line, None);
}

#[test]
fn an_error_with_a_line_only_keeps_its_line() {
    let text = draft("line");
    let errors = admin_with(&fixture_cli()).check_manifest(&text).unwrap();
    let line = text
        .lines()
        .position(|row| row.contains("fixture:line"))
        .unwrap()
        + 1;
    assert_eq!(
        errors,
        [CheckError {
            message: "invalid TOML value".into(),
            line: Some(line),
            key: None
        }]
    );
}

#[test]
fn an_old_cli_is_one_error_that_asks_for_an_update() {
    let expected = [CheckError {
        message: CLI_TOO_OLD.into(),
        line: None,
        key: None,
    }];
    assert_eq!(
        admin_with(&fixture_cli()).check_manifest(&draft("old-cli")),
        Ok(expected.to_vec())
    );
    let temp = tempfile::tempdir().unwrap();
    let usage = script(temp.path(), "usage", "#!/bin/sh\nexit 2\n");
    assert_eq!(
        admin_with(&usage).check_manifest(MANIFEST),
        Ok(expected.to_vec())
    );
    let clap = script(
        temp.path(),
        "clap",
        "#!/bin/sh\nprintf '%s\\n' \"error: unrecognized subcommand 'manifest'\" >&2\nexit 1\n",
    );
    assert_eq!(
        admin_with(&clap).check_manifest(MANIFEST),
        Ok(expected.to_vec())
    );
}

#[test]
fn a_newer_cli_is_tried_when_the_first_is_too_old() {
    let temp = tempfile::tempdir().unwrap();
    let old = script(temp.path(), "old", "#!/bin/sh\nexit 2\n");
    let admin = admin_with(&old);
    assert_eq!(
        admin
            .check_manifest_with(&[old.clone(), fixture_cli()], &draft("keys"))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        admin.check_manifest_with(&[old, fixture_cli()], MANIFEST),
        Ok(Vec::new())
    );
}

#[test]
fn a_slow_cli_is_stopped_at_the_limit() {
    let temp = tempfile::tempdir().unwrap();
    let slow = script(temp.path(), "slow", "#!/bin/sh\nexec sleep 5\n");
    let mut admin = admin_with(&slow);
    admin.check_limit = Duration::from_millis(300);
    let started = Instant::now();
    let error = admin.check_manifest(MANIFEST).unwrap_err();
    assert!(error.contains("did not finish"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn an_answer_that_does_not_agree_with_itself_is_never_valid() {
    let temp = tempfile::tempdir().unwrap();
    let say = |name: &str, code: i32, json: &str| {
        script(
            temp.path(),
            name,
            &format!("#!/bin/sh\nprintf '%s\\n' '{json}'\nexit {code}\n"),
        )
    };
    let refused_without_reason = say("none", 1, r#"{"ok":false,"errors":[]}"#);
    assert!(
        admin_with(&refused_without_reason)
            .check_manifest(MANIFEST)
            .is_err()
    );
    let ok_but_failed = say("exit", 1, r#"{"ok":true,"errors":[]}"#);
    assert!(admin_with(&ok_but_failed).check_manifest(MANIFEST).is_err());
    let reasons_with_ok_exit = say(
        "reasons",
        0,
        r#"{"ok":false,"errors":[{"message":"bad","line":null,"key":null}]}"#,
    );
    assert_eq!(
        admin_with(&reasons_with_ok_exit)
            .check_manifest(MANIFEST)
            .unwrap()
            .len(),
        1
    );
    let garbage = say("garbage", 0, "not json");
    assert!(admin_with(&garbage).check_manifest(MANIFEST).is_err());
    let crash = script(
        temp.path(),
        "crash",
        "#!/bin/sh\nprintf '%s\\n' 'boom' >&2\nexit 9\n",
    );
    assert_eq!(
        admin_with(&crash).check_manifest(MANIFEST),
        Err("boom".into())
    );
}

#[test]
fn a_missing_cli_is_an_error_that_says_what_to_install() {
    let admin = admin_with(Path::new("/fictional/missing/open-pact-client"));
    assert!(admin.check_manifest(MANIFEST).is_err());
    let none = admin.check_manifest_with(&[], MANIFEST).unwrap_err();
    assert!(none.contains("open-pact-client was not found"), "{none}");
}

#[test]
fn a_check_leaves_the_command_log_alone() {
    let admin = admin_with(&fixture_cli());
    admin.check_manifest(MANIFEST).unwrap();
    assert!(admin.runner.logs().is_empty());
}
