//! The real binary on `manifest check`: a draft is judged by the rules a client and the gateway run,
//! with no home, no enrolment and no network.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const DEMO: &str = include_str!("../../../examples/manifest.toml");

fn check(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_open-pact-client"))
        .env_remove("HOME")
        .args(["manifest", "check"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn json(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert_eq!(stdout.lines().count(), 1, "one document: {stdout:?}");
    assert!(stdout.ends_with('\n'), "{stdout:?}");
    serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("{stdout:?}: {error}"))
}

fn replaced(from: &str, to: &str) -> String {
    assert!(DEMO.contains(from), "fixture lacks {from}");
    DEMO.replacen(from, to, 1)
}

#[test]
fn a_valid_manifest_passes_without_a_home() {
    let output = check(&["--json"], DEMO);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "{\"ok\":true,\"errors\":[]}\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn a_toml_syntax_error_reports_its_line() {
    let draft = replaced("claim_max_age = \"24h\"", "claim_max_age = ");
    let line = draft.lines().position(|l| l == "claim_max_age = ").unwrap() + 1;

    let output = check(&["--json"], &draft);

    assert_eq!(output.status.code(), Some(1));
    let report = json(&output);
    assert_eq!(report["ok"], false);
    let errors = report["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1, "{report}");
    assert_eq!(errors[0]["line"], line, "{report}");
    assert!(!errors[0]["message"].as_str().unwrap().is_empty());
    assert!(errors[0]["key"].is_null(), "{report}");
}

#[test]
fn a_core_rule_error_names_its_message_and_key() {
    let output = check(
        &["--json"],
        &replaced("interval = \"55m\"", "interval = \"4m\""),
    );

    assert_eq!(output.status.code(), Some(1));
    let report = json(&output);
    assert_eq!(report["ok"], false);
    let errors = report["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1, "{report}");
    assert!(
        errors[0]["message"].as_str().unwrap().contains("4m"),
        "{report}"
    );

    let output = check(
        &["--json"],
        &replaced("witness_quorum = 1", "witness_quorum = 2"),
    );

    assert_eq!(output.status.code(), Some(1));
    let report = json(&output);
    assert_eq!(report["errors"][0]["key"], "log.witness_quorum", "{report}");
    assert!(report["errors"][0]["line"].is_null(), "{report}");
}

#[test]
fn a_builtin_this_client_does_not_run_is_refused() {
    let draft = replaced("id = \"screen_lock\"", "id = \"screen_lock_strict\"");

    let output = check(&["--json"], &draft);

    assert_eq!(output.status.code(), Some(1));
    let report = json(&output);
    assert_eq!(report["ok"], false);
    let message = report["errors"][0]["message"].as_str().unwrap();
    assert!(
        message.contains("screen_lock_strict") && message.contains("builtin:screen_lock@1"),
        "{report}"
    );
}

#[test]
fn text_output_prints_one_line_per_error() {
    let valid = check(&[], DEMO);
    assert_eq!(valid.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&valid.stdout),
        "Manifest is valid.\n"
    );

    let invalid = check(&[], &replaced("interval = \"55m\"", "interval = \"4m\""));
    assert_eq!(invalid.status.code(), Some(1));
    let stdout = String::from_utf8(invalid.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout:?}");
    assert!(stdout.contains("4m"), "{stdout:?}");
}

#[test]
fn input_that_is_not_utf8_is_one_error() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_open-pact-client"))
        .args(["manifest", "check", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&[0xff, 0xfe])
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(json(&output)["errors"][0]["message"], "not UTF-8");
}

#[test]
fn a_usage_error_exits_2() {
    let with_json = check(&["--json", "--bogus"], "");
    assert_eq!(with_json.status.code(), Some(2));
    assert!(!json(&with_json)["error"].as_str().unwrap().is_empty());

    let without_json = check(&["--bogus"], "");
    assert_eq!(without_json.status.code(), Some(2));
    assert!(without_json.stdout.is_empty());
    assert!(String::from_utf8_lossy(&without_json.stderr).contains("--bogus"));
}
