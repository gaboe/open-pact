//! The real binary on a command line that does not parse: with a JSON flag, stdout holds one
//! error document and nothing else.

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_open-pact-client"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn an_argument_failure_with_a_json_flag_prints_one_error_document() {
    for args in [
        &["join", "--json", "--yes", "--auto-send", "maybe"][..],
        &["join", "--preview"],
        &["check", "--json", "--bogus"],
        &["status", "--json", "--bogus"],
    ] {
        let output = run(args);

        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let document: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("{args:?} printed {stdout:?}: {error}"));
        assert_eq!(document.as_object().unwrap().len(), 1, "{stdout}");
        assert!(!document["error"].as_str().unwrap().is_empty(), "{stdout}");
        assert_eq!(stdout.lines().count(), 1, "{stdout}");
        assert!(output.stderr.is_empty(), "{args:?}");
    }
}

#[test]
fn an_argument_failure_without_a_json_flag_stays_a_readable_error_on_stderr() {
    let output = run(&["join", "--bogus"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--bogus"));
}

#[test]
fn help_still_prints_on_stdout() {
    let output = run(&["join", "--help", "--json"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
}
