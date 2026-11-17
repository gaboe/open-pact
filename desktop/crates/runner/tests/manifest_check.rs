//! The admin app checks a manifest draft with the rules of open-pact-core.
use runner::admin::{CheckError, check_draft};

const MANIFEST: &str = include_str!("../../../tests/fixtures/manifest.toml");

fn replaced(from: &str, to: &str) -> String {
    assert!(MANIFEST.contains(from), "the fixture has no {from}");
    MANIFEST.replace(from, to)
}

#[test]
fn a_valid_draft_has_no_errors() {
    assert_eq!(check_draft(MANIFEST), Vec::new());
}

#[test]
fn an_error_with_a_key_keeps_its_key() {
    let errors = check_draft(&replaced(
        "required = { macos = { max = 30 }, windows = { max = 30 }",
        "required = { macos = { max = 30 }, windows = { max = 3651 }",
    ));
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].key.as_deref(),
        Some("controls.os_patch_age_days.required.windows")
    );
    assert_eq!(errors[0].line, None);
}

#[test]
fn an_error_with_a_line_only_keeps_its_line() {
    let text = format!("{MANIFEST}\nbroken = \n");
    let errors = check_draft(&text);
    let line = text.lines().position(|row| row == "broken = ").unwrap() + 1;
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].line, Some(line));
}

#[test]
fn a_builtin_this_client_cannot_run_is_one_error_without_a_key() {
    let draft = replaced(
        "check = \"builtin:firewall@1\"",
        "check = \"builtin:firewall@2\"",
    );
    assert_eq!(
        check_draft(&draft),
        [CheckError {
            message: "this client does not implement firewall (builtin:firewall@2)".into(),
            line: None,
            key: None,
        }]
    );
}
