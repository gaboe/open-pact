//! What the form keeps of the manifest rules: it shows the CLI's errors per field, holds the text
//! it cannot read, and summarizes edits. The rules themselves run in the open-pact CLI.
use runner::admin::CheckError;
use runner::manifest::{self, Field, Form, ManifestCheck, Os, Pending};

const MANIFEST: &str = include_str!("../../../tests/fixtures/manifest.toml");

fn replaced(from: &str, to: &str) -> String {
    assert!(MANIFEST.contains(from), "the fixture has no {from}");
    MANIFEST.replace(from, to)
}

fn requirement(id: &str, os: Os) -> Field {
    Field::Requirement(id.to_owned(), os)
}

fn error(message: &str, key: Option<&str>, line: Option<usize>) -> CheckError {
    CheckError {
        message: message.into(),
        line,
        key: key.map(str::to_owned),
    }
}

#[test]
fn a_time_check_offers_no_time_and_no_unknown() {
    let form = Form::parse(MANIFEST).unwrap();
    let cleared = form.control("log_cleared").unwrap();
    assert_eq!(cleared.output.choices(), ["null", "n/a"]);
    assert!(cleared.output.values().contains(&"time".to_owned()));
    let lock = form.control("screen_lock").unwrap();
    assert_eq!(lock.output.choices(), lock.output.values());
    let patch = form.control("os_patch_age_days").unwrap();
    assert!(patch.output.choices().is_empty());
    assert_eq!(
        manifest::value_label("log_cleared", "null", true),
        "Never cleared"
    );
}

#[test]
fn a_field_names_its_place_in_words() {
    let form = Form::parse(MANIFEST).unwrap();
    assert_eq!(Field::VpnInterval.label(&form), "VPN: send every");
    assert_eq!(
        requirement("screen_lock", Os::Windows).label(&form),
        "Screen lock: Windows"
    );
    assert_eq!(
        Field::Grace("firewall".into()).label(&form),
        "Firewall: time to fix"
    );
}

#[test]
fn an_error_in_one_field_survives_an_edit_of_another() {
    let mut pending = Pending::default();
    assert!(pending.is_empty());
    pending.record(Field::ValidFrom, Err("Type the date.".into()));
    pending.record(Field::MaxAge, Ok(()));
    pending.record(Field::Retention, Err("Type a whole number.".into()));
    assert_eq!(pending.get(&Field::ValidFrom), Some("Type the date."));
    assert_eq!(pending.get(&Field::Retention), Some("Type a whole number."));
    assert_eq!(pending.get(&Field::MaxAge), None);
    pending.record(Field::Retention, Ok(()));
    assert_eq!(pending.get(&Field::ValidFrom), Some("Type the date."));
    assert!(!pending.is_empty());
    pending.record(Field::ValidFrom, Ok(()));
    assert!(pending.is_empty());
}

#[test]
fn one_field_keeps_one_error_that_the_newest_input_replaces() {
    let mut pending = Pending::default();
    pending.record(Field::VpnInterval, Err("first".into()));
    pending.record(Field::VpnInterval, Err("second".into()));
    assert_eq!(pending.get(&Field::VpnInterval), Some("second"));
    assert_eq!(pending.errors().len(), 1);
}

#[test]
fn panel_errors_follow_a_renamed_check_and_drop_with_the_panel() {
    let mut pending = Pending::default();
    pending.record(Field::ValidFrom, Err("date".into()));
    pending.record(Field::Grace("old".into()), Err("grace".into()));
    pending.record(requirement("old", Os::Linux), Err("number".into()));
    pending.rename_control("old", "new");
    assert_eq!(pending.get(&Field::Grace("new".into())), Some("grace"));
    assert_eq!(pending.get(&requirement("new", Os::Linux)), Some("number"));
    assert_eq!(pending.get(&Field::Grace("old".into())), None);
    pending.drop_panel();
    assert_eq!(pending.get(&Field::ValidFrom), Some("date"));
    assert_eq!(pending.errors().len(), 1);
}

#[test]
fn the_change_list_names_edits_the_form_does_not_model() {
    let text = replaced(
        "issuer = \"Example Company, IT security\"",
        "issuer = \"Example Company, Security\"",
    )
    .replace(
        "check = \"builtin:firewall@1\"\noutput = [\"on\", \"off\", \"unknown\"]",
        "check = \"builtin:firewall@1\"\noutput = [\"on\", \"off\"]",
    );
    assert_eq!(
        manifest::changes_between(MANIFEST, &text),
        [
            "Issuer: Example Company, IT security → Example Company, Security",
            "Other edits in TOML: firewall.output"
        ]
    );
}

#[test]
fn every_kind_of_unmodelled_edit_is_named() {
    let edits = |text: &str| manifest::changes_between(MANIFEST, text);
    assert_eq!(
        edits(&replaced(
            "checkpoint_max_age = \"1h\"",
            "checkpoint_max_age = \"2h\""
        )),
        ["Other edits in TOML: log"]
    );
    assert_eq!(
        edits(&replaced("builtin:firewall@1", "builtin:firewall@2")),
        ["Other edits in TOML: firewall.check"]
    );
    assert_eq!(
        edits(&replaced(
            "remotes = [\"github.com/example-org/\"]\noutput = { integer = { min = 0, max = 2147483647 } }\nrequired = { macos = { max = 0 }",
            "remotes = [\"github.com/other-org/\"]\noutput = { integer = { min = 0, max = 2147483647 } }\nrequired = { macos = { max = 0 }"
        )),
        ["Other edits in TOML: managed_repos_outside.remotes"]
    );
    assert_eq!(
        edits(&replaced("manifest_version = 1", "manifest_version = 2")),
        ["Other edits in TOML: manifest_version"]
    );
    let two = replaced("manifest_version = 1", "manifest_version = 2")
        .replace("checkpoint_max_age = \"1h\"", "checkpoint_max_age = \"2h\"");
    assert_eq!(edits(&two), ["Other edits in TOML: log, manifest_version"]);
}

#[test]
fn modelled_edits_alone_add_no_other_edits_line() {
    let text = replaced("min_trust_level = \"L0\"", "min_trust_level = \"L1\"");
    assert_eq!(
        manifest::changes_between(MANIFEST, &text),
        ["Device key at least: L0 software → L1 hardware"]
    );
    assert!(manifest::changes_between(MANIFEST, MANIFEST).is_empty());
}

#[test]
fn comments_alone_are_a_change() {
    let text = replaced(
        "# Example manifest. Fictional.",
        "# Example manifest. Fictional, changed.",
    );
    assert_eq!(
        manifest::changes_between(MANIFEST, &text),
        ["Comments changed in TOML"]
    );
}

#[test]
fn a_comment_edit_next_to_a_field_edit_is_still_listed() {
    let text = replaced(
        "issuer = \"Example Company, IT security\"",
        "issuer = \"Example Company, Security\"",
    )
    .replace(
        "# Example manifest. Fictional.",
        "# Example manifest. Fictional, revised.",
    );
    assert_eq!(
        manifest::changes_between(MANIFEST, &text),
        [
            "Issuer: Example Company, IT security → Example Company, Security",
            "Comments changed in TOML"
        ]
    );
}

#[test]
fn a_hash_inside_a_string_is_no_comment() {
    let before = "issuer = \"A # B\"\nvalid_from = \"2026-10-01\" # from\n";
    let after = "issuer = \"A # C\"\nvalid_from = \"2026-10-01\" # from\n";
    assert_eq!(
        manifest::changes_between(before, after),
        ["Issuer: A # B → A # C"]
    );
    let note = "issuer = '''a # b'''\nvalid_from = \"2026-10-01\"\n";
    assert_eq!(manifest::changes_between(note, note), Vec::<String>::new());
}

#[test]
fn spacing_alone_is_a_layout_change() {
    let text = format!("{MANIFEST}\n\n");
    assert_eq!(
        manifest::changes_between(MANIFEST, &text),
        ["Layout changed in TOML"]
    );
}

#[test]
fn a_text_that_does_not_parse_is_one_change() {
    assert_eq!(
        manifest::changes_between(MANIFEST, "issuer = \""),
        ["The TOML text changed"]
    );
}

#[test]
fn a_cli_key_names_the_form_field_it_belongs_to() {
    for (key, field) in [
        ("issuer", Field::Issuer),
        ("valid_from", Field::ValidFrom),
        ("min_trust_level", Field::Trust),
        ("unknown_grace", Field::UnknownGrace),
        ("claim_max_age", Field::MaxAge),
        ("schedule.vpn.interval", Field::VpnInterval),
        ("schedule.vpn.probe", Field::VpnProbe),
        ("schedule.vpn.probe_name", Field::VpnProbeName),
        ("schedule.vpn.check", Field::VpnCheck),
        ("schedule.always.interval", Field::AlwaysInterval),
        ("schedule.vpn_probe", Field::VpnProbe),
        ("schedule.vpn_probe_name", Field::VpnProbeName),
        ("controls.firewall.check", Field::Id("firewall".into())),
        (
            "controls.os_patch_age_days.required.windows",
            requirement("os_patch_age_days", Os::Windows),
        ),
    ] {
        assert_eq!(manifest::field_of(key), Some(field), "{key}");
    }
    for key in [
        "log.witness_quorum",
        "controls.firewall.output",
        "controls.firewall.remotes",
        "controls.firewall.required.beos",
        "controls.firewall",
        "disclosed_metadata",
        "",
    ] {
        assert_eq!(manifest::field_of(key), None, "{key}");
    }
}

#[test]
fn an_error_with_a_key_sits_under_its_field_and_one_without_is_listed() {
    let mut pending = Pending::default();
    pending.record(Field::ValidFrom, Err("Type the date.".into()));
    let keyed = error("interval is too short", Some("schedule.vpn.interval"), None);
    let loose = error("duplicate id", None, Some(4));
    let all = manifest::problems(&pending, &[keyed.clone(), loose.clone()]);
    assert_eq!(
        all.fields
            .iter()
            .map(|problem| (problem.field.clone(), problem.message.as_str()))
            .collect::<Vec<_>>(),
        [
            (Field::ValidFrom, "Type the date."),
            (Field::VpnInterval, "interval is too short")
        ]
    );
    assert_eq!(all.listed, [loose]);
    assert_eq!(all.len(), 3);
    let form = Form::parse(MANIFEST).unwrap();
    assert_eq!(
        all.first(&form).as_deref(),
        Some("Valid from: Type the date.")
    );
    assert_eq!(
        manifest::problems(&Pending::default(), &[error("duplicate id", None, Some(4))])
            .first(&form)
            .as_deref(),
        Some("Line 4: duplicate id")
    );
    assert!(manifest::problems(&Pending::default(), &[]).is_empty());
}

#[test]
fn a_reply_to_an_older_draft_is_dropped() {
    let mut check = ManifestCheck::default();
    assert_eq!(check.result("a"), None, "nothing was asked yet");
    let first = check.begin();
    let second = check.begin();
    let slow = vec![error("old", None, None)];
    assert!(!check.finish(first, "a", Ok(slow)), "stale reply");
    assert_eq!(check.result("a"), None);
    assert!(check.finish(second, "b", Ok(Vec::new())));
    assert_eq!(check.result("b"), Some(Vec::new()));
    assert_eq!(
        check.result("a"),
        None,
        "an answer belongs to its own draft"
    );
    assert_eq!(
        check.result("b "),
        None,
        "a draft edited since has no answer"
    );
}

#[test]
fn a_cli_that_did_not_answer_stops_the_review_with_one_error() {
    let mut check = ManifestCheck::default();
    let generation = check.begin();
    check.finish(
        generation,
        "a",
        Err("open-pact-client was not found.".into()),
    );
    let errors = check.result("a").unwrap();
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0]
            .message
            .contains("open-pact-client was not found.")
    );
}

#[test]
fn each_os_shows_its_own_operator_and_mixed_ones_share_no_direction() {
    let mixed = Form::parse(&replaced(
        "required = { macos = { max = 30 }, windows = { max = 30 }, linux = { max = 30 } }",
        "required = { macos = { max = 90 }, windows = { min = 30 } }",
    ))
    .unwrap();
    let uptime = mixed.control("os_patch_age_days").unwrap();
    assert!(uptime.mixed_limits());
    assert_eq!(uptime.limit_symbol(Os::Macos), "≤");
    assert_eq!(uptime.limit_symbol(Os::Windows), "≥");
    let same = Form::parse(MANIFEST).unwrap();
    let patch = same.control("os_patch_age_days").unwrap();
    assert!(!patch.mixed_limits());
    assert_eq!(patch.limit_symbol(Os::Linux), "≤");
}

#[test]
fn text_the_panel_cannot_read_blocks_a_switch_and_text_of_the_form_does_not() {
    let form = Form::parse(MANIFEST).unwrap();
    let mut pending = Pending::default();
    assert_eq!(pending.panel_blocks(&form), None);
    pending.record(Field::ValidFrom, Err("date".into()));
    assert_eq!(pending.panel_blocks(&form), None);
    pending.record(
        requirement("os_patch_age_days", Os::Windows),
        Err("number".into()),
    );
    let note = pending.panel_blocks(&form).unwrap();
    assert!(note.contains("Windows"), "{note}");
    assert_eq!(
        pending.get(&requirement("os_patch_age_days", Os::Windows)),
        Some("number")
    );
}

#[test]
fn a_new_question_hides_the_answer_to_the_older_one() {
    let mut check = ManifestCheck::default();
    let first = check.begin();
    assert!(check.finish(first, "A", Ok(Vec::new())));
    assert_eq!(check.result("A"), Some(Vec::new()));
    let second = check.begin();
    assert_eq!(check.result("A"), None, "the question about A is pending");
    assert!(check.finish(second, "A", Err("refused".into())));
    assert_eq!(check.result("A").map(|errors| errors.len()), Some(1));
}

#[test]
fn a_comment_after_a_multiline_string_closed_by_extra_quotes_is_seen() {
    let before = replaced(
        "rationale = \"Lock the screen when you walk away, so nobody can read client data on an open laptop.\"",
        "rationale = \"\"\"A quote: \"\"\"\" # old note",
    );
    let after = before.replace("# old note", "# new note");
    assert_eq!(
        manifest::changes_between(&before, &after),
        ["Comments changed in TOML"]
    );
}
