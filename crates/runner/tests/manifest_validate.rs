//! The form refuses what the gateway or a client would refuse, and says so per field.
use runner::manifest::{self, Field, FieldError, Form, Os, Pending};

const MANIFEST: &str = include_str!("../../../tests/fixtures/manifest.toml");
const MANIFEST_V2: &str = include_str!("../../../tests/fixtures/manifest-v2.toml");

fn replaced(from: &str, to: &str) -> String {
    assert!(MANIFEST.contains(from), "the fixture has no {from}");
    MANIFEST.replace(from, to)
}

fn problems(text: &str) -> Vec<FieldError> {
    manifest::validate(&Form::parse(text).unwrap())
}

fn message(text: &str, field: &Field) -> Option<String> {
    problems(text)
        .into_iter()
        .find(|problem| problem.field == *field)
        .map(|problem| problem.message)
}

fn refused(text: &str, field: &Field) {
    assert!(
        message(text, field).is_some(),
        "{field:?} is not refused in\n{text}"
    );
}

fn accepted(text: &str) {
    assert_eq!(problems(text), [], "\n{text}");
}

fn requirement(id: &str, os: Os) -> Field {
    Field::Requirement(id.to_owned(), os)
}

#[test]
fn the_fixture_manifests_have_no_problem() {
    accepted(MANIFEST);
    accepted(MANIFEST_V2);
}

#[test]
fn the_sending_interval_runs_from_5_minutes_to_24_hours() {
    for good in ["5m", "55m", "1440m", "1h", "24h"] {
        accepted(&replaced(
            "interval = \"55m\"",
            &format!("interval = \"{good}\""),
        ));
    }
    for bad in [
        "4m",
        "0m",
        "1441m",
        "25h",
        "1d",
        "55",
        "",
        "055m",
        "m",
        "+5m",
        "99999999999h",
    ] {
        refused(
            &replaced("interval = \"55m\"", &format!("interval = \"{bad}\"")),
            &Field::Interval,
        );
    }
}

#[test]
fn unknown_is_allowed_for_more_than_zero() {
    refused(
        &replaced("unknown_grace = \"7d\"", "unknown_grace = \"0d\""),
        &Field::UnknownGrace,
    );
    accepted(&replaced(
        "unknown_grace = \"7d\"",
        "unknown_grace = \"1h\"",
    ));
}

#[test]
fn a_zero_time_to_fix_is_valid_because_it_denies_at_once() {
    let form = Form::parse(MANIFEST).unwrap();
    assert_eq!(form.controls[0].grace, "0d");
    accepted(MANIFEST);
}

#[test]
fn every_duration_ends_in_hours_days_weeks_or_months() {
    refused(
        &replaced("claim_max_age = \"24h\"", "claim_max_age = \"5m\""),
        &Field::MaxAge,
    );
    refused(
        &replaced("claim_retention = \"1mo\"", "claim_retention = \"\""),
        &Field::Retention,
    );
    refused(
        &replaced(
            "claim_max_age = \"24h\"",
            "claim_max_age = \"99999999999999h\"",
        ),
        &Field::MaxAge,
    );
    refused(
        &replaced(
            "check = \"builtin:firewall@1\"\noutput = [\"on\", \"off\", \"unknown\"]\nrequired = { macos = \"on\", windows = \"on\", linux = \"on\" }\ngrace = \"1d\"",
            "check = \"builtin:firewall@1\"\noutput = [\"on\", \"off\", \"unknown\"]\nrequired = { macos = \"on\", windows = \"on\", linux = \"on\" }\ngrace = \"soon\"",
        ),
        &Field::Grace("firewall".into()),
    );
}

#[test]
fn a_number_requirement_stays_inside_the_output_range() {
    let patch = |bound: &str| {
        replaced(
            "required = { macos = { max = 30 }, windows = { max = 30 }, linux = { max = 30 } }",
            &format!(
                "required = {{ macos = {{ max = 30 }}, windows = {{ max = {bound} }}, linux = {{ max = 30 }} }}"
            ),
        )
    };
    let field = requirement("os_patch_age_days", Os::Windows);
    accepted(&patch("0"));
    accepted(&patch("3650"));
    refused(&patch("-1"), &field);
    refused(&patch("3651"), &field);
    let narrow = replaced(
        "output = { integer = { min = 0, max = 3650 } }\nrequired = { macos = { max = 30 }",
        "output = { integer = { min = 10, max = 100 } }\nrequired = { macos = { max = 30 }",
    );
    accepted(&narrow);
    refused(
        &narrow.replace("macos = { max = 30 }", "macos = { max = 101 }"),
        &requirement("os_patch_age_days", Os::Macos),
    );
    refused(
        &narrow.replace("macos = { max = 30 }", "macos = { min = 9 }"),
        &requirement("os_patch_age_days", Os::Macos),
    );
}

#[test]
fn an_unreadable_output_limits_a_number_to_32_bits() {
    let unreadable = replaced(
        "output = { integer = { min = 0, max = 3650 } }\nrequired = { macos = { max = 30 }",
        "output = \"unreadable\"\nrequired = { macos = { max = 30 }",
    );
    let field = requirement("os_patch_age_days", Os::Macos);
    accepted(&unreadable.replace("macos = { max = 30 }", "macos = { max = 2147483647 }"));
    refused(
        &unreadable.replace("macos = { max = 30 }", "macos = { max = 2147483648 }"),
        &field,
    );
    refused(
        &unreadable.replace("macos = { max = 30 }", "macos = { min = -2147483649 }"),
        &field,
    );
}

#[test]
fn a_number_needs_a_check_that_reports_numbers() {
    refused(
        &replaced(
            "required = { macos = \"on\", windows = \"on\", linux = \"on\" }\ngrace = \"1d\"\n\n[[control]]\nid = \"screen_lock\"",
            "required = { macos = { max = 1 }, windows = \"on\", linux = \"on\" }\ngrace = \"1d\"\n\n[[control]]\nid = \"screen_lock\"",
        ),
        &requirement("firewall", Os::Macos),
    );
}

#[test]
fn a_choice_requirement_names_a_result_of_the_check() {
    let lock = |value: &str| replaced("windows = \"le_5min\"", &format!("windows = {value}"));
    let field = requirement("screen_lock", Os::Windows);
    accepted(&lock("\"le_15min\""));
    accepted(&lock("[\"le_5min\", \"le_15min\"]"));
    refused(&lock("\"banana\""), &field);
    refused(&lock("[\"le_5min\", \"banana\"]"), &field);
    refused(&lock("[]"), &field);
}

#[test]
fn a_time_check_requires_never_cleared_a_sentinel_or_a_utc_time() {
    let cleared = |value: &str| replaced("windows = \"null\"", &format!("windows = \"{value}\""));
    let field = requirement("log_cleared", Os::Windows);
    accepted(&cleared("null"));
    accepted(&cleared("n/a"));
    accepted(&cleared("2026-01-01T00:00:00Z"));
    for bad in ["time", "unknown", "2026-01-01T00:00:00+01:00", "yesterday"] {
        refused(&cleared(bad), &field);
    }
    let not_nullable = replaced("nullable = true, ", "");
    refused(&not_nullable, &field);
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
fn only_the_company_vpn_needs_a_probe_address() {
    let always = manifest::set_send_mode(MANIFEST, "always").unwrap();
    accepted(&always);
    let vpn = manifest::set_send_mode(&always, "vpn").unwrap();
    assert!(vpn.contains("vpn_probe = \"\""));
    refused(&vpn, &Field::VpnProbe);
    for good in ["10.0.0.2:443", "vpn.example.org:443", "[::1]:443"] {
        accepted(&manifest::set_schedule(&vpn, "vpn_probe", good).unwrap());
    }
    for bad in [
        "10.0.0.2",
        "10.0.0.2:0",
        "10.0.0.2:70000",
        "::1:443",
        "vpn..example.org:443",
        ":443",
        "host:",
    ] {
        refused(
            &manifest::set_schedule(&vpn, "vpn_probe", bad).unwrap(),
            &Field::VpnProbe,
        );
    }
}

#[test]
fn the_probe_name_is_a_dns_name() {
    for good in ["vpn.example.org", ""] {
        accepted(&manifest::set_schedule(MANIFEST, "vpn_probe_name", good).unwrap());
    }
    for bad in ["10.0.0.1", "vpn.example.org.", "vpn example.org"] {
        refused(
            &manifest::set_schedule(MANIFEST, "vpn_probe_name", bad).unwrap(),
            &Field::VpnProbeName,
        );
    }
}

#[test]
fn always_takes_no_probe_and_the_mode_is_known() {
    refused(
        &replaced("mode = \"vpn\"", "mode = \"always\""),
        &Field::Send,
    );
    refused(
        &replaced("mode = \"vpn\"", "mode = \"sometimes\""),
        &Field::Send,
    );
}

#[test]
fn a_built_in_check_runs_only_under_its_own_id_and_version() {
    let id = |name: &str| Field::Id(name.to_owned());
    refused(
        &replaced("id = \"screen_lock\"", "id = \"screen_lock_custom\""),
        &id("screen_lock_custom"),
    );
    refused(
        &replaced("builtin:screen_lock@1", "builtin:screen_lock@2"),
        &id("screen_lock"),
    );
    refused(
        &replaced("builtin:screen_lock@1", "custom:screen_lock"),
        &id("screen_lock"),
    );
    refused(
        &replaced("id = \"screen_lock\"", "id = \"firewall\""),
        &id("firewall"),
    );
}

#[test]
fn a_field_names_its_place_in_words() {
    let form = Form::parse(MANIFEST).unwrap();
    assert_eq!(Field::Interval.label(&form), "Every");
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
    pending.record(Field::Interval, Err("first".into()));
    pending.record(Field::Interval, Err("second".into()));
    assert_eq!(pending.get(&Field::Interval), Some("second"));
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
fn problems_list_unparsed_input_before_the_manifest_problems() {
    let form = Form::parse(&replaced(
        "unknown_grace = \"7d\"",
        "unknown_grace = \"0d\"",
    ))
    .unwrap();
    let mut pending = Pending::default();
    pending.record(Field::ValidFrom, Err("Type the date.".into()));
    let all = manifest::problems(&form, &pending);
    assert_eq!(
        all.iter()
            .map(|problem| problem.field.clone())
            .collect::<Vec<_>>(),
        [Field::ValidFrom, Field::UnknownGrace]
    );
    assert!(manifest::problems(&Form::parse(MANIFEST).unwrap(), &Pending::default()).is_empty());
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
fn comments_and_layout_alone_are_still_an_edit() {
    let text = replaced(
        "# Example manifest. Fictional.",
        "# Example manifest. Fictional, changed.",
    );
    assert_eq!(
        manifest::changes_between(MANIFEST, &text),
        ["Other edits in TOML: comments or layout"]
    );
}

#[test]
fn a_text_that_does_not_parse_is_one_change() {
    assert_eq!(
        manifest::changes_between(MANIFEST, "issuer = \""),
        ["The TOML text changed"]
    );
}
