//! Edits of the Form view that must keep the text and the meaning of the manifest.
use runner::manifest::{self, Form, Os, Requirement};

const MANIFEST: &str = include_str!("../../../tests/fixtures/manifest.toml");

fn form(text: &str) -> Form {
    Form::parse(text).unwrap()
}

fn replaced(from: &str, to: &str) -> String {
    assert!(MANIFEST.contains(from), "the fixture has no {from}");
    MANIFEST.replace(from, to)
}

#[test]
fn a_built_in_check_keeps_its_id() {
    let screen_lock = &form(MANIFEST).controls[2];
    assert_eq!(screen_lock.id, "screen_lock");
    assert!(screen_lock.id_locked());
    let error = manifest::set_control_text(MANIFEST, 2, "id", "screen_lock_custom").unwrap_err();
    assert!(error.contains("keeps its ID"), "{error}");
    let text = manifest::set_control_text(MANIFEST, 2, "grace", "2d").unwrap();
    assert_eq!(form(&text).controls[2].grace, "2d");
}

#[test]
fn a_check_that_is_not_built_in_can_be_renamed() {
    let text = replaced(
        "check = \"builtin:firewall@1\"",
        "check = \"custom:firewall\"",
    );
    let control = &form(&text).controls[1];
    assert!(!control.id_locked());
    let renamed = manifest::set_control_text(&text, 1, "id", "firewall_custom").unwrap();
    assert_eq!(form(&renamed).controls[1].id, "firewall_custom");
    assert!(manifest::set_control_text(&text, 1, "id", "screen_lock").is_err());
    assert!(manifest::set_control_text(&text, 1, "id", "").is_err());
}

#[test]
fn an_os_number_keeps_its_own_operator() {
    let text = replaced(
        "check = \"builtin:uptime_days@1\"\noutput = { integer = { min = 0, max = 2147483647 } }\nrequired = {}",
        "check = \"builtin:uptime_days@1\"\noutput = { integer = { min = 0, max = 2147483647 } }\nrequired = { macos = { max = 90 }, windows = { min = 30 } }",
    );
    let form = form(&text);
    let uptime = form.control("uptime_days").unwrap();
    assert_eq!(uptime.requirement(Os::Macos), &Requirement::Max(90));
    assert_eq!(uptime.requirement(Os::Windows), &Requirement::Min(30));
    assert_eq!(uptime.limit(Os::Windows, 31), Requirement::Min(31));
    assert_eq!(uptime.limit(Os::Macos, 91), Requirement::Max(91));
    assert_eq!(uptime.limit(Os::Linux, 5), Requirement::Max(5));
    let index = form
        .controls
        .iter()
        .position(|c| c.id == "uptime_days")
        .unwrap();
    let written =
        manifest::set_requirement(&text, index, Os::Windows, &uptime.limit(Os::Windows, 31))
            .unwrap();
    assert!(written.contains("windows = { min = 31 }"), "{written}");
    assert!(written.contains("macos = { max = 90 }"), "{written}");
}

#[test]
fn a_control_without_a_bound_uses_the_default_of_its_check() {
    let form = form(MANIFEST);
    let password = form.control("password_min_length").unwrap();
    let mut unset = password.clone();
    unset.required = [
        Requirement::Reported,
        Requirement::Reported,
        Requirement::Reported,
    ];
    assert_eq!(unset.limit(Os::Macos, 8), Requirement::Min(8));
    let mut uptime = form.control("uptime_days").unwrap().clone();
    uptime.required = [
        Requirement::Reported,
        Requirement::Reported,
        Requirement::Reported,
    ];
    assert_eq!(uptime.limit(Os::Macos, 8), Requirement::Max(8));
}

const MULTILINE: &str = "manifest_version = 1
claim_recipients = [
    # The company
    \"Company IT security\",
    \"Auditor on request\", # trailing
]
disclosed_metadata = [\"nonce\", \"time\"] # always sent
";

#[test]
fn adding_to_a_list_keeps_the_comments_inside_it() {
    let items: Vec<String> = ["Company IT security", "Auditor on request", "Third"]
        .map(String::from)
        .into();
    let text = manifest::set_top_list(MULTILINE, "claim_recipients", &items).unwrap();
    assert_eq!(
        text,
        "manifest_version = 1
claim_recipients = [
    # The company
    \"Company IT security\",
    \"Auditor on request\", # trailing
    \"Third\",
]
disclosed_metadata = [\"nonce\", \"time\"] # always sent
"
    );
}

#[test]
fn removing_from_a_list_keeps_the_decor_of_the_other_items() {
    let items = vec!["Auditor on request".to_owned()];
    let text = manifest::set_top_list(MULTILINE, "claim_recipients", &items).unwrap();
    assert!(
        text.contains("\"Auditor on request\", # trailing"),
        "{text}"
    );
    assert!(!text.contains("Company IT security"), "{text}");
    assert!(text.contains("disclosed_metadata = [\"nonce\", \"time\"] # always sent"));
    let both = ["Company IT security", "Auditor on request"].map(String::from);
    let kept = manifest::set_top_list(MULTILINE, "claim_recipients", &both).unwrap();
    assert_eq!(kept, MULTILINE);
}

#[test]
fn a_single_line_list_stays_on_one_line_and_keeps_its_comment() {
    let items = ["nonce", "time", "os"].map(String::from);
    let text = manifest::set_top_list(MULTILINE, "disclosed_metadata", &items).unwrap();
    assert!(
        text.contains("disclosed_metadata = [\"nonce\", \"time\", \"os\"] # always sent"),
        "{text}"
    );
    let fewer = vec!["time".to_owned()];
    let text = manifest::set_top_list(MULTILINE, "disclosed_metadata", &fewer).unwrap();
    assert!(
        text.contains("disclosed_metadata = [\"time\"] # always sent"),
        "{text}"
    );
    let missing = manifest::set_top_list("a = 1\n", "claim_recipients", &fewer).unwrap();
    assert!(
        missing.contains("claim_recipients = [\"time\"]"),
        "{missing}"
    );
}
