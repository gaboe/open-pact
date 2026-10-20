use open_pact_core::{ControlValue, Manifest, Os, is_narrowing};

const DEMO: &str = include_str!("../../../examples/manifest.toml");

fn parse(s: &str) -> Manifest {
    Manifest::parse(s.as_bytes()).unwrap()
}

#[test]
fn integer_sentinels_are_declared_closed_and_typed() {
    let m = parse(DEMO);
    let output = &m
        .body()
        .control("antimalware_full_scan_age_days")
        .unwrap()
        .output;
    for value in [0.into(), 3650.into(), "n/a".into(), "unknown".into()] {
        assert!(output.contains(&value));
    }
    for value in [
        (-1).into(),
        3651.into(),
        "none".into(),
        "0".into(),
        "free text".into(),
    ] {
        assert!(!output.contains(&value));
    }
    for values in [r#"["n/a", "n/a"]"#, r#"["unknown"]"#, r#"["arbitrary"]"#] {
        let text = DEMO.replacen(r#"values = ["n/a"]"#, &format!("values = {values}"), 1);
        assert!(Manifest::parse(text.as_bytes()).is_err(), "{values}");
    }
}

#[test]
fn integer_sentinels_can_be_required_without_bypassing_limits() {
    let text = DEMO.replacen("output = { integer = { min = 0, max = 3650 }, values = [\"n/a\"] }\nrequired = {}", "output = { integer = { min = 0, max = 3650 }, values = [\"n/a\"] }\nrequired = { macos = \"n/a\", linux = { max = 3 } }", 1);
    let m = parse(&text);
    let control = m.body().control("antimalware_full_scan_age_days").unwrap();
    assert!(control.required[&Os::Macos].contains(&"n/a".into()));
    assert!(!control.required[&Os::Macos].contains(&0.into()));
    assert!(!control.required[&Os::Linux].contains(&"n/a".into()));
    assert!(control.required[&Os::Linux].contains(&3.into()));
    assert!(!control.required[&Os::Linux].contains(&4.into()));
    assert!(
        Manifest::parse(
            text.replace("macos = \"n/a\"", "macos = \"none\"")
                .as_bytes()
        )
        .is_err()
    );
}

#[test]
fn adding_a_sentinel_expands_disclosure_and_needs_consent() {
    let full = parse(DEMO);
    let fewer = parse(&DEMO.replacen(r#"values = ["n/a"]"#, "values = []", 1));
    assert!(is_narrowing(&full, &fewer).is_ok());
    assert!(is_narrowing(&fewer, &full).is_err());
    let json = serde_json::to_string(
        &full
            .body()
            .control("antimalware_full_scan_age_days")
            .unwrap()
            .output,
    )
    .unwrap();
    assert!(json.contains(r#""values":["n/a"]"#));
    assert_eq!(
        serde_json::from_str::<ControlValue>("42").unwrap(),
        ControlValue::Integer(42)
    );
}
