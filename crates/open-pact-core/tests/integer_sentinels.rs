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
fn screen_lock_in_minutes_is_an_integer_output_with_none_compared_to_a_maximum() {
    // builtin:screen_lock@2 needs no code in core: the manifest declares its output, and an
    // integer output with the sentinel "none" is compared to a maximum like os_patch_age_days.
    let text = DEMO.replacen(
        "check = \"builtin:screen_lock@1\"\noutput = [\"le_5min\", \"le_15min\", \"gt_15min\", \"none\", \"unknown\"]\nrequired = { macos = \"le_5min\", windows = \"le_5min\", linux = \"le_5min\" }",
        "check = \"builtin:screen_lock@2\"\noutput = { integer = { min = 0, max = 1440 }, values = [\"none\"] }\nrequired = { macos = { max = 5 }, windows = { max = 5 }, linux = { max = 10 } }",
        1,
    );
    assert_ne!(text, DEMO);
    let m = parse(&text);
    let control = m.body().control("screen_lock").unwrap();
    for value in [
        0.into(),
        5.into(),
        1440.into(),
        "none".into(),
        "unknown".into(),
    ] {
        assert!(control.output.contains(&value), "{value}");
    }
    for value in [(-1).into(), 1441.into(), "off".into(), "le_5min".into()] {
        assert!(!control.output.contains(&value), "{value}");
    }
    let linux = &control.required[&Os::Linux];
    for value in [0.into(), 10.into()] {
        assert!(linux.contains(&value), "{value}");
    }
    for value in [11.into(), "none".into(), "unknown".into()] {
        assert!(!linux.contains(&value), "{value}");
    }
    assert!(control.required[&Os::Macos].contains(&5.into()));
    assert!(!control.required[&Os::Macos].contains(&6.into()));
    // A maximum beyond the output's range is not a requirement the control can report.
    assert!(
        Manifest::parse(
            text.replace("linux = { max = 10 }", "linux = { max = 1441 }")
                .as_bytes()
        )
        .is_err()
    );
    // Moving from the buckets of screen_lock@1 to minutes changes the check and the output kind,
    // so the owner has to agree to it.
    assert!(is_narrowing(&parse(DEMO), &m).is_err());
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
