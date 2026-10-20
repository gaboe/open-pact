use open_pact_core::{
    Claim, ControlValue, Decision, FirstFailures, Manifest, Os, Pseudonym, PublicKey, TrustLevel,
    Violation, dev_key, evaluate, is_narrowing, sign_claim, verify_claim,
};

const DEMO: &str = include_str!("../../../examples/manifest.toml");

fn manifest(text: &str) -> Manifest {
    Manifest::parse(text.as_bytes()).unwrap()
}

fn claim(m: &Manifest, value: ControlValue) -> Claim {
    let key = dev_key::generate();
    let device_key = PublicKey::from(&key);
    Claim {
        manifest: m.hash().clone(),
        device: Pseudonym::of(&device_key),
        device_key,
        nonce: "fictional-nonce".into(),
        time: "2026-10-12T09:00:00Z".parse().unwrap(),
        client: "open-pact-client 0.2.0".into(),
        os: Os::Linux,
        trust_level: TrustLevel::L0,
        virtualized: None,
        csr_sha256: None,
        log_checkpoint: None,
        results: [
            ("disk_encryption", "full".into()),
            ("firewall", "on".into()),
            ("screen_lock", "le_5min".into()),
            ("os_supported", "yes".into()),
            ("os_patch_age_days", value),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect(),
    }
}

#[test]
fn integer_claim_signs_and_verifies_as_a_json_number() {
    let m = manifest(DEMO);
    let key = dev_key::generate();
    let mut c = claim(&m, 30.into());
    c.device_key = PublicKey::from(&key);
    c.device = Pseudonym::of(&c.device_key);
    let json = String::from_utf8(c.canonical_json()).unwrap();
    assert!(json.contains("\"os_patch_age_days\":30"));
    let verified = verify_claim(&sign_claim(&c, &key).unwrap()).unwrap();
    assert_eq!(verified.claim(), &c);
    assert_eq!(
        evaluate(&m, verified.claim(), c.time, &FirstFailures::new()).decision,
        Decision::Allow { warnings: vec![] }
    );
}

#[test]
fn integer_limits_and_unknown_use_existing_grace_rules() {
    let m = manifest(DEMO);
    for n in [0, 30] {
        let c = claim(&m, n.into());
        assert_eq!(
            evaluate(&m, &c, c.time, &FirstFailures::new()).decision,
            Decision::Allow { warnings: vec![] }
        );
    }
    for value in [31.into(), 3650.into(), "unknown".into()] {
        let c = claim(&m, value);
        let e = evaluate(&m, &c, c.time, &FirstFailures::new());
        assert!(matches!(e.decision, Decision::Allow { warnings } if warnings.len() == 1));
        let later = c.time + chrono::TimeDelta::days(8);
        let mut c = c;
        c.time = later;
        assert!(matches!(
            evaluate(&m, &c, later, &e.first_failures).decision,
            Decision::Deny { .. }
        ));
    }
}

#[test]
fn outside_disclosure_range_and_wrong_kinds_are_refused() {
    let m = manifest(DEMO);
    for value in [(-1).into(), 3651.into(), "30".into(), "other".into()] {
        let c = claim(&m, value);
        let e = evaluate(&m, &c, c.time, &FirstFailures::new());
        assert!(
            matches!(e.decision, Decision::Deny { reasons } if reasons.iter().any(|r| r.breaks_disclosure_contract()))
        );
        assert!(e.first_failures.is_empty());
    }
    for raw in [
        "1.5",
        "true",
        "null",
        "[]",
        "{}",
        "2147483648",
        "-2147483649",
    ] {
        assert!(serde_json::from_str::<ControlValue>(raw).is_err(), "{raw}");
    }
}

#[test]
fn integer_output_and_requirement_shapes_are_closed() {
    for (from, to) in [
        ("min = 0, max = 3650", "min = 3651, max = 3650"),
        ("min = 0, max = 3650", "min = 0"),
        ("min = 0, max = 3650", "max = 3650"),
        ("min = 0, max = 3650", "min = 0, max = 3650, extra = 1"),
        ("{ max = 30 }", "{ max = 30, min = 0 }"),
        ("{ max = 30 }", "{ max = 3651 }"),
        ("{ max = 30 }", "\"unknown\""),
    ] {
        assert!(
            Manifest::parse(DEMO.replace(from, to).as_bytes()).is_err(),
            "{to}"
        );
    }
}

#[test]
fn narrowing_rejects_wider_ranges_and_stricter_limits() {
    let old = manifest(DEMO);
    for (from, to, allowed) in [
        ("min = 0, max = 3650", "min = 1, max = 3650", true),
        ("min = 0, max = 3650", "min = 0, max = 365", true),
        ("min = 0, max = 3650", "min = -1, max = 3650", false),
        ("min = 0, max = 3650", "min = 0, max = 3651", false),
        ("{ max = 30 }", "{ max = 31 }", true),
        ("{ max = 30 }", "{ max = 29 }", false),
        ("{ max = 30 }", "{ min = 30 }", false),
    ] {
        let new = manifest(&DEMO.replace(from, to));
        assert_eq!(is_narrowing(&old, &new).is_ok(), allowed, "{to}");
        assert_ne!(old.hash(), new.hash());
    }
    let min = DEMO.replace("{ max = 30 }", "{ min = 30 }");
    let old = manifest(&min);
    assert!(
        is_narrowing(
            &old,
            &manifest(&min.replace("{ min = 30 }", "{ min = 29 }"))
        )
        .is_ok()
    );
    assert!(
        matches!(is_narrowing(&old,&manifest(&min.replace("{ min = 30 }","{ min = 31 }"))), Err(v) if v.iter().all(|v| matches!(v, Violation::RequiredStricter { .. })))
    );
    let m = manifest(&min);
    for (n, passes) in [(29, false), (30, true), (31, true)] {
        let c = claim(&m, n.into());
        let e = evaluate(&m, &c, c.time, &FirstFailures::new());
        assert!(
            matches!(e.decision, Decision::Allow { warnings } if warnings.is_empty() == passes)
        );
    }
}

#[test]
fn declared_not_applicable_is_evaluated_as_an_ordinary_value() {
    let text = DEMO
        .replace(
            "output = [\"yes\", \"no\"]",
            "output = [\"yes\", \"no\", \"n/a\"]",
        )
        .replace(
            "required = { macos = \"yes\", windows = \"yes\", linux = \"yes\" }",
            "required = { macos = \"yes\", windows = \"yes\", linux = \"n/a\" }",
        );
    let m = manifest(&text);
    let mut c = claim(&m, 14.into());
    c.results.insert("os_supported".into(), "n/a".into());
    assert_eq!(
        evaluate(&m, &c, c.time, &FirstFailures::new()).decision,
        Decision::Allow { warnings: vec![] }
    );
    c.os = Os::Macos;
    assert!(
        matches!(evaluate(&m, &c, c.time, &FirstFailures::new()).decision,
        Decision::Allow { warnings } if warnings.len() == 1)
    );
    let plain = manifest(DEMO);
    c.manifest = plain.hash().clone();
    assert!(
        matches!(evaluate(&plain, &c, c.time, &FirstFailures::new()).decision,
        Decision::Deny { reasons } if reasons.iter().any(|r| r.breaks_disclosure_contract()))
    );
}

#[test]
fn screen_lock_none_replaces_off() {
    let m = manifest(DEMO);
    let mut c = claim(&m, 14.into());
    c.results.insert("screen_lock".into(), "none".into());
    assert!(
        matches!(evaluate(&m, &c, c.time, &FirstFailures::new()).decision,
        Decision::Allow { warnings } if warnings.len() == 1)
    );
    c.results.insert("screen_lock".into(), "off".into());
    assert!(
        matches!(evaluate(&m, &c, c.time, &FirstFailures::new()).decision,
        Decision::Deny { reasons } if reasons.iter().any(|r| r.breaks_disclosure_contract()))
    );
}
