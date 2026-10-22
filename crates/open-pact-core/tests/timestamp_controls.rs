use open_pact_core::{ControlValue, Manifest, Os, is_narrowing};

const DEMO: &str = include_str!("../../../examples/manifest.toml");
fn parse(text: &str) -> Manifest {
    Manifest::parse(text.as_bytes()).unwrap()
}

#[test]
fn clearing_domain_keeps_timestamp_null_unknown_and_na_distinct() {
    let manifest = parse(DEMO);
    let control = manifest.body().control("log_cleared").unwrap();
    for value in [
        ControlValue::Null,
        "2026-10-22T10:00:00Z".into(),
        "unknown".into(),
        "n/a".into(),
    ] {
        assert!(control.output.contains(&value));
    }
    for value in [
        "null".into(),
        "none".into(),
        "2026-10-22T10:00:00+02:00".into(),
        "2026-99-99T00:00:00Z".into(),
        0.into(),
    ] {
        assert!(!control.output.contains(&value));
    }
    assert!(control.required[&Os::Windows].contains(&ControlValue::Null));
    assert!(!control.required[&Os::Windows].contains(&"2026-10-22T10:00:00Z".into()));
    assert!(!control.required[&Os::Windows].contains(&"unknown".into()));
    let json = serde_json::to_string(&ControlValue::Null).unwrap();
    assert_eq!(json, "null");
    assert_eq!(
        serde_json::from_str::<ControlValue>(&json).unwrap(),
        ControlValue::Null
    );
    assert_eq!(serde_jcs::to_string(&ControlValue::Null).unwrap(), "null");
}

#[test]
fn timestamp_output_changes_need_owner_consent() {
    let full = parse(DEMO);
    let without_na = parse(
        &DEMO
            .replace(
                "timestamp = true, nullable = true, values = [\"n/a\"]",
                "timestamp = true, nullable = true",
            )
            .replace(
                "windows = \"null\", macos = \"n/a\", linux = \"n/a\"",
                "windows = \"null\"",
            ),
    );
    assert!(is_narrowing(&full, &without_na).is_ok());
    assert!(is_narrowing(&without_na, &full).is_err());
    for replacement in [
        "timestamp = false, nullable = true, values = [\"n/a\"]",
        "timestamp = true, nullable = true, values = [\"free text\"]",
        "timestamp = true, nullable = true, values = [\"n/a\", \"n/a\"]",
    ] {
        assert!(
            Manifest::parse(
                DEMO.replace(
                    "timestamp = true, nullable = true, values = [\"n/a\"]",
                    replacement
                )
                .as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn v31_example_declares_exact_fields_and_reported_only_controls() {
    let manifest = parse(DEMO);
    let mut ids: Vec<_> = manifest
        .body()
        .controls
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    ids.sort_unstable();
    let mut expected = vec![
        "disk_encryption",
        "preboot_auth",
        "os_supported",
        "os_patch_age_days",
        "os_auto_updates",
        "screen_lock",
        "firewall",
        "antimalware_active",
        "antimalware_realtime",
        "antimalware_signature_age_days",
        "antimalware_active_threats",
        "antimalware_full_scan_age_days",
        "web_protection",
        "log_oldest_record_days",
        "process_audit",
        "powershell_logging",
        "log_cleared",
        "work_account",
        "uptime_days",
    ];
    expected.sort_unstable();
    assert_eq!(ids, expected);
    for id in [
        "antimalware_full_scan_age_days",
        "web_protection",
        "work_account",
        "uptime_days",
    ] {
        assert!(manifest.body().control(id).unwrap().required.is_empty());
    }
}

#[test]
fn signed_null_claim_passes_but_a_clearing_time_does_not() {
    use open_pact_core::{
        Claim, Decision, FirstFailures, Pseudonym, PublicKey, TrustLevel, dev_key, evaluate,
        sign_claim, verify_claim,
    };
    let mut fixture: toml::Value = toml::from_str(DEMO).unwrap();
    fixture["control"]
        .as_array_mut()
        .unwrap()
        .retain(|c| c["id"].as_str() == Some("log_cleared"));
    fixture["control"][0]["grace"] = "0d".into();
    let manifest = parse(&toml::to_string(&fixture).unwrap());
    let key = dev_key::generate();
    let device_key = PublicKey::from(&key);
    let mut claim = Claim {
        manifest: manifest.hash().clone(),
        device: Pseudonym::of(&device_key),
        device_key,
        nonce: "fictional-nonce".into(),
        time: "2026-10-22T12:00:00Z".parse().unwrap(),
        client: "open-pact-client 0.2.0".into(),
        os: Os::Windows,
        trust_level: TrustLevel::L0,
        virtualized: None,
        csr_sha256: None,
        log_checkpoint: None,
        results: [("log_cleared".into(), ControlValue::Null)].into(),
    };
    let verified = verify_claim(&sign_claim(&claim, &key).unwrap()).unwrap();
    assert_eq!(verified.claim().results["log_cleared"], ControlValue::Null);
    assert_eq!(
        evaluate(
            &manifest,
            verified.claim(),
            claim.time,
            &FirstFailures::new()
        )
        .decision,
        Decision::Allow { warnings: vec![] }
    );
    claim
        .results
        .insert("log_cleared".into(), "2026-10-22T10:00:00Z".into());
    assert!(matches!(
        evaluate(&manifest, &claim, claim.time, &FirstFailures::new()).decision,
        Decision::Deny { .. }
    ));
    claim.results.insert("log_cleared".into(), "unknown".into());
    assert!(
        matches!(evaluate(&manifest, &claim, claim.time, &FirstFailures::new()).decision, Decision::Allow { warnings } if warnings.len() == 1)
    );
    claim.results.insert("log_cleared".into(), "null".into());
    assert!(
        matches!(evaluate(&manifest, &claim, claim.time, &FirstFailures::new()).decision, Decision::Deny { reasons } if reasons.iter().any(|r| r.breaks_disclosure_contract()))
    );
}
