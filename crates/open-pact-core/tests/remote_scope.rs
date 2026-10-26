use open_pact_core::{Manifest, Violation, is_narrowing};

const DEMO: &str = include_str!("../../../examples/manifest.toml");
const FIREWALL_CHECK: &str = r#"check = "builtin:firewall@1""#;

fn managed_manifest(check: &str, remotes: &[&str]) -> Manifest {
    let remote_list = remotes
        .iter()
        .map(|pattern| format!("\"{pattern}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let text = DEMO.replacen(
        FIREWALL_CHECK,
        &format!("check = \"{check}\"\nremotes = [{remote_list}]"),
        1,
    );
    Manifest::parse(text.as_bytes()).unwrap()
}

#[test]
fn parses_and_normalizes_remote_patterns() {
    let manifest = managed_manifest(
        "builtin:managed_repos_outside@1",
        &["GITHUB.com/example-org/repo.git/"],
    );

    assert_eq!(
        manifest.body().control("firewall").unwrap().remotes[0].as_str(),
        "github.com/example-org/repo/"
    );
}

#[test]
fn rejects_invalid_remote_patterns() {
    for pattern in [
        "https://github.com/example-org/",
        "user@github.com/example-org/",
        "github.com:443/example-org/",
        "github.com/example-*/",
        "github.com/example-org/?repo/",
        "github.com//example-org/",
        "github.com/example org/",
        "github.com/example-org",
    ] {
        let result = managed_manifest_result(pattern);
        assert!(result.is_err(), "accepted {pattern:?}");
    }
}

fn managed_manifest_result(pattern: &str) -> Result<Manifest, open_pact_core::Error> {
    let remote_list = format!("[\"{pattern}\"]");
    let text = DEMO.replacen(
        FIREWALL_CHECK,
        &format!("check = \"builtin:managed_repos_outside@1\"\nremotes = {remote_list}"),
        1,
    );
    Manifest::parse(text.as_bytes())
}

#[test]
fn rejects_remotes_on_other_controls_and_missing_remotes_on_managed_controls() {
    let wrong_control = DEMO.replacen(
        FIREWALL_CHECK,
        "check = \"builtin:firewall@1\"\nremotes = [\"github.com/example-org/\"]",
        1,
    );
    let error = Manifest::parse(wrong_control.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("firewall"));

    let missing_pattern = DEMO.replacen(
        FIREWALL_CHECK,
        "check = \"builtin:managed_repos_total@1\"",
        1,
    );
    let error = Manifest::parse(missing_pattern.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("firewall"));
}

#[test]
fn empty_remote_lists_are_omitted_when_serialized() {
    let manifest = Manifest::parse(DEMO.as_bytes()).unwrap();
    let control = manifest.body().control("firewall").unwrap();
    let serialized = serde_json::to_value(control).unwrap();

    assert!(serialized.get("remotes").is_none());
}

#[test]
fn remote_set_changes_need_fresh_consent() {
    let github = "github.com/example-org/";
    let azure = "dev.azure.com/example-org/";
    let old = managed_manifest("builtin:managed_repos_outside@1", &[github]);

    assert_eq!(
        is_narrowing(
            &old,
            &managed_manifest("builtin:managed_repos_outside@1", &[github, azure])
        ),
        Err(vec![Violation::RemotesChanged {
            id: "firewall".into()
        }])
    );
    assert_eq!(
        is_narrowing(
            &managed_manifest("builtin:managed_repos_outside@1", &[github, azure]),
            &old
        ),
        Err(vec![Violation::RemotesChanged {
            id: "firewall".into()
        }])
    );
    assert_eq!(
        is_narrowing(
            &managed_manifest("builtin:managed_repos_outside@1", &[github, azure]),
            &managed_manifest("builtin:managed_repos_outside@1", &[azure, github])
        ),
        Ok(())
    );
}

#[test]
fn accepts_remote_patterns_for_both_managed_repository_checks() {
    for check in [
        "builtin:managed_repos_outside@1",
        "builtin:managed_repos_total@1",
    ] {
        let manifest = managed_manifest(check, &["github.com/example-org/"]);
        assert_eq!(manifest.body().control("firewall").unwrap().check, check);
    }
}
