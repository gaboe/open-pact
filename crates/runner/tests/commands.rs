use runner::{
    Runner,
    admin::{Admin, Settings},
    client::{Client, JoinEvent},
    manifest::{self, Block, Kind},
};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[cfg(unix)]
fn client() -> Client {
    Client {
        runner: Runner::default(),
        executable: fixture("bin/open-pact-client"),
    }
}

#[test]
#[cfg(unix)]
fn client_screens_use_json_and_keep_actionable_status() {
    let client = client();
    let preview = client.preview("opi1:fictional").unwrap();
    assert!(preview.company.matches_invitation);
    assert_eq!(preview.folders, ["~/Documents"]);
    assert!(
        client
            .preview("opi1:expired")
            .unwrap_err()
            .starts_with("This invitation expired")
    );
    let mut events = Vec::new();
    client
        .join("opi1:fictional", &preview.folders, true, |e| events.push(e))
        .unwrap();
    assert!(matches!(events.last(), Some(JoinEvent::Result { .. })));
    assert_eq!(events.len(), 7);
    let status = client.status().unwrap();
    assert_eq!(status.verdict, "action_needed");
    assert!(!status.approval.live);
    assert_eq!(status.issues.len(), 2);
    assert!(client.check().unwrap().accepted);
    assert!(client.changes().unwrap().schedule_widened);
    client.accept().unwrap();
    client.schedule(false).unwrap();
    client.schedule(true).unwrap();
    let logs = client.runner.logs();
    assert!(logs.iter().any(|log| log.exit == Some(2)));
    assert!(logs.iter().any(|log| {
        log.args
            .windows(2)
            .any(|w| w == ["--folder", "~/Documents"])
    }));
    assert!(logs.iter().all(|log| log.exit.is_some()));
}

#[test]
#[cfg(unix)]
fn admin_screens_use_context_namespace_and_gateway_json() {
    let mut admin = Admin::new(
        Runner::default(),
        Settings {
            context: "fictional-cluster".into(),
            namespace: "open-pact".into(),
            ..Settings::default()
        },
    );
    admin.kubectl = fixture("bin/kubectl");
    assert!(!admin.gateway().unwrap().auto_approve);
    let devices = admin.devices().unwrap();
    assert_eq!(devices.len(), 3);
    assert!(devices.iter().any(|d| d.state == "pending"));
    assert!(runner::admin::ready(&admin.deployment().unwrap()));
    assert!(
        admin
            .invite("72h", "Fictional note; $(ignored)")
            .unwrap()
            .invitation
            .starts_with("opi1:")
    );
    admin.device_action("approve", "0a1b2c3d").unwrap();
    admin.device_action("revoke", "fictional-a").unwrap();
    for log in admin.runner.logs() {
        assert_eq!(
            &log.args[..4],
            ["--context", "fictional-cluster", "-n", "open-pact"]
        );
    }
}

#[test]
fn yaml_edit_preserves_all_bytes_outside_the_manifest() {
    for newline in ["\n", "\r\n"] {
        let original = std::fs::read_to_string(fixture("application.yaml"))
            .unwrap()
            .replace('\n', newline);
        let block = Block::parse(original.clone()).unwrap();
        assert_eq!(block.replace(&block.text).unwrap(), original);
        let fields = manifest::fields(&block.text).unwrap();
        let password = fields.iter().find(|f| f.label.ends_with("min")).unwrap();
        let changed = manifest::set_field(&block.text, password, "12").unwrap();
        assert_eq!(
            block.replace(&changed).unwrap(),
            original.replace("min = 10", "min = 12")
        );
        assert!(fields.iter().any(|f| f.kind == Kind::Bool));
        assert!(fields.iter().any(|f| f.kind == Kind::List));
        assert!(block.replace("broken = [").is_err());
    }
}

#[test]
fn every_toml_value_has_an_editable_control() {
    let text = "name = \"Example\"\nnumber = 3\nratio = 0.5\nactive = true\nlist = [1, 2]\n[table]\ninline = { threshold = 10 }\n[[controls]]\nid = \"disk\"\nrequired = true\n";
    let fields = manifest::fields(text).unwrap();
    assert_eq!(fields.len(), 8);
    for field in fields {
        let value = match field.kind {
            Kind::Text => "Changed",
            Kind::Number => "15",
            Kind::Bool => "false",
            Kind::List => "[3, 4]",
        };
        let changed = manifest::set_field(text, &field, value).unwrap();
        let new_fields = manifest::fields(&changed).unwrap();
        assert_eq!(
            new_fields
                .iter()
                .find(|f| f.path == field.path)
                .unwrap()
                .value,
            value
        );
    }
}

#[test]
fn ambiguous_discovery_and_path_escape_fail() {
    let temp = tempfile::tempdir().unwrap();
    let source = std::fs::read_to_string(fixture("application.yaml")).unwrap();
    std::fs::write(temp.path().join("one.yaml"), &source).unwrap();
    assert_eq!(
        manifest::discover(temp.path()).unwrap(),
        temp.path().join("one.yaml")
    );
    std::fs::write(temp.path().join("two.yml"), source).unwrap();
    assert!(manifest::discover(temp.path()).is_err());
    let settings = Settings {
        repo: temp.path().into(),
        manifest: "../escape.yaml".into(),
        ..Settings::default()
    };
    assert!(settings.manifest_path().is_err());
}

#[test]
#[cfg(unix)]
fn bundled_install_keeps_an_executable_and_checks_version() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("bundled");
    std::fs::write(&source, "#!/bin/sh\nprintf 'open-pact-client 0.6.0\\n'\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
    let destination = temp.path().join("local/bin/open-pact-client");
    runner::client::install(&Runner::default(), &source, &destination).unwrap();
    assert_eq!(
        runner::client::version(&Runner::default(), &destination).unwrap(),
        "open-pact-client 0.6.0"
    );
}
