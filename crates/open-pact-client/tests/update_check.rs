//! The real binary on an empty home: the update check must not open any connection.

use std::net::TcpListener;
use std::process::Command;

#[test]
fn an_empty_home_makes_no_update_request() {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let address = format!("http://{}", proxy.local_addr().unwrap());
    let home = tempfile::tempdir().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_open-pact-client"))
        .env_remove("OPEN_PACT_NO_UPDATE_CHECK")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .env_remove("ALL_PROXY")
        .env("HTTPS_PROXY", &address)
        .env("HTTP_PROXY", &address)
        .arg("--home")
        .arg(home.path())
        .args(["status", "--online", "--json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let document: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("printed {stdout:?}: {error}"));
    assert!(document["update"].is_null(), "{stdout}");
    assert!(
        proxy.accept().is_err(),
        "the update check opened a connection through the proxy"
    );
}
