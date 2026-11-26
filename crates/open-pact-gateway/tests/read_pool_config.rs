//! The real binary refuses a read pool of no connections at startup, before it reaches a database.

use std::process::Command;

#[test]
fn a_read_pool_of_zero_connections_refuses_startup() {
    let output = Command::new(env!("CARGO_BIN_EXE_open-pact-gateway"))
        .env("READ_POOL_CONNECTIONS", "0")
        // A closed port: a gateway that connected first would retry for a minute.
        .env("DATABASE_URL", "postgres://fictional@127.0.0.1:1/pact")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("READ_POOL_CONNECTIONS must be at least 1"),
        "{stderr}"
    );
}
