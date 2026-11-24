//! The client must start without elevation. The manifest in build.rs declares asInvoker.

#[cfg(windows)]
#[test]
fn client_binary_declares_as_invoker() {
    let bytes =
        std::fs::read(env!("CARGO_BIN_EXE_open-pact-client")).expect("read the client binary");
    let needle = b"asInvoker";
    assert!(
        bytes.windows(needle.len()).any(|window| window == needle),
        "the client binary has no asInvoker application manifest"
    );
}
