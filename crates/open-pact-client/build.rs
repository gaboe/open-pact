fn main() {
    // The release workflow names its own repository, so a fork's build updates from the fork.
    println!("cargo:rerun-if-env-changed=OPEN_PACT_REPOSITORY");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource.set_manifest(MANIFEST);
        resource
            .compile()
            .expect("embed the Windows application manifest");
    }
}

/// Runs as the user who starts it. Without this, Windows Installer Detection asks for elevation
/// for an exe whose name contains "install".
const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#;
