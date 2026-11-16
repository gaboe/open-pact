fn main() {
    println!("cargo:rerun-if-changed=../../assets/open-pact.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("../../assets/open-pact.ico");
        resource.compile().expect("embed the Windows icon");
    }
}
