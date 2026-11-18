//! The running() check of scripts/install-desktop.sh decides only by its exit status. It must not
//! print anything, because the in-app update logs the installer output.
#![cfg(unix)]

use runner::shell_quote;
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn running_function() -> String {
    let script = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/install-desktop.sh"),
    )
    .unwrap();
    let start = script
        .find("running() {")
        .expect("the script defines running()");
    let rest = &script[start..];
    let end = rest
        .find("\n}\n")
        .expect("running() ends with a closing brace")
        + 3;
    rest[..end].to_owned()
}

/// Runs `running open-pact` with a fake `ps` that prints `ps_lines`, where `{dir}` stands for the
/// install folder. Returns what it printed on stdout and stderr, and its exit status.
fn run(ps_lines: &str) -> (String, String, Option<i32>) {
    let work = tempfile::tempdir().unwrap();
    let bin = work.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let dir = work.path().join("Applications (Work)");
    let dir_text = dir.display().to_string();
    let fake = bin.join("ps");
    fs::write(
        &fake,
        format!(
            "#!/bin/sh\ncat <<'LINES'\n{}\nLINES\n",
            ps_lines.replace("{dir}", &dir_text)
        ),
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let script = format!(
        "dir={}\n{}\nrunning open-pact\n",
        shell_quote(&dir_text),
        running_function()
    );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .output()
        .unwrap();
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
        output.status.code(),
    )
}

#[test]
fn running_prints_nothing_when_the_app_runs() {
    let (stdout, stderr, status) =
        run("/usr/bin/unrelated --example\n{dir}/open-pact.app/Contents/MacOS/open-pact --example");
    assert_eq!(status, Some(0));
    assert_eq!((stdout.as_str(), stderr.as_str()), ("", ""));
}

#[test]
fn running_prints_nothing_when_the_app_does_not_run() {
    let (stdout, stderr, status) = run(
        "/usr/bin/unrelated --example\n{dir}/open-pact-admin.app/Contents/MacOS/open-pact-admin",
    );
    assert_eq!(status, Some(1));
    assert_eq!((stdout.as_str(), stderr.as_str()), ("", ""));
}
