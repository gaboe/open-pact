//! Checks a release before the workflow uploads its assets: the SHA256SUMS of the tag must be
//! signed by the release workflow of this repository. client-release.yml runs this before it
//! uploads anything, so a failed check stops the release.
//!
//! Usage: verify_release <tag> <repository> <SHA256SUMS> <SHA256SUMS.sigstore.json>

use std::process::ExitCode;

use open_pact_client::release_verify::verify_release;

const USAGE: &str =
    "usage: verify_release <tag> <repository> <SHA256SUMS> <SHA256SUMS.sigstore.json>";

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("verify_release: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [tag, repository, sums_path, bundle_path] = args.as_slice() else {
        return Err(format!("expected 4 arguments, got {}. {USAGE}", args.len()));
    };
    let sums =
        std::fs::read(sums_path).map_err(|error| format!("cannot read {sums_path}: {error}"))?;
    let bundle = std::fs::read(bundle_path)
        .map_err(|error| format!("cannot read {bundle_path}: {error}"))?;
    let verified =
        verify_release(&sums, &bundle, tag, repository).map_err(|error| error.to_string())?;
    Ok(format!("verified {} for {repository}", verified.tag))
}
