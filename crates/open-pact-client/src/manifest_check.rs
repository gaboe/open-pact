//! `manifest check`: the rules a client and the gateway apply to a new manifest, run on a draft.
//! It reads no home, no enrolment and no network.

use std::io::{Read, Write};
use std::process::ExitCode;

use anyhow::Result;
use open_pact_core::{Error, Manifest};
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Problem {
    message: String,
    line: Option<usize>,
    key: Option<String>,
}

#[derive(Serialize)]
struct Report {
    ok: bool,
    errors: Vec<Problem>,
}

/// What a client and the gateway refuse in `bytes`: the core rules, then the builtins this client runs.
fn problems(bytes: &[u8]) -> Vec<Problem> {
    let manifest = match Manifest::parse(bytes) {
        Ok(manifest) => manifest,
        Err(error) => return vec![core_problem(bytes, &error)],
    };
    match crate::checks::check_supported(&manifest) {
        Ok(()) => Vec::new(),
        Err(message) => vec![Problem {
            message,
            line: None,
            key: None,
        }],
    }
}

fn core_problem(bytes: &[u8], error: &Error) -> Problem {
    let (message, line) = match error {
        Error::ManifestToml(toml_error) => (
            toml_error.message().to_string(),
            toml_error.span().map(|span| line_at(bytes, span.start)),
        ),
        Error::InvalidManifest(message) => (message.clone(), None),
        other => (other.to_string(), None),
    };
    Problem {
        message,
        line,
        key: error.manifest_key(),
    }
}

/// The 1-based line that holds byte `offset`.
fn line_at(bytes: &[u8], offset: usize) -> usize {
    1 + bytes[..offset.min(bytes.len())]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
}

fn render(problems: Vec<Problem>, json: bool) -> String {
    if json {
        let report = Report {
            ok: problems.is_empty(),
            errors: problems,
        };
        return serde_json::to_string(&report).expect("a report serializes");
    }
    if problems.is_empty() {
        return "Manifest is valid.".to_string();
    }
    problems
        .iter()
        .map(|problem| match problem.line {
            Some(line) => format!("line {line}: {}", problem.message),
            None => problem.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn run(json: bool) -> Result<ExitCode> {
    let mut bytes = Vec::new();
    let problems = match std::io::stdin().lock().read_to_end(&mut bytes) {
        Ok(_) => problems(&bytes),
        Err(error) => vec![Problem {
            message: format!("read the manifest from stdin: {error}"),
            line: None,
            key: None,
        }],
    };
    let code = if problems.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    };
    let _ = writeln!(std::io::stdout(), "{}", render(problems, json));
    Ok(code)
}
