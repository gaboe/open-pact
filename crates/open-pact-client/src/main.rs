//! The `open-pact-client` command line: the parser, the terminal and the process. Everything else
//! is the `open_pact_client` library, which the desktop apps call too.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use open_pact_client as client;

#[derive(Parser)]
#[command(
    name = "open-pact-client",
    version,
    about = "Prove this device meets the company's signed manifest, nothing more"
)]
struct Cli {
    /// Directory for keys, the signed manifest and logs [default: ~/.config/open-pact]
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    /// Allow a plain http:// gateway other than localhost. For development only
    #[arg(long, global = true)]
    insecure_dev: bool,
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn into_invocation(self) -> client::Invocation {
        client::Invocation {
            home: self.home,
            insecure_dev: self.insecure_dev,
            command: self.command.into(),
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Show the device status without running checks or sending a claim
    Status(StatusOptions),
    /// Check the gateway against the invitation from IT, show the manifest, sign it and enrol
    Join {
        /// The opi1: invitation string from IT
        invitation: Option<String>,
        /// Sign without asking
        #[arg(long)]
        yes: bool,
        /// Keep a new device key in a file (trust level L0) even when a Secure Enclave is available
        #[arg(long)]
        software_key: bool,
        /// Print the device code and exit without waiting for IT
        #[arg(long)]
        no_wait: bool,
        /// Show what joining would sign, as JSON, and stop. Signs nothing, writes no file, sends no POST
        #[arg(
            long,
            requires = "invitation",
            conflicts_with_all = ["yes", "software_key", "no_wait", "json"]
        )]
        preview: bool,
        /// Print one JSON line per wizard step event. Needs --yes; nothing is asked
        #[arg(long, requires = "yes")]
        json: bool,
        /// With --json: a folder that holds your repositories, for the manifest's repository checks. Repeatable
        #[arg(long = "folder", requires = "json")]
        folders: Vec<PathBuf>,
        /// With --json: send claims automatically (on) or not (off) [default: off]
        #[arg(long, requires = "json", value_enum)]
        auto_send: Option<Toggle>,
    },
    /// Run the manifest's checks, send a signed claim and fetch a VPN certificate
    Check {
        /// Print the claim that would be sent. Make GET requests only and write no file
        #[arg(long)]
        dry_run: bool,
        /// With --dry-run: also print the wall time of the run and the CPU time of this process
        /// and its child processes
        #[arg(long, requires = "dry_run")]
        timings: bool,
        /// After sending, print the result as JSON
        #[arg(long, conflicts_with = "dry_run")]
        json: bool,
    },
    /// Review a changed manifest from the gateway, sign it and move this device to it
    Accept {
        /// Sign without asking
        #[arg(long)]
        yes: bool,
        /// Print what accepting would change, as JSON, and stop. Signs nothing, writes no file
        #[arg(long, conflicts_with = "yes")]
        preview: bool,
    },
    /// Choose the folders that hold your repositories, for the manifest's repository checks
    Folders {
        #[command(subcommand)]
        command: FoldersCommand,
    },
    /// Show the manifest this device signed, or check a manifest draft
    Manifest {
        #[command(subcommand)]
        command: ManifestCommand,
    },
    /// Turn automatic sending of claims on or off, or show its state
    Schedule {
        #[command(subcommand)]
        command: ScheduleCommand,
    },
    /// Transparency log and local claim log
    Log {
        #[command(subcommand)]
        command: LogCommand,
    },
    /// Show how to stop the scheduled claims and remove the client
    Stop,
    /// Destroy the device key before full uninstall or rotation
    DeleteDeviceKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Toggle {
    On,
    Off,
}

#[derive(Subcommand)]
enum FoldersCommand {
    /// Show the folders
    List,
    /// Add a folder that holds repositories. `~` is your home folder
    Add { path: PathBuf },
    /// Remove a folder
    Remove { path: PathBuf },
}

#[derive(Subcommand)]
enum ManifestCommand {
    /// Show the signed manifest stored on this device
    Show,
    /// Check a manifest draft from stdin with the rules clients and the gateway apply. Needs no home or network
    Check {
        /// Print one JSON document: ok, and the errors with their line and key
        #[arg(long)]
        json: bool,
    },
    /// List the built-in checks this client runs, with their default text. Needs no home or network
    Builtins {
        /// Print one JSON array: each check, its id and its default text
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum LogCommand {
    /// Print the last verified, gateway-signed log checkpoint held on this device
    Head,
    /// Fetch and verify the inclusion proof of one log entry [default: this device's enrolment]
    Prove { index: Option<u64> },
    /// Print every claim this device sent and the gateway's response
    Show,
}

/// The options of `status`.
#[derive(clap::Args)]
struct StatusOptions {
    /// Refresh approval, manifest, log, VPN probe, and OS job state. Sends no claim
    #[arg(long)]
    online: bool,
    /// Print the same evidence and issues as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum ScheduleCommand {
    /// Install the job that sends claims by itself, as the signed manifest allows
    On {
        /// Windows only: run the job as SYSTEM. Needs an elevated PowerShell prompt
        #[arg(long, hide = !cfg!(windows), conflicts_with = "user")]
        system: bool,
        /// Windows only: run the job as the current user
        #[arg(long, hide = !cfg!(windows))]
        user: bool,
        /// Show what would change and change nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the job
    Off {
        /// Show what would change and change nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Show whether the job is installed and what the signed manifest allows
    Status,
    #[command(hide = true)]
    Run {
        #[arg(long)]
        system: bool,
        /// The profile whose repositories and `~` paths count, when the job does not run as that user
        #[arg(long)]
        user_home: Option<PathBuf>,
    },
    #[command(hide = true)]
    Probe {
        #[arg(long)]
        address: String,
        /// The DNS name that the probe's TLS certificate must carry
        #[arg(long)]
        name: Option<String>,
    },
}

impl From<Command> for client::Command {
    fn from(command: Command) -> Self {
        match command {
            Command::Status(options) => client::Command::Status(client::StatusOptions {
                online: options.online,
                json: options.json,
            }),
            Command::Join {
                invitation,
                yes,
                software_key,
                no_wait,
                preview,
                json,
                folders,
                auto_send,
            } => client::Command::Join {
                invitation,
                yes,
                software_key,
                no_wait,
                preview,
                json,
                folders,
                auto_send: auto_send.map(|toggle| match toggle {
                    Toggle::On => client::Toggle::On,
                    Toggle::Off => client::Toggle::Off,
                }),
            },
            Command::Check {
                dry_run,
                timings,
                json,
            } => client::Command::Check {
                dry_run,
                timings,
                json,
            },
            Command::Accept { yes, preview } => client::Command::Accept { yes, preview },
            Command::Folders { command } => client::Command::Folders {
                command: match command {
                    FoldersCommand::List => client::FoldersCommand::List,
                    FoldersCommand::Add { path } => client::FoldersCommand::Add { path },
                    FoldersCommand::Remove { path } => client::FoldersCommand::Remove { path },
                },
            },
            Command::Manifest { command } => client::Command::Manifest {
                command: match command {
                    ManifestCommand::Show => client::ManifestCommand::Show,
                    ManifestCommand::Check { json } => client::ManifestCommand::Check { json },
                    ManifestCommand::Builtins { json } => {
                        client::ManifestCommand::Builtins { json }
                    }
                },
            },
            Command::Schedule { command } => client::Command::Schedule {
                command: match command {
                    ScheduleCommand::On {
                        system,
                        user,
                        dry_run,
                    } => client::ScheduleCommand::On {
                        system,
                        user,
                        dry_run,
                    },
                    ScheduleCommand::Off { dry_run } => client::ScheduleCommand::Off { dry_run },
                    ScheduleCommand::Status => client::ScheduleCommand::Status,
                    ScheduleCommand::Run { system, user_home } => {
                        client::ScheduleCommand::Run { system, user_home }
                    }
                    ScheduleCommand::Probe { address, name } => {
                        client::ScheduleCommand::Probe { address, name }
                    }
                },
            },
            Command::Log { command } => client::Command::Log {
                command: match command {
                    LogCommand::Head => client::LogCommand::Head,
                    LogCommand::Prove { index } => client::LogCommand::Prove { index },
                    LogCommand::Show => client::LogCommand::Show,
                },
            },
            Command::Stop => client::Command::Stop,
            Command::DeleteDeviceKey => client::Command::DeleteDeviceKey,
        }
    }
}

/// Whether the command line asked for JSON output, so a failure to parse it is JSON too.
fn args_ask_for_json(args: &[std::ffi::OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--json" || arg == "--preview")
}

/// The error line for a command line that does not parse, when it asked for JSON. Help and version
/// output, and the errors of a command line that did not ask for JSON, stay as clap prints them.
fn usage_error_line(args: &[std::ffi::OsString], error: &clap::Error) -> Option<String> {
    if !error.use_stderr() || !args_ask_for_json(args) {
        return None;
    }
    let text = error.to_string();
    let first = text.split("\n\n").next().unwrap_or_default().trim();
    let first = first.strip_prefix("error: ").unwrap_or(first);
    Some(serde_json::json!({ "error": first }).to_string())
}

/// What the terminal gives the library: the standard input, whether a person sits at it, and Ctrl-C.
fn terminal() -> client::Host {
    client::Host::new(
        || Box::new(std::io::stdin().lock()),
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        || {
            Box::pin(async {
                let _ = tokio::signal::ctrl_c().await;
            })
        },
    )
}

fn main() -> ExitCode {
    // Windows gives the main thread 1 MiB, which the debug CLI future can exceed.
    std::thread::Builder::new()
        .name("open-pact-client".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build the CLI runtime");
            let code = runtime.block_on(cli_main());
            // A blocking task, such as a repository scan that waits on a FIFO, cannot be stopped.
            // Dropping the runtime would wait for it, so the command ends without waiting.
            runtime.shutdown_background();
            code
        })
        .expect("start the CLI thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

async fn cli_main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error) => match usage_error_line(&args, &error) {
            Some(line) => {
                let _ = writeln!(std::io::stdout(), "{line}");
                return ExitCode::from(2);
            }
            None => error.exit(),
        },
    };
    let invocation = cli.into_invocation();
    let json = client::prints_json(&invocation.command);
    // Keep Rust's ignored SIGPIPE for JSON: a closed stderr must not kill usable stdout.
    // Text commands still exit quietly when their stdout pipe closes, such as `log show | head`.
    #[cfg(unix)]
    if !json {
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }
    let executable = std::env::current_exe().unwrap_or_default();
    let result = client::with_host(terminal(), async {
        if json {
            client::catch_panic(client::run(invocation, &executable)).await
        } else {
            client::run(invocation, &executable).await
        }
    })
    .await;
    match result {
        Ok(code) => code,
        Err(error) if error.is::<client::Interrupted>() => {
            if json {
                let _ = writeln!(
                    std::io::stdout(),
                    "{}",
                    serde_json::json!({ "error": "interrupted" })
                );
            }
            ExitCode::from(130)
        }
        Err(error) if json => {
            let line = serde_json::json!({ "error": format!("{error:#}") });
            let _ = writeln!(std::io::stdout(), "{line}");
            ExitCode::FAILURE
        }
        Err(error) => {
            // A warning that cannot be written must not stop the command.
            let _ = writeln!(std::io::stderr(), "error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn join_invitation_argument_is_optional_for_a_saved_enrolment() {
        let cli = Cli::try_parse_from(["open-pact-client", "join"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Join {
                invitation: None,
                ..
            }
        ));
    }
    #[test]
    fn json_flags_need_the_flags_they_depend_on() {
        let parse = |args: &[&str]| {
            let mut all = vec!["open-pact-client"];
            all.extend_from_slice(args);
            Cli::try_parse_from(all).map(|_| ())
        };
        assert!(parse(&["join", "--preview", "opi1:x"]).is_ok());
        assert!(
            parse(&["join", "--preview"]).is_err(),
            "preview needs the invitation"
        );
        assert!(parse(&["join", "--preview", "--yes", "opi1:x"]).is_err());
        assert!(
            parse(&[
                "join",
                "--json",
                "--yes",
                "--folder",
                "/a",
                "--auto-send",
                "on"
            ])
            .is_ok()
        );
        assert!(
            parse(&["join", "--json"]).is_err(),
            "--json asks nothing, so it needs --yes"
        );
        assert!(parse(&["join", "--yes", "--folder", "/a"]).is_err());
        assert!(parse(&["join", "--yes", "--auto-send", "on"]).is_err());
        assert!(parse(&["join", "--json", "--yes", "--auto-send", "maybe"]).is_err());
        assert!(parse(&["check", "--json"]).is_ok());
        assert!(parse(&["check", "--json", "--dry-run"]).is_err());
        assert!(parse(&["check", "--dry-run", "--timings"]).is_ok());
        assert!(
            parse(&["check", "--timings"]).is_err(),
            "timings belong to the dry run: a real check writes files and sends"
        );
        assert!(parse(&["accept", "--preview"]).is_ok());
        assert!(parse(&["accept", "--preview", "--yes"]).is_err());
    }
    #[test]
    fn startup_vpn_recovery_skips_the_commands_that_write_no_file() {
        let parse = |args: &[&str]| {
            let mut all = vec!["open-pact-client"];
            all.extend_from_slice(args);
            Cli::try_parse_from(all).unwrap()
        };
        for skipped in [
            &["status"][..],
            &["manifest", "show"],
            &["join", "--preview", "opi1:fictional"],
            &["accept", "--preview"],
        ] {
            assert!(
                !client::recovers_vpn_first(&parse(skipped).into_invocation().command),
                "{skipped:?}"
            );
        }
        for recovering in [
            &["check"][..],
            &["check", "--json"],
            &["join", "opi1:fictional"],
            &["accept"],
        ] {
            assert!(
                client::recovers_vpn_first(&parse(recovering).into_invocation().command),
                "{recovering:?}"
            );
        }
    }
    #[test]
    fn a_command_line_that_does_not_parse_gets_a_json_error_when_it_asked_for_json() {
        let line = |args: &[&str]| {
            let mut all = vec!["open-pact-client"];
            all.extend_from_slice(args);
            let all: Vec<std::ffi::OsString> = all.into_iter().map(Into::into).collect();
            let error = Cli::try_parse_from(&all).map(|_| ()).unwrap_err();
            usage_error_line(&all, &error)
        };
        for args in [
            &["join", "--json", "--yes", "--auto-send", "maybe"][..],
            &["join", "--preview"],
            &["check", "--json", "--bogus"],
            &["status", "--json", "--bogus"],
        ] {
            let text = line(args).unwrap_or_else(|| panic!("{args:?} has no JSON error"));
            let document: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(document.as_object().unwrap().len(), 1, "{text}");
            assert!(!document["error"].as_str().unwrap().is_empty(), "{text}");
            assert!(!text.contains('\n'), "{text}");
        }
        assert_eq!(line(&["join", "--bogus"]), None);
        assert_eq!(line(&["check", "--bogus"]), None);
    }
}

#[cfg(test)]
mod schedule {
    mod tests {
        use crate::Cli;

        #[test]
        fn imperative_setup_commands_are_removed() {
            use clap::Parser;
            for args in [
                vec![
                    "client",
                    "schedule",
                    "install",
                    "--collector",
                    "https://example.org",
                ],
                vec!["client", "schedule", "uninstall"],
                vec!["client", "report", "--collector", "https://example.org"],
                vec!["client", "report", "--dry-run"],
                vec!["client", "log", "reports"],
                vec!["client", "apply"],
                vec!["client", "finish"],
                vec!["client", "config", "example"],
            ] {
                assert!(Cli::try_parse_from(args).is_err());
            }
            assert!(Cli::try_parse_from(["client", "check", "--dry-run"]).is_ok());
            for args in [
                vec!["client", "schedule", "on"],
                vec!["client", "schedule", "on", "--dry-run"],
                vec!["client", "schedule", "off"],
                vec!["client", "schedule", "status"],
                vec!["client", "folders", "list"],
                vec!["client", "folders", "add", "~/work"],
                vec!["client", "folders", "remove", "~/work"],
            ] {
                assert!(Cli::try_parse_from(args).is_ok());
            }
            assert!(
                Cli::try_parse_from(["client", "schedule", "on", "--system", "--user"]).is_err()
            );
        }
    }
}
