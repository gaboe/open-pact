//! The client app owns the device: the OS job runs the one command line tool copy that the app
//! installed. These rules find every other copy and name the command that removes it. Nothing
//! here removes a file or runs a package manager; the app runs the command when its user clicks.

use crate::shell_quote;
use crate::update::{Invocation, Platform, shell_invocation};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The package that Homebrew and Scoop install the command line tool as.
const PACKAGE: &str = "open-pact";

/// How an other copy came onto this computer, which decides how it goes away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Homebrew,
    Scoop,
    /// A file that no package manager owns.
    Other,
}

/// A command line tool on PATH that is not the installed copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtherCopy {
    pub path: PathBuf,
    pub source: Source,
}

/// The command that removes an other copy: the line to show, and the process to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removal {
    pub shown: String,
    pub call: Invocation,
}

fn words(path: &Path) -> Vec<String> {
    path.to_string_lossy()
        .split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn contains_run(parts: &[String], run: &[&str]) -> bool {
    parts.windows(run.len()).any(|window| window == run)
}

/// Where a copy at `path` came from. `resolved` is the path after symlinks, because Homebrew
/// links its tools into a `bin` folder from its `Cellar`. `brew_roots` are the folders that
/// `brew --prefix open-pact` names, also after symlinks.
pub fn classify(path: &Path, resolved: &Path, brew_roots: &[PathBuf]) -> Source {
    let seen = [words(path), words(resolved)];
    let scoop = seen.iter().any(|parts| {
        contains_run(parts, &["scoop", "apps", PACKAGE]) || contains_run(parts, &["scoop", "shims"])
    });
    if scoop {
        return Source::Scoop;
    }
    let brew = seen
        .iter()
        .any(|parts| contains_run(parts, &["cellar", PACKAGE]))
        || brew_roots
            .iter()
            .any(|root| path.starts_with(root) || resolved.starts_with(root));
    if brew {
        Source::Homebrew
    } else {
        Source::Other
    }
}

/// The command that removes `copy`. A package manager removes its own package, so the app never
/// deletes a file that a package manager owns.
pub fn removal(copy: &OtherCopy, platform: Platform) -> Removal {
    match copy.source {
        Source::Homebrew => Removal {
            shown: format!("brew uninstall {PACKAGE}"),
            call: Invocation {
                program: "brew".into(),
                args: vec!["uninstall".into(), PACKAGE.into()],
                env: Vec::new(),
            },
        },
        Source::Scoop => {
            let line = format!("scoop uninstall {PACKAGE}");
            Removal {
                call: shell_invocation(platform, &line),
                shown: line,
            }
        }
        Source::Other => {
            let file = copy.path.to_string_lossy();
            let line = if platform == Platform::Windows {
                format!("Remove-Item -LiteralPath '{}'", file.replace('\'', "''"))
            } else {
                format!("rm {}", shell_quote(&file))
            };
            Removal {
                call: shell_invocation(platform, &line),
                shown: line,
            }
        }
    }
}

/// Every `name` on `path_var` except the files in `own` (the installed copy and the copy
/// bundled with the app). A file that two PATH entries reach counts once.
pub fn other_copies(
    path_var: &OsStr,
    name: &str,
    own: &[PathBuf],
    brew_roots: &[PathBuf],
) -> Vec<OtherCopy> {
    let resolve = |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let own: Vec<PathBuf> = own
        .iter()
        .flat_map(|path| [path.clone(), resolve(path)])
        .collect();
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut found = Vec::new();
    for directory in std::env::split_paths(path_var) {
        let path = directory.join(name);
        if !path.is_file() {
            continue;
        }
        let resolved = resolve(&path);
        if own.contains(&path) || own.contains(&resolved) || seen.contains(&resolved) {
            continue;
        }
        seen.push(resolved.clone());
        found.push(OtherCopy {
            source: classify(&path, &resolved, brew_roots),
            path,
        });
    }
    found
}

fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    let canonical =
        |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if canonical(a) == canonical(b) {
        return true;
    }
    cfg!(windows)
        && a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
}

/// True when the recorded OS job runs another executable than the installed copy, and the owner
/// already agreed to automatic sending. Rewriting the job then only changes its executable. A
/// SYSTEM job is never rewritten here: it needs an elevated process.
pub fn job_needs_rewrite(
    job_executable: Option<&Path>,
    installed: &Path,
    consented: bool,
    system_job: bool,
) -> bool {
    consented && !system_job && job_executable.is_some_and(|job| !same_path(job, installed))
}

/// `schedule on --system` in an elevated process, which the user's UAC prompt allows. A library
/// call cannot elevate, so the app starts the installed copy through PowerShell's `runas` verb
/// and waits for its exit code.
pub fn elevated_system_schedule(installed: &Path) -> Invocation {
    let file = installed.to_string_lossy().replace('\'', "''");
    let line = format!(
        "$run = Start-Process -FilePath '{file}' -ArgumentList 'schedule','on','--system' -Verb RunAs -Wait -PassThru; exit $run.ExitCode"
    );
    shell_invocation(Platform::Windows, &line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copy(path: &str, source: Source) -> OtherCopy {
        OtherCopy {
            path: PathBuf::from(path),
            source,
        }
    }

    #[test]
    fn a_homebrew_link_is_known_by_its_cellar_or_by_the_brew_prefix() {
        let link = Path::new("/opt/fictional/bin/open-pact-client");
        let cellar = Path::new("/opt/fictional/Cellar/open-pact/0.7.1/bin/open-pact-client");
        assert_eq!(classify(link, cellar, &[]), Source::Homebrew);
        let root = PathBuf::from("/srv/fictional-brew/opt/open-pact");
        let inside = Path::new("/srv/fictional-brew/opt/open-pact/bin/open-pact-client");
        assert_eq!(classify(inside, inside, &[root]), Source::Homebrew);
        assert_eq!(classify(link, link, &[]), Source::Other);
    }

    #[test]
    fn a_scoop_app_or_shim_is_scoop() {
        let app =
            Path::new(r"C:\Users\Fictional\Scoop\apps\open-pact\current\open-pact-client.exe");
        assert_eq!(classify(app, app, &[]), Source::Scoop);
        let shim = Path::new(r"C:\Users\Fictional\scoop\shims\open-pact-client.exe");
        assert_eq!(classify(shim, shim, &[]), Source::Scoop);
        let loose = Path::new(r"C:\Tools\open-pact-client.exe");
        assert_eq!(classify(loose, loose, &[]), Source::Other);
    }

    #[test]
    fn each_source_has_its_own_removal_command() {
        let brew = removal(
            &copy("/opt/fictional/bin/open-pact-client", Source::Homebrew),
            Platform::Mac,
        );
        assert_eq!(brew.shown, "brew uninstall open-pact");
        assert_eq!(
            (brew.call.program.as_str(), brew.call.args.as_slice()),
            (
                "brew",
                ["uninstall".to_owned(), "open-pact".to_owned()].as_slice()
            )
        );

        let scoop = removal(
            &copy(
                r"C:\fictional\scoop\shims\open-pact-client.exe",
                Source::Scoop,
            ),
            Platform::Windows,
        );
        assert_eq!(scoop.shown, "scoop uninstall open-pact");
        assert_eq!(scoop.call.program, "powershell");
        assert_eq!(
            scoop.call.args.last().map(String::as_str),
            Some("scoop uninstall open-pact")
        );

        let file = removal(
            &copy("/home/fictional/my tools/open-pact-client", Source::Other),
            Platform::Mac,
        );
        assert_eq!(file.shown, "rm '/home/fictional/my tools/open-pact-client'");
        assert_eq!(
            file.call.args,
            ["-c", "rm '/home/fictional/my tools/open-pact-client'"]
        );

        let windows = removal(
            &copy(r"C:\Fictional's\open-pact-client.exe", Source::Other),
            Platform::Windows,
        );
        assert_eq!(
            windows.shown,
            r"Remove-Item -LiteralPath 'C:\Fictional''s\open-pact-client.exe'"
        );
    }

    #[test]
    fn the_job_is_rewritten_only_when_it_names_another_executable_with_consent() {
        let installed = Path::new("/home/fictional/.local/bin/open-pact-client");
        let brew = Path::new("/opt/fictional/bin/open-pact-client");
        assert!(job_needs_rewrite(Some(brew), installed, true, false));
        assert!(!job_needs_rewrite(Some(installed), installed, true, false));
        // No job recorded, no consent, or a SYSTEM job: nothing to rewrite.
        assert!(!job_needs_rewrite(None, installed, true, false));
        assert!(!job_needs_rewrite(Some(brew), installed, false, false));
        assert!(!job_needs_rewrite(Some(brew), installed, true, true));
    }

    #[test]
    fn the_elevated_command_quotes_the_path_and_passes_the_exit_code_on() {
        let call =
            elevated_system_schedule(Path::new(r"C:\Users\O'Fictional\open-pact-client.exe"));
        let line = call.args.last().unwrap();
        assert!(line.contains(r"'C:\Users\O''Fictional\open-pact-client.exe'"));
        assert!(line.contains("'schedule','on','--system' -Verb RunAs -Wait -PassThru"));
        assert!(line.ends_with("exit $run.ExitCode"));
    }

    #[cfg(unix)]
    #[test]
    fn other_copies_skip_the_installed_one_and_count_a_linked_file_once() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let make = |relative: &str| {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "fictional").unwrap();
            path
        };
        let installed = make("home/.local/bin/open-pact-client");
        let cellar = make("brew/Cellar/open-pact/0.7.1/bin/open-pact-client");
        std::fs::create_dir_all(root.join("brew/bin")).unwrap();
        symlink(&cellar, root.join("brew/bin/open-pact-client")).unwrap();
        let loose = make("tools/open-pact-client");
        let path = std::env::join_paths([
            root.join("home/.local/bin"),
            root.join("brew/bin"),
            root.join("brew/Cellar/open-pact/0.7.1/bin"),
            root.join("tools"),
            root.join("missing"),
        ])
        .unwrap();
        let found = other_copies(&path, "open-pact-client", &[installed], &[]);
        assert_eq!(
            found,
            vec![
                OtherCopy {
                    path: root.join("brew/bin/open-pact-client"),
                    source: Source::Homebrew
                },
                OtherCopy {
                    path: loose,
                    source: Source::Other
                },
            ]
        );
    }
}
