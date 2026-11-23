//! The client app owns the device: the OS job runs the one command line tool copy that the app
//! installed. These rules find every other copy and name the command that removes it. Nothing
//! here removes a file or runs a package manager; the app runs the command when its user clicks.

use crate::update::{Invocation, Platform, shell_invocation};
use crate::{shell_line, shell_quote};
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
    /// The machine client in Program Files, installed for all users by an administrator. The app
    /// never removes it.
    MachineClient,
}

/// A command line tool on PATH that is not the installed copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtherCopy {
    pub path: PathBuf,
    pub source: Source,
    /// Homebrew: the `brew` program of the prefix that owns this copy. `None` when no prefix
    /// was found, and the removal then uses the first `brew` on PATH.
    pub brew: Option<PathBuf>,
    /// Scoop: the package that owns this copy. `None` means the standalone package.
    pub package: Option<String>,
    /// Scoop: the file that the shim at `path` names. The package uninstall removes it together
    /// with the shim, so it counts as the same copy.
    pub target: Option<PathBuf>,
}

impl OtherCopy {
    pub fn new(path: PathBuf, source: Source) -> Self {
        Self {
            path,
            source,
            brew: None,
            package: None,
            target: None,
        }
    }
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

/// The `brew` program of the Homebrew prefix that owns the copy at `path` (`resolved` is the
/// same file after symlinks, inside the Cellar). Every folder above the copy that holds
/// `bin/brew` is a prefix; the nearest one wins. Two Homebrew installations on one computer
/// each remove their own package this way, whichever `brew` comes first on PATH.
pub fn brew_owner(path: &Path, resolved: &Path) -> Option<PathBuf> {
    [resolved, path].into_iter().find_map(|file| {
        file.ancestors()
            .skip(1)
            .map(|folder| folder.join("bin").join("brew"))
            .find(|brew| brew.is_file())
    })
}

/// The Scoop package that owns a file below `scoop/apps/<package>`.
pub fn scoop_package(path: &Path) -> Option<String> {
    let parts = words(path);
    let at = parts
        .windows(2)
        .position(|pair| pair == ["scoop", "apps"])?;
    parts
        .get(at + 2)
        .filter(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        })
        .cloned()
}

/// The target of a Scoop shim. Scoop copies a shim program next to a `.shim` text file that names
/// the real executable, so the shim itself is a file that no link points through.
pub fn shim_target(contents: &str) -> Option<PathBuf> {
    contents.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "path").then(|| PathBuf::from(value.trim().trim_matches('"')))
    })
}

/// The command that removes `copy`. A package manager removes its own package, so the app never
/// deletes a file that a package manager owns. The machine client has no removal: `None`.
pub fn removal(copy: &OtherCopy, platform: Platform) -> Option<Removal> {
    let removal = match copy.source {
        Source::MachineClient => return None,
        Source::Homebrew => {
            let program = copy.brew.as_ref().map_or_else(
                || "brew".to_owned(),
                |brew| brew.to_string_lossy().into_owned(),
            );
            Removal {
                shown: shell_line(&[program.as_str(), "uninstall", PACKAGE]),
                call: Invocation {
                    program,
                    args: vec!["uninstall".into(), PACKAGE.into()],
                    env: Vec::new(),
                },
            }
        }
        Source::Scoop => {
            let package = copy.package.as_deref().unwrap_or(PACKAGE);
            let line = format!("scoop uninstall {package}");
            Removal {
                call: shell_invocation(platform, &line),
                shown: line,
            }
        }
        Source::Other => {
            let file = copy.path.to_string_lossy();
            let line = if platform == Platform::Windows {
                format!("Remove-Item -LiteralPath {}", powershell_literal(&file))
            } else {
                format!("rm {}", shell_quote(&file))
            };
            Removal {
                call: shell_invocation(platform, &line),
                shown: line,
            }
        }
    };
    Some(removal)
}

/// Every `name` on `path_var` except the files in `own` (the installed copy and the copy
/// bundled with the app). A file that two PATH entries reach counts once. A Scoop shim counts as
/// the file it names, so the shim of the bundled copy is not another copy.
///
/// A file that is `machine`, the machine client, or a Scoop shim that names it, is the one entry
/// of source `MachineClient`, at the machine client's own path. The app shows it and never removes it.
pub fn other_copies(
    path_var: &OsStr,
    name: &str,
    own: &[PathBuf],
    brew_roots: &[PathBuf],
    machine: Option<&Path>,
) -> Vec<OtherCopy> {
    let resolve = |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let is_own = |path: &Path| own.iter().any(|own| same_path(own, path));
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut found = Vec::new();
    for directory in std::env::split_paths(path_var) {
        let path = directory.join(name);
        if !path.is_file() {
            continue;
        }
        let shim = read_shim_target(&path);
        let has_shim = shim.is_some();
        let target = shim.unwrap_or_else(|| path.clone());
        let resolved = resolve(&target);
        if is_own(&path) || is_own(&target) || seen.contains(&resolved) {
            continue;
        }
        seen.push(resolved.clone());
        if let Some(machine) =
            machine.filter(|machine| same_path(machine, &path) || same_path(machine, &target))
        {
            found.push(OtherCopy::new(machine.to_path_buf(), Source::MachineClient));
            continue;
        }
        let source = classify(&path, &resolved, brew_roots);
        found.push(OtherCopy {
            brew: (source == Source::Homebrew)
                .then(|| brew_owner(&path, &resolved))
                .flatten(),
            package: (source == Source::Scoop)
                .then(|| scoop_package(&resolved).or_else(|| scoop_package(&target)))
                .flatten(),
            source,
            target: has_shim.then_some(target),
            path,
        });
    }
    found
}

/// The copy that the app offers to remove: the first one with a removal command, in PATH order.
/// The machine client can come first, and it never hides a copy behind it.
/// The copy that the active user job runs is never offered: removing it stops the job.
pub fn first_removable<'a>(
    copies: &'a [OtherCopy],
    platform: Platform,
    active: Option<&Path>,
) -> Option<(&'a OtherCopy, Removal)> {
    copies
        .iter()
        .filter(|copy| !is_active(copy, active))
        .find_map(|copy| removal(copy, platform).map(|removal| (copy, removal)))
}

fn read_shim_target(path: &Path) -> Option<PathBuf> {
    std::fs::read_to_string(path.with_extension("shim"))
        .ok()
        .and_then(|contents| shim_target(&contents))
}

/// The words of the Scoop app folder that holds `path`: everything through `scoop/apps/<name>`.
/// The folder covers `current` and each version folder of the package.
fn scoop_app_folder(path: &Path) -> Option<Vec<String>> {
    let parts = words(path);
    let at = parts
        .windows(2)
        .position(|pair| pair == ["scoop", "apps"])?;
    parts.get(at + 2)?;
    Some(parts[..=at + 2].to_vec())
}

/// Whether `copy` is the executable that the active user job records. The job's file is the
/// copy's PATH entry, the file a shim of that entry names, or any file in the same Scoop app
/// folder as that target: the package uninstall removes them all. The recorded file can also be a
/// shim whose target is the copy.
pub fn is_active(copy: &OtherCopy, active: Option<&Path>) -> bool {
    let Some(active) = active else {
        return false;
    };
    let active_files: Vec<PathBuf> = [Some(active.to_path_buf()), read_shim_target(active)]
        .into_iter()
        .flatten()
        .collect();
    let copy_files: Vec<&Path> = [Some(copy.path.as_path()), copy.target.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    if copy_files
        .iter()
        .any(|file| active_files.iter().any(|active| same_path(file, active)))
    {
        return true;
    }
    copy.source == Source::Scoop
        && copy_files
            .iter()
            .filter_map(|file| scoop_app_folder(file))
            .any(|folder| {
                active_files
                    .iter()
                    .any(|active| words(active).starts_with(&folder))
            })
}

/// The copy that the active user job runs, when it is among the copies.
pub fn active_copy<'a>(copies: &'a [OtherCopy], active: Option<&Path>) -> Option<&'a OtherCopy> {
    copies.iter().find(|copy| is_active(copy, active))
}

/// The machine client among the copies, which the app names but never removes.
pub fn machine_copy(copies: &[OtherCopy]) -> Option<&OtherCopy> {
    copies
        .iter()
        .find(|copy| copy.source == Source::MachineClient)
}

/// How many other copies the owner can act on. The machine client is no other copy.
pub fn other_count(copies: &[OtherCopy]) -> usize {
    copies
        .iter()
        .filter(|copy| copy.source != Source::MachineClient)
        .count()
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

/// A PowerShell single-quoted string. PowerShell reads the typographic single quotes as quotes
/// too, so each of them doubles like the plain one.
fn powershell_literal(text: &str) -> String {
    let mut quoted = String::from("'");
    for letter in text.chars() {
        quoted.push(letter);
        if matches!(
            letter,
            '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}'
        ) {
            quoted.push(letter);
        }
    }
    quoted.push('\'');
    quoted
}

/// One argument of a command line for `CommandLineToArgvW`: the value in double quotes, with each
/// backslash before a quote, and the backslashes at its end, doubled, as Rust's own spawn does.
fn windows_arg(raw: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in raw.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        out.push_str(&"\\".repeat(if c == '"' { slashes * 2 + 1 } else { slashes }));
        out.push(c);
        slashes = 0;
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

/// `schedule on --system` in an elevated process, which the user's UAC prompt allows. The machine
/// client at `machine` runs with the `runas` verb and the job's arguments: the device home, and the
/// profile whose repositories the job scans. The client checks each argument and its own protection
/// when it registers the job. The wrapper ends with the client's exit code. A cancelled prompt, a
/// launch that fails and a child without an exit code all end it with a nonzero exit code.
pub fn elevated_system_schedule(machine: &Path, home: &Path, profile: &Path) -> Invocation {
    let arguments = format!(
        "--home {} schedule on --system --user-home {}",
        windows_arg(&home.to_string_lossy()),
        windows_arg(&profile.to_string_lossy()),
    );
    let line = format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ $run = Start-Process -FilePath {exe} -ArgumentList {arguments} -Verb RunAs -Wait -PassThru }} \
         catch {{ [Console]::Error.WriteLine('The administrator process did not start: ' + $_.Exception.Message); exit 1 }}; \
         if ($null -eq $run -or $null -eq $run.ExitCode) {{ [Console]::Error.WriteLine('The administrator process gave no exit code.'); exit 1 }}; \
         exit $run.ExitCode",
        exe = powershell_literal(&machine.to_string_lossy()),
        arguments = powershell_literal(&arguments),
    );
    shell_invocation(Platform::Windows, &line)
}

/// Starts `exe` again with the `runas` verb, which shows the UAC prompt. The wrapper ends with 0
/// once the process started, and with 1 when the user cancelled the prompt or the launch failed.
/// It does not wait for the new process.
pub fn elevated_restart(exe: &Path) -> Invocation {
    let line = format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ Start-Process -FilePath {exe} -Verb RunAs }} \
         catch {{ [Console]::Error.WriteLine('The administrator process did not start: ' + $_.Exception.Message); exit 1 }}; \
         exit 0",
        exe = powershell_literal(&exe.to_string_lossy()),
    );
    shell_invocation(Platform::Windows, &line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copy(path: &str, source: Source) -> OtherCopy {
        OtherCopy::new(PathBuf::from(path), source)
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
        )
        .unwrap();
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
        )
        .unwrap();
        assert_eq!(scoop.shown, "scoop uninstall open-pact");
        assert_eq!(scoop.call.program, "powershell");
        assert_eq!(
            scoop.call.args.last().map(String::as_str),
            Some("scoop uninstall open-pact")
        );

        let file = removal(
            &copy("/home/fictional/my tools/open-pact-client", Source::Other),
            Platform::Mac,
        )
        .unwrap();
        assert_eq!(file.shown, "rm '/home/fictional/my tools/open-pact-client'");
        assert_eq!(
            file.call.args,
            ["-c", "rm '/home/fictional/my tools/open-pact-client'"]
        );

        let windows = removal(
            &copy(r"C:\Fictional's\open-pact-client.exe", Source::Other),
            Platform::Windows,
        )
        .unwrap();
        assert_eq!(
            windows.shown,
            r"Remove-Item -LiteralPath 'C:\Fictional''s\open-pact-client.exe'"
        );
        // A typographic quote in the file name cannot end the literal early either.
        let typographic = removal(
            &copy(
                "C:\\Fictional\u{2019}s\\open-pact-client.exe",
                Source::Other,
            ),
            Platform::Windows,
        )
        .unwrap();
        assert_eq!(
            typographic.shown,
            "Remove-Item -LiteralPath 'C:\\Fictional\u{2019}\u{2019}s\\open-pact-client.exe'"
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

    const HOME: &str = r"C:\Users\Fictional\.config\open-pact";
    const PROFILE: &str = r"C:\Users\Fictional";

    #[test]
    fn the_elevated_child_gets_the_device_home_and_the_profile_as_plain_arguments() {
        let call = elevated_system_schedule(
            Path::new(r"C:\Program Files\open-pact-client\open-pact-client.exe"),
            Path::new(HOME),
            Path::new(PROFILE),
        );
        let line = call.args.last().unwrap();
        assert!(line.contains(
            r"-FilePath 'C:\Program Files\open-pact-client\open-pact-client.exe' -ArgumentList '--home "
        ));
        assert!(line.contains(&powershell_literal(&format!(
            r#"--home "{HOME}" schedule on --system --user-home "{PROFILE}""#
        ))));
        // A typographic quote in a path cannot end the literal early.
        assert_eq!(powershell_literal("a\u{2019}b"), "'a\u{2019}\u{2019}b'");
    }

    #[test]
    fn a_value_with_a_space_or_a_trailing_slash_stays_one_argument() {
        assert_eq!(
            windows_arg(r"C:\Users\Fictional Name\"),
            r#""C:\Users\Fictional Name\\""#
        );
        assert_eq!(windows_arg(r#"a"b"#), r#""a\"b""#);
    }

    #[test]
    fn a_cancelled_or_failed_elevation_ends_the_wrapper_with_a_failure() {
        let call = elevated_system_schedule(
            Path::new(r"C:\Users\Fictional\open-pact-client.exe"),
            Path::new(HOME),
            Path::new(PROFILE),
        );
        let line = call.args.last().unwrap();
        assert!(line.starts_with("$ErrorActionPreference = 'Stop'"));
        assert!(line.contains("-Verb RunAs -Wait -PassThru"));
        // A cancelled UAC prompt throws: the wrapper reports it and exits with 1, not 0.
        assert!(line.contains(
            "catch { [Console]::Error.WriteLine('The administrator process did not start: '"
        ));
        assert!(line.contains("exit 1 }"));
        // No process or no exit code is a failure too, never a silent `exit $null`.
        assert!(line.contains("if ($null -eq $run -or $null -eq $run.ExitCode)"));
        assert!(line.ends_with("exit $run.ExitCode"));
    }

    #[test]
    fn the_machine_client_has_no_removal_command_and_never_hides_another_copy() {
        let machine = r"C:\Program Files\open-pact-client\open-pact-client.exe";
        let scoop = r"C:\Users\Fictional\scoop\shims\open-pact-client.exe";
        assert_eq!(
            removal(&copy(machine, Source::MachineClient), Platform::Windows),
            None
        );
        // The machine client's directory comes first on PATH, as the MSI puts it there.
        let copies = vec![
            copy(machine, Source::MachineClient),
            copy(scoop, Source::Scoop),
        ];
        let (first, removal) = first_removable(&copies, Platform::Windows, None).unwrap();
        assert_eq!(first.path, Path::new(scoop));
        assert_eq!(removal.shown, "scoop uninstall open-pact");
        assert_eq!(machine_copy(&copies).unwrap().path, Path::new(machine));
        // The machine client is no other copy in the count.
        assert_eq!(other_count(&copies), 1);
        assert!(first_removable(&copies[..1], Platform::Windows, None).is_none());
        assert_eq!(other_count(&copies[..1]), 0);
    }

    #[test]
    fn the_copy_that_the_active_user_job_runs_is_never_offered_for_removal() {
        let active = "/opt/fictional/bin/open-pact-client";
        let unrelated = "/usr/local/fictional/open-pact-client";
        let copies = vec![copy(active, Source::Other), copy(unrelated, Source::Other)];
        let active_path = Some(Path::new(active));
        // The first copy on PATH is the active one: the offer moves to the unrelated copy.
        let (offered, _) = first_removable(&copies, Platform::Mac, active_path).unwrap();
        assert_eq!(offered.path, Path::new(unrelated));
        assert_eq!(
            active_copy(&copies, active_path).unwrap().path,
            Path::new(active)
        );
        assert!(is_active(&copies[0], active_path));
        assert!(!is_active(&copies[1], active_path));
        // With only the active copy there is nothing to offer.
        assert!(first_removable(&copies[..1], Platform::Mac, active_path).is_none());
        // Without an active job executable nothing changes.
        assert_eq!(
            first_removable(&copies, Platform::Mac, None)
                .unwrap()
                .0
                .path,
            Path::new(active)
        );
    }

    /// A Scoop package with a real shim: the shim folder, the package folder and the shim file.
    struct ScoopFixture {
        _temp: tempfile::TempDir,
        shims: PathBuf,
        app: PathBuf,
        shim: PathBuf,
        target: PathBuf,
        other_app: PathBuf,
        version: PathBuf,
    }

    fn scoop_fixture() -> ScoopFixture {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let make = |relative: &str, text: &str| {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            path
        };
        let target = make("scoop/apps/open-pact/current/open-pact-client", "fictional");
        let version = make("scoop/apps/open-pact/0.7.1/open-pact-client", "fictional");
        let other_app = make(
            "scoop/apps/open-pact-other/current/open-pact-client",
            "fictional",
        );
        let shim = make("scoop/shims/open-pact-client", "shim program");
        make(
            "scoop/shims/open-pact-client.shim",
            &format!("path = \"{}\"\n", target.display()),
        );
        ScoopFixture {
            shims: root.join("scoop/shims"),
            app: root.join("scoop/apps/open-pact/current"),
            shim,
            target,
            other_app,
            version,
            _temp: temp,
        }
    }

    fn scoop_copies(path: &[&Path], own: &[PathBuf]) -> Vec<OtherCopy> {
        let path = std::env::join_paths(path).unwrap();
        other_copies(&path, "open-pact-client", own, &[], None)
    }

    #[test]
    fn a_scoop_copy_is_active_through_its_shim_target_or_its_app_folder() {
        let fixture = scoop_fixture();
        let unrelated = tempfile::tempdir().unwrap();
        let loose = unrelated.path().join("tools/open-pact-client");
        std::fs::create_dir_all(loose.parent().unwrap()).unwrap();
        std::fs::write(&loose, "fictional").unwrap();
        let loose_dir = loose.parent().unwrap();

        // The shim comes first on PATH: the copy keeps the shim, and names its target.
        let shim_first = scoop_copies(&[&fixture.shims, &fixture.app, loose_dir], &[]);
        assert_eq!(shim_first.len(), 2);
        assert_eq!(shim_first[0].path, fixture.shim);
        assert_eq!(shim_first[0].target.as_ref(), Some(&fixture.target));
        // The target folder comes first: the later shim is the same copy.
        let target_first = scoop_copies(&[&fixture.app, &fixture.shims, loose_dir], &[]);
        assert_eq!(target_first.len(), 2);
        assert_eq!(target_first[0].path, fixture.target);

        let shim_file = fixture.shim.clone();
        let receipts = [
            // The receipt names the shim, the target, or a version folder of the package.
            shim_file.as_path(),
            fixture.target.as_path(),
            fixture.version.as_path(),
        ];
        for found in [&shim_first, &target_first] {
            for receipt in receipts {
                let active = Some(receipt);
                assert!(is_active(&found[0], active), "{receipt:?}");
                assert!(!is_active(&found[1], active));
                let (offered, _) = first_removable(found, Platform::Windows, active).unwrap();
                assert_eq!(offered.path, loose);
                assert!(first_removable(&found[..1], Platform::Windows, active).is_none());
                assert_eq!(active_copy(found, active).unwrap().path, found[0].path);
            }
            // Another package's folder and an unrelated file leave the copy removable.
            for receipt in [fixture.other_app.as_path(), loose.as_path()] {
                assert!(!is_active(&found[0], Some(receipt)), "{receipt:?}");
            }
            assert!(!is_active(&found[0], None));
        }
    }

    #[test]
    fn removing_a_scoop_copy_that_the_active_job_runs_through_its_shim_is_refused() {
        use crate::engine::remove_copy;
        let fixture = scoop_fixture();
        let found = scoop_copies(&[&fixture.shims], &[]);
        assert_eq!(found.len(), 1);
        // The runner would fail on a missing program: only the refusal gives this text.
        let runner = crate::Runner::default();
        for active in [&fixture.shim, &fixture.target, &fixture.version] {
            let error = remove_copy(&runner, &found[0], || Some(active.clone())).unwrap_err();
            assert!(error.contains("scheduled job runs"), "{error}");
        }
    }

    #[test]
    fn the_machine_client_is_marked_by_its_path_or_by_a_shim_that_names_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let make = |relative: &str, text: &str| {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            path
        };
        let machine = make(
            "Program Files/open-pact-client/open-pact-client",
            "fictional",
        );
        let loose = make("tools/open-pact-client", "fictional");
        let installed = make("home/open-pact-client", "fictional");
        let own = [installed];
        // PATH order: the machine client, then another copy.
        let path = std::env::join_paths([
            root.join("Program Files/open-pact-client"),
            root.join("tools"),
        ])
        .unwrap();
        let found = other_copies(&path, "open-pact-client", &own, &[], Some(&machine));
        assert_eq!(
            found,
            vec![
                OtherCopy::new(machine.clone(), Source::MachineClient),
                OtherCopy::new(loose.clone(), Source::Other),
            ]
        );
        assert_eq!(
            first_removable(&found, Platform::Mac, None).unwrap().0.path,
            loose
        );
        // A shim that names the machine client comes first, then its own folder: one entry, and
        // it is the machine client.
        make("scoop/shims/open-pact-client", "shim program");
        make(
            "scoop/shims/open-pact-client.shim",
            &format!("path = \"{}\"\n", machine.display()),
        );
        let path = std::env::join_paths([
            root.join("scoop/shims"),
            root.join("Program Files/open-pact-client"),
        ])
        .unwrap();
        let found = other_copies(&path, "open-pact-client", &own, &[], Some(&machine));
        assert_eq!(
            found,
            vec![OtherCopy::new(machine.clone(), Source::MachineClient)]
        );
    }

    #[test]
    fn the_restart_starts_the_app_with_the_runas_verb_and_fails_when_it_does_not_start() {
        let call = elevated_restart(Path::new(r"C:\Users\O'Fictional\open-pact.exe"));
        assert_eq!(call.program, "powershell");
        assert_eq!(&call.args[..2], ["-NoProfile", "-Command"]);
        let expected = concat!(
            "$ErrorActionPreference = 'Stop'; ",
            r"try { Start-Process -FilePath 'C:\Users\O''Fictional\open-pact.exe' -Verb RunAs } ",
            "catch { [Console]::Error.WriteLine('The administrator process did not start: ' + $_.Exception.Message); exit 1 }; ",
            "exit 0",
        );
        assert_eq!(call.args.last().unwrap(), expected);
    }

    #[test]
    fn a_shim_names_its_target_and_a_package_owns_its_apps_folder() {
        let contents = "path = \"C:\\Users\\Fictional\\scoop\\apps\\open-pact-desktop\\current\\open-pact-client.exe\"\r\nargs = --x\r\n";
        assert_eq!(
            shim_target(contents),
            Some(PathBuf::from(
                r"C:\Users\Fictional\scoop\apps\open-pact-desktop\current\open-pact-client.exe"
            ))
        );
        assert_eq!(shim_target("args = nothing"), None);
        assert_eq!(
            scoop_package(Path::new(
                r"C:\Users\Fictional\Scoop\apps\open-pact\current\x.exe"
            )),
            Some("open-pact".to_owned())
        );
        assert_eq!(
            scoop_package(Path::new(r"C:\Users\Fictional\scoop\shims\x.exe")),
            None
        );
    }

    #[test]
    fn a_scoop_copy_is_removed_by_the_package_that_owns_it() {
        let mut copy = copy(
            r"C:\fictional\scoop\shims\open-pact-client.exe",
            Source::Scoop,
        );
        copy.package = Some("open-pact-other".into());
        assert_eq!(
            removal(&copy, Platform::Windows).unwrap().shown,
            "scoop uninstall open-pact-other"
        );
    }

    #[test]
    fn the_scoop_shim_of_the_bundled_copy_is_not_another_copy() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let make = |relative: &str, text: &str| {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            path
        };
        let bundled = make(
            "scoop/apps/open-pact-desktop/current/open-pact-client",
            "fictional",
        );
        make("scoop/shims/open-pact-client", "shim program");
        make(
            "scoop/shims/open-pact-client.shim",
            &format!("path = \"{}\"\n", bundled.display()),
        );
        let path = std::env::join_paths([root.join("scoop/shims")]).unwrap();
        assert_eq!(
            other_copies(
                &path,
                "open-pact-client",
                std::slice::from_ref(&bundled),
                &[],
                None
            ),
            vec![]
        );

        // A shim of the standalone package is another copy, owned by that package.
        let standalone = make("scoop/apps/open-pact/current/open-pact-client", "fictional");
        make(
            "scoop/shims/open-pact-client.shim",
            &format!("path = \"{}\"\n", standalone.display()),
        );
        let found = other_copies(&path, "open-pact-client", &[bundled], &[], None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].source, Source::Scoop);
        assert_eq!(found[0].package.as_deref(), Some("open-pact"));
    }

    #[cfg(unix)]
    #[test]
    fn each_homebrew_copy_is_removed_by_the_brew_of_its_own_prefix() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let canonical_root = std::fs::canonicalize(temp.path()).unwrap();
        let root = canonical_root.as_path();
        let make = |relative: &str| {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "fictional").unwrap();
            path
        };
        for prefix in ["brew-a", "brew-b"] {
            make(&format!("{prefix}/bin/brew"));
            let cellar = make(&format!(
                "{prefix}/Cellar/open-pact/0.7.1/bin/open-pact-client"
            ));
            symlink(&cellar, root.join(prefix).join("bin/open-pact-client")).unwrap();
        }
        let installed = make("home/.local/bin/open-pact-client");
        let path =
            std::env::join_paths([root.join("brew-a/bin"), root.join("brew-b/bin")]).unwrap();
        // The first brew on PATH owns only prefix A; `brew --prefix` names that one root.
        let roots = [std::fs::canonicalize(root.join("brew-a/Cellar/open-pact")).unwrap()];
        let found = other_copies(
            &path,
            "open-pact-client",
            std::slice::from_ref(&installed),
            &roots,
            None,
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].brew, Some(root.join("brew-a/bin/brew")));
        assert_eq!(found[1].brew, Some(root.join("brew-b/bin/brew")));
        let second = removal(&found[1], Platform::Mac).unwrap();
        assert_eq!(
            second.call.program,
            root.join("brew-b/bin/brew").to_string_lossy()
        );
        assert_eq!(second.call.args, ["uninstall", "open-pact"]);
        assert!(
            second
                .shown
                .ends_with("brew-b/bin/brew uninstall open-pact")
        );
        // After prefix A lost its package, the rescan reports B, and the command names B's brew.
        std::fs::remove_file(root.join("brew-a/bin/open-pact-client")).unwrap();
        let rescan = other_copies(&path, "open-pact-client", &[installed], &[], None);
        assert_eq!(rescan.len(), 1);
        assert_eq!(rescan[0].brew, Some(root.join("brew-b/bin/brew")));
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
        let found = other_copies(&path, "open-pact-client", &[installed], &[], None);
        assert_eq!(
            found,
            vec![
                OtherCopy::new(root.join("brew/bin/open-pact-client"), Source::Homebrew),
                OtherCopy::new(loose, Source::Other),
            ]
        );
    }
}
