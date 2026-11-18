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
}

impl OtherCopy {
    pub fn new(path: PathBuf, source: Source) -> Self {
        Self {
            path,
            source,
            brew: None,
            package: None,
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
/// deletes a file that a package manager owns.
pub fn removal(copy: &OtherCopy, platform: Platform) -> Removal {
    match copy.source {
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
/// bundled with the app). A file that two PATH entries reach counts once. A Scoop shim counts as
/// the file it names, so the shim of the bundled copy is not another copy.
pub fn other_copies(
    path_var: &OsStr,
    name: &str,
    own: &[PathBuf],
    brew_roots: &[PathBuf],
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
        let shim = std::fs::read_to_string(path.with_extension("shim"))
            .ok()
            .and_then(|contents| shim_target(&contents));
        let target = shim.unwrap_or_else(|| path.clone());
        let resolved = resolve(&target);
        if is_own(&path) || is_own(&target) || seen.contains(&resolved) {
            continue;
        }
        seen.push(resolved.clone());
        let source = classify(&path, &resolved, brew_roots);
        found.push(OtherCopy {
            brew: (source == Source::Homebrew)
                .then(|| brew_owner(&path, &resolved))
                .flatten(),
            package: (source == Source::Scoop)
                .then(|| scoop_package(&resolved).or_else(|| scoop_package(&target)))
                .flatten(),
            source,
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

/// What the elevated PowerShell runs. A process that starts with the `runas` verb gets no
/// environment from its parent, and a UAC prompt can run it as another administrator. So the
/// script sets the scan profile itself, and the CLI gets the device home as `--home`. It ends
/// with the CLI's exit code, and with 1 when the CLI did not run at all.
fn elevated_script(installed: &Path, home: &Path, profile: &Path) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $env:USERPROFILE = {profile}\n\
         try {{ & {exe} --home {home} schedule on --system }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}\n\
         if ($null -eq $LASTEXITCODE) {{ exit 1 }}\n\
         exit $LASTEXITCODE",
        profile = powershell_literal(&profile.to_string_lossy()),
        exe = powershell_literal(&installed.to_string_lossy()),
        home = powershell_literal(&home.to_string_lossy()),
    )
}

/// The text that `powershell -EncodedCommand` takes: base64 of the script as UTF-16 little endian.
fn encoded_command(script: &str) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let word = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for place in 0..4 {
            if place <= chunk.len() {
                encoded.push(char::from(
                    DIGITS[((word >> (18 - 6 * place)) & 63) as usize],
                ));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// `schedule on --system` in an elevated process, which the user's UAC prompt allows. A library
/// call cannot elevate, so the app starts the installed copy through PowerShell's `runas` verb
/// and waits for its exit code. `home` is the device home of the app's session and `profile`
/// the profile whose repositories the job scans. A cancelled prompt, a launch that fails and a
/// child without an exit code all end the wrapper with a nonzero exit code.
pub fn elevated_system_schedule(installed: &Path, home: &Path, profile: &Path) -> Invocation {
    let child = encoded_command(&elevated_script(installed, home, profile));
    let line = format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ $run = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','{child}' -Verb RunAs -Wait -PassThru }} \
         catch {{ [Console]::Error.WriteLine('The administrator process did not start: ' + $_.Exception.Message); exit 1 }}; \
         if ($null -eq $run -or $null -eq $run.ExitCode) {{ [Console]::Error.WriteLine('The administrator process gave no exit code.'); exit 1 }}; \
         exit $run.ExitCode"
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

    const HOME: &str = r"C:\Users\Fictional\.config\open-pact";
    const PROFILE: &str = r"C:\Users\Fictional";

    #[test]
    fn the_elevated_child_gets_the_device_home_and_the_scan_profile() {
        let script = elevated_script(
            Path::new(r"C:\Users\O'Fictional\open-pact-client.exe"),
            Path::new(HOME),
            Path::new(PROFILE),
        );
        assert!(script.contains(r"$env:USERPROFILE = 'C:\Users\Fictional'"));
        assert!(script.contains(
            r"& 'C:\Users\O''Fictional\open-pact-client.exe' --home 'C:\Users\Fictional\.config\open-pact' schedule on --system"
        ));
        // A typographic quote in a path cannot end the literal early.
        assert_eq!(powershell_literal("a\u{2019}b"), "'a\u{2019}\u{2019}b'");
    }

    #[test]
    fn the_child_script_ends_with_the_cli_exit_code_and_fails_without_one() {
        let script = elevated_script(Path::new("a.exe"), Path::new(HOME), Path::new(PROFILE));
        assert!(script.contains("$ErrorActionPreference = 'Stop'"));
        assert!(
            script.contains("catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")
        );
        assert!(script.contains("if ($null -eq $LASTEXITCODE) { exit 1 }"));
        assert!(script.ends_with("exit $LASTEXITCODE"));
    }

    #[test]
    fn a_cancelled_or_failed_elevation_ends_the_wrapper_with_a_failure() {
        let call = elevated_system_schedule(
            Path::new(r"C:\Users\Fictional\open-pact-client.exe"),
            Path::new(HOME),
            Path::new(PROFILE),
        );
        let line = call.args.last().unwrap();
        let child = encoded_command(&elevated_script(
            Path::new(r"C:\Users\Fictional\open-pact-client.exe"),
            Path::new(HOME),
            Path::new(PROFILE),
        ));
        assert!(line.starts_with("$ErrorActionPreference = 'Stop'"));
        assert!(line.contains(&format!(
            "'-EncodedCommand','{child}' -Verb RunAs -Wait -PassThru"
        )));
        // A cancelled UAC prompt throws: the wrapper reports it and exits with 1, not 0.
        assert!(line.contains(
            "catch { [Console]::Error.WriteLine('The administrator process did not start: '"
        ));
        assert!(line.contains("exit 1 }"));
        // No process or no exit code is a failure too, never a silent `exit $null`.
        assert!(line.contains("if ($null -eq $run -or $null -eq $run.ExitCode)"));
        assert!(line.ends_with("exit $run.ExitCode"));
        assert!(!line.contains('"'));
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
    fn the_encoded_command_is_base64_of_utf16() {
        assert_eq!(encoded_command("dir"), "ZABpAHIA");
        assert_eq!(encoded_command("Hi"), "SABpAA==");
        assert_eq!(encoded_command("A"), "QQA=");
        assert_eq!(encoded_command(""), "");
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
            removal(&copy, Platform::Windows).shown,
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
                &[]
            ),
            vec![]
        );

        // A shim of the standalone package is another copy, owned by that package.
        let standalone = make("scoop/apps/open-pact/current/open-pact-client", "fictional");
        make(
            "scoop/shims/open-pact-client.shim",
            &format!("path = \"{}\"\n", standalone.display()),
        );
        let found = other_copies(&path, "open-pact-client", &[bundled], &[]);
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
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].brew, Some(root.join("brew-a/bin/brew")));
        assert_eq!(found[1].brew, Some(root.join("brew-b/bin/brew")));
        let second = removal(&found[1], Platform::Mac);
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
        let rescan = other_copies(&path, "open-pact-client", &[installed], &[]);
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
        let found = other_copies(&path, "open-pact-client", &[installed], &[]);
        assert_eq!(
            found,
            vec![
                OtherCopy::new(root.join("brew/bin/open-pact-client"), Source::Homebrew),
                OtherCopy::new(loose, Source::Other),
            ]
        );
    }
}
