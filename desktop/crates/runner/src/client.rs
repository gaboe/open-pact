//! Where the command line tool lives on this computer: the copy bundled with an app, the copy the
//! client app installs for the OS job, and the PATH entry that makes it work in a terminal.

use crate::{Runner, args, find_on_path};
use std::path::{Path, PathBuf};

pub fn cli_name() -> &'static str {
    if cfg!(windows) {
        "open-pact-client.exe"
    } else {
        "open-pact-client"
    }
}

pub fn installed_path() -> Result<PathBuf, String> {
    let base = if cfg!(windows) {
        dirs::data_local_dir().map(|p| p.join("open-pact"))
    } else {
        dirs::home_dir().map(|p| p.join(".local/bin"))
    };
    Ok(base
        .ok_or("Cannot find the user home directory")?
        .join(cli_name()))
}

/// The CLIs a desktop app may run, best first: the one bundled with this app, the one the client
/// app installs, and the one on PATH. The bundled one matches this app's version, so an older CLI
/// elsewhere never wins. Only files that exist.
pub fn cli_candidates(app: Option<&Path>) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let listed = [
        app.and_then(|app| bundled_path(app).ok()),
        installed_path().ok(),
        find_on_path(cli_name()),
    ];
    for path in listed.into_iter().flatten() {
        if path.is_file() && !found.contains(&path) {
            found.push(path);
        }
    }
    found
}

pub fn bundled_path(app: &Path) -> Result<PathBuf, String> {
    let parent = app.parent().ok_or("Cannot find the app folder")?;
    let adjacent = parent.join(cli_name());
    if adjacent.is_file() {
        return Ok(adjacent);
    }
    Ok(parent
        .parent()
        .ok_or("Cannot find Contents folder")?
        .join("Helpers")
        .join(cli_name()))
}

pub fn version(runner: &Runner, path: &Path) -> Result<String, String> {
    Ok(runner
        .run(path, &args(&["--version"]))?
        .stdout
        .trim()
        .into())
}

/// Orders `open-pact-client 0.6.0` style version lines. A prerelease sorts before its release.
pub(crate) fn version_key(text: &str) -> Option<(Vec<u64>, bool)> {
    let token = text.split_whitespace().last()?;
    let token = token.strip_prefix('v').unwrap_or(token);
    let token = token.split('+').next()?;
    let (core, prerelease) = match token.split_once('-') {
        Some((core, _)) => (core, true),
        None => (token, false),
    };
    let mut numbers = core
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    if numbers.len() < 3 {
        numbers.resize(3, 0);
    }
    Some((numbers, !prerelease))
}

pub fn install(runner: &Runner, bundled: &Path, destination: &Path) -> Result<(), String> {
    let wanted = version(runner, bundled)?;
    let parent = destination.parent().ok_or("Invalid install destination")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let temporary = temporary_path(destination);
    std::fs::copy(bundled, &temporary).map_err(|e| e.to_string())?;
    if version(runner, &temporary)? != wanted {
        let _ = std::fs::remove_file(&temporary);
        return Err("Installed CLI version does not match the bundled CLI".into());
    }
    if cfg!(windows) && destination.exists() {
        std::fs::remove_file(destination).map_err(|e| e.to_string())?;
    }
    std::fs::rename(temporary, destination).map_err(|e| e.to_string())
}

/// The staging name for a copy that will replace `destination`. It must not contain "install":
/// Windows Installer Detection treats such an unmanifested exe as a setup program and asks for elevation.
fn temporary_path(destination: &Path) -> PathBuf {
    destination.with_extension("new")
}

#[cfg(unix)]
pub fn terminal_path(profile: &Path, directory: &Path) -> Result<(), String> {
    use std::io::Write;
    let existing = match std::fs::read_to_string(profile) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.to_string()),
    };
    let quoted = directory.to_string_lossy().replace('\'', "'\\''");
    let line = format!("export PATH='{quoted}':\"$PATH\"");
    if existing.lines().any(|row| row == line) {
        return Ok(());
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(profile)
        .map_err(|e| e.to_string())?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(file).map_err(|e| e.to_string())?;
    }
    writeln!(file, "{line}").map_err(|e| e.to_string())
}

/// zsh reads ~/.zprofile. A login bash reads ~/.bash_profile when it exists and skips ~/.profile.
pub fn profile_name(shell: &str, home: &Path) -> &'static str {
    if shell.ends_with("zsh") {
        ".zprofile"
    } else if home.join(".bash_profile").exists() {
        ".bash_profile"
    } else {
        ".profile"
    }
}

pub fn enable_terminal(destination: &Path) -> Result<(), String> {
    let directory = destination.parent().ok_or("Invalid CLI location")?;
    #[cfg(unix)]
    {
        let home = dirs::home_dir().ok_or("Cannot locate the home directory")?;
        let shell = std::env::var("SHELL").unwrap_or_default();
        terminal_path(&home.join(profile_name(&shell, &home)), directory)
    }
    #[cfg(windows)]
    {
        use winreg::{HKCU, RegValue, enums::REG_EXPAND_SZ, types::ToRegValue};
        let (environment, _) = HKCU
            .create_subkey("Environment")
            .map_err(|e| e.to_string())?;
        let original: String = match environment.get_value("Path") {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.to_string()),
        };
        let directory = directory.to_string_lossy();
        if original
            .split(';')
            .any(|part| part.eq_ignore_ascii_case(&directory))
        {
            return Ok(());
        }
        let kind = environment
            .get_raw_value("Path")
            .map(|value| value.vtype)
            .unwrap_or(REG_EXPAND_SZ);
        let path_value = format!("{directory};{original}");
        let value = path_value.to_reg_value();
        environment
            .set_raw_value(
                "Path",
                &RegValue {
                    bytes: value.bytes,
                    vtype: kind,
                },
            )
            .map_err(|e| e.to_string())?;
        broadcast_environment_change();
        Ok(())
    }
}

/// Tells Explorer and new terminals to reread the user environment.
#[cfg(windows)]
fn broadcast_environment_change() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn SendMessageTimeoutW(
            window: isize,
            message: u32,
            wparam: usize,
            lparam: isize,
            flags: u32,
            timeout: u32,
            result: *mut usize,
        ) -> isize;
    }
    const HWND_BROADCAST: isize = 0xffff;
    const WM_SETTINGCHANGE: u32 = 0x001a;
    const SMTO_ABORTIFHUNG: u32 = 0x0002;
    let name: Vec<u16> = "Environment\0".encode_utf16().collect();
    let mut result = 0usize;
    // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call, and `result` is a
    // valid pointer for the duration of the call.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            name.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            5000,
            &mut result,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_name_has_no_install_word() {
        for destination in [
            Path::new(cli_name()),
            Path::new("C:/Users/Ana/AppData/Local/open-pact/open-pact-client.exe"),
            Path::new("/home/ana/.local/bin/open-pact-client"),
        ] {
            let staged = temporary_path(destination);
            let name = staged.file_name().unwrap().to_string_lossy().to_lowercase();
            assert!(
                !name.contains("install"),
                "staging name {name} contains install"
            );
        }
    }
}
