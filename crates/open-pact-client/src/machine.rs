//! The machine client: the one copy of the client that a per-machine package installs under
//! Program Files. The SYSTEM job runs it, and only it. No client copies itself there.
//!
//! The protection boundary is the administrator-only path, not the package. A protected file at
//! that path counts, whoever installed it, and every text calls it "the machine client at <path>".

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use semver::Version;
use serde::Serialize;

use crate::schedule::{ASSERT_PROTECTED, apply_command, powershell_literal};

/// The repository whose release workflow signs the package. A constant, never an environment value.
const REPOSITORY: &str = "gaboe/open-pact";
const COSIGN_URL: &str =
    "https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-windows-amd64.exe";
/// SHA-256 of `cosign-windows-amd64.exe` of Cosign v3.0.6, as its release checksums list it.
const COSIGN_SHA256: &str = "9b85a88ebff2d9dd30ff4984a6f61f2cedc232dd87d81fa7f2ff3c0ed96c241c";
const MSI_NAME: &str = "open-pact-client-x86_64-pc-windows-msvc.msi";
const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The release after the first merge flips this, when the package is in the winget community
/// repository. Until then no text names winget.
const WINGET_PUBLISHED: bool = false;

const MACHINE_FOLDER: &str = "open-pact-client";
const MACHINE_FILE: &str = "open-pact-client.exe";

/// The machine client, read without elevation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MachineClient {
    /// No file at the machine path.
    Missing,
    /// The ACL check failed on Program Files, the folder or the file.
    Unprotected { reason: String },
    /// Protected, and `--version` printed a version.
    Present { version: Version },
    /// The probe or `--version` failed.
    Unknown { reason: String },
}

/// What `status --json` reports as `schedule.machine_client`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineState {
    Missing,
    Unprotected,
    Unknown,
    Outdated,
    Current,
}

impl MachineState {
    /// The protection check passed and `--version` answered. Only then may a text name the machine
    /// client in a line that an administrator runs.
    pub(crate) fn usable(self) -> bool {
        matches!(self, Self::Current | Self::Outdated)
    }

    /// Whether an administrator can run the machine client after the package fix of this state: the
    /// machine client is usable, or the fix is an install block that puts a verified one in place.
    /// An unprotected or unreadable one stays unusable after a fix that only describes it.
    pub(crate) fn usable_after_fix(self) -> bool {
        self.usable() || self == Self::Missing
    }
}

/// The machine client compared with the running client. A running client older than the machine
/// client is no problem: the job runs the newer one.
pub(crate) fn machine_state(machine: &MachineClient, running: &Version) -> MachineState {
    match machine {
        MachineClient::Missing => MachineState::Missing,
        MachineClient::Unprotected { .. } => MachineState::Unprotected,
        MachineClient::Unknown { .. } => MachineState::Unknown,
        MachineClient::Present { version } if version.cmp_precedence(running).is_lt() => {
            MachineState::Outdated
        }
        MachineClient::Present { .. } => MachineState::Current,
    }
}

/// The version of this client.
pub(crate) fn running_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("the crate version is a semantic version")
}

/// The path of the machine client in `program_files`.
pub(crate) fn machine_executable_in(program_files: &Path) -> PathBuf {
    program_files.join(MACHINE_FOLDER).join(MACHINE_FILE)
}

/// The path of the machine client: Q, under the Program Files folder that Windows names.
pub fn machine_executable() -> Result<PathBuf> {
    Ok(machine_executable_in(&known_folder(Known::ProgramFiles)?))
}

/// Q, or an empty path where Windows does not say. An empty path never equals a running image.
pub(crate) fn machine_path() -> PathBuf {
    machine_executable().unwrap_or_default()
}

enum Known {
    ProgramFiles,
    System,
}

#[cfg(windows)]
fn known_folder(which: Known) -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramFiles, FOLDERID_System, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };

    let id = match which {
        Known::ProgramFiles => &FOLDERID_ProgramFiles,
        Known::System => &FOLDERID_System,
    };
    let mut raw: *mut u16 = std::ptr::null_mut();
    // SAFETY: `id` points at a constant GUID and `raw` at a local. On success Windows gives back
    // a NUL-terminated string. This function copies it and frees it with `CoTaskMemFree`.
    let path = unsafe {
        let status =
            SHGetKnownFolderPath(id, KF_FLAG_DEFAULT as u32, std::ptr::null_mut(), &mut raw);
        if status < 0 {
            CoTaskMemFree(raw.cast());
            None
        } else {
            let mut length = 0;
            while *raw.add(length) != 0 {
                length += 1;
            }
            let path = PathBuf::from(std::ffi::OsString::from_wide(std::slice::from_raw_parts(
                raw, length,
            )));
            CoTaskMemFree(raw.cast());
            Some(path)
        }
    };
    path.ok_or_else(|| anyhow::anyhow!("Windows did not name a known folder"))
}

#[cfg(not(windows))]
fn known_folder(which: Known) -> Result<PathBuf> {
    let _ = which;
    bail!("the machine client exists only on Windows")
}

/// The `schtasks.exe` of the system folder. A bare name would let a copy in the current folder run first.
pub(crate) fn system_schtasks() -> PathBuf {
    known_folder(Known::System)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32"))
        .join("schtasks.exe")
}

/// The Windows PowerShell of the system folder. Every start of PowerShell uses this path, so a
/// `powershell.exe` in the current folder or on `PATH` never runs.
pub(crate) fn system_powershell() -> PathBuf {
    static PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        known_folder(Known::System)
            .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32"))
            .join(r"WindowsPowerShell\v1.0\powershell.exe")
    })
    .clone()
}

/// Whether two Windows paths name the same file: ignores case and a `\\?\` prefix.
pub(crate) fn same_windows_path(left: &Path, right: &Path) -> bool {
    let normal = |path: &Path| {
        let text = path.to_string_lossy().to_lowercase();
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
    };
    normal(left) == normal(right)
}

/// The PowerShell that checks Program Files, the folder and the file of `machine`, and prints
/// `missing`, `present` or `unprotected: <reason>`.
pub(crate) fn machine_probe_script(machine: &Path) -> Result<String> {
    let literal = powershell_literal(path_text(machine)?);
    Ok(format!(
        r#"{ASSERT_PROTECTED}
$machine = {literal}
if (-not (Test-Path -LiteralPath $machine -PathType Leaf)) {{ Write-Output 'missing'; return }}
$folder = Split-Path -Parent $machine
try {{
    AssertProtected (Split-Path -Parent $folder)
    AssertProtected $folder
    AssertProtected $machine
    Write-Output 'present'
}} catch {{ Write-Output ('unprotected: ' + $_.Exception.Message) }}
"#
    ))
}

fn path_text(path: &Path) -> Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("a Windows path must be UTF-8"))?;
    if text.chars().any(char::is_control) {
        bail!("a path must not hold a control character");
    }
    Ok(text)
}

/// The machine client from what the probe printed and what `--version` printed.
fn machine_client_from(
    probe: Result<String>,
    version: impl FnOnce() -> Result<String>,
) -> MachineClient {
    let probe = match probe {
        Ok(probe) => probe,
        Err(error) => {
            return MachineClient::Unknown {
                reason: format!("{error:#}"),
            };
        }
    };
    match probe.lines().next().map(str::trim) {
        Some("missing") => MachineClient::Missing,
        Some("present") => match version().and_then(|output| parse_version(&output)) {
            Ok(version) => MachineClient::Present { version },
            Err(error) => MachineClient::Unknown {
                reason: format!("{error:#}"),
            },
        },
        Some(line) if line.starts_with("unprotected:") => MachineClient::Unprotected {
            reason: line["unprotected:".len()..].trim().to_owned(),
        },
        _ => MachineClient::Unknown {
            reason: "the check printed no answer".into(),
        },
    }
}

/// The version in the output of `open-pact-client --version`: the last word of its first line.
fn parse_version(output: &str) -> Result<Version> {
    let word = output
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().last())
        .ok_or_else(|| anyhow::anyhow!("`--version` printed nothing"))?;
    Ok(Version::parse(word)?)
}

// How many times this thread read the machine client, for the tests that must show that a local
// report starts no process.
#[cfg(test)]
thread_local! {
    pub(crate) static PROBES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Reads the machine client. One PowerShell start for the protection, then `Q --version`.
pub(crate) fn read_machine_client() -> MachineClient {
    #[cfg(test)]
    PROBES.with(|probes| probes.set(probes.get() + 1));
    let machine = match machine_executable() {
        Ok(machine) => machine,
        Err(error) => {
            return MachineClient::Unknown {
                reason: format!("{error:#}"),
            };
        }
    };
    let probe = machine_probe_script(&machine)
        .and_then(|script| crate::schedule::windows_powershell(&script));
    machine_client_from(probe, || {
        let mut command = std::process::Command::new(&machine);
        command.arg("--version");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let output = command.output()?;
        if !output.status.success() {
            bail!("`--version` failed with code {:?}", output.status.code());
        }
        Ok(String::from_utf8(output.stdout)?)
    })
}

/// One entry of `HKLM\...\ProfileList`: the SID of an account and its `ProfileImagePath`, with the
/// environment variables expanded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProfileEntry {
    pub(crate) sid: String,
    pub(crate) path: PathBuf,
}

/// What Windows says about profiles: the SID of the token of the running process and the entries of
/// the user accounts. Only a local, domain or Entra account is an entry, not SYSTEM or a service
/// account.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProfileList {
    pub(crate) own_sid: Option<String>,
    pub(crate) entries: Vec<ProfileEntry>,
}

impl ProfileList {
    /// The profile folder of the account that owns the token of the running process.
    fn own_profile(&self) -> Option<PathBuf> {
        let own = self.own_sid.as_deref()?;
        self.entries
            .iter()
            .find(|entry| entry.sid.eq_ignore_ascii_case(own))
            .map(|entry| entry.path.clone())
    }

    /// The list from the lines that `PROFILE_LIST_SCRIPT` printed: `own <sid>` once, and
    /// `entry <sid> <path>` for each account.
    #[cfg(any(windows, test))]
    fn parse(output: &str) -> Self {
        let mut list = Self::default();
        for line in output.lines().map(str::trim) {
            if let Some(sid) = line.strip_prefix("own ") {
                list.own_sid = Some(sid.trim().to_owned());
            } else if let Some(rest) = line.strip_prefix("entry ")
                && let Some((sid, path)) = rest.split_once(' ')
                && !path.trim().is_empty()
            {
                list.entries.push(ProfileEntry {
                    sid: sid.to_owned(),
                    path: PathBuf::from(path.trim()),
                });
            }
        }
        list
    }
}

/// The owner's profile that a SYSTEM job reads: an absolute path to a folder that exists, with no
/// `%` and no control character, that is not a link, and that Windows lists as the profile of a
/// user account. A user chooses `USERPROFILE` and the arguments of a task, so neither is a source.
///
/// Only a path that needs a SYSTEM profile comes here, because on Windows the list costs a start of
/// PowerShell.
pub(crate) fn validate_user_home(path: &Path) -> Result<PathBuf> {
    validate_user_home_in(path, registered_profiles()?.as_ref())
}

/// `validate_user_home` against the `profiles` that were read, or against none on a system
/// without the list.
fn validate_user_home_in(path: &Path, profiles: Option<&ProfileList>) -> Result<PathBuf> {
    let text = path_text(path)?;
    if text.contains('%') {
        bail!("the user home must not contain %");
    }
    if !path.is_absolute() {
        bail!("the user home must be an absolute path");
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| anyhow::anyhow!("the user home is not a folder that exists"))?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        bail!("the user home must not be a link");
    }
    if !metadata.is_dir() {
        bail!("the user home is not a folder that exists");
    }
    if let Some(profiles) = profiles
        && !profiles
            .entries
            .iter()
            .any(|entry| same_windows_path(&entry.path, path))
    {
        bail!("the user home is not the profile of a user account");
    }
    Ok(path.to_path_buf())
}

/// The profile that a SYSTEM job reads when no `--user-home` names one: the `ProfileImagePath` of
/// the SID of the token of this process. `USERPROFILE` is the caller's own word, and a standard
/// user can point it at the profile of another account, so it is never the source on Windows.
pub fn default_user_home() -> Option<PathBuf> {
    match registered_profiles() {
        Ok(Some(list)) => list.own_profile(),
        Ok(None) => crate::user_profile(),
        Err(_) => None,
    }
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// The PowerShell that prints the token SID of the process and the profile folders of the user
/// accounts of `ProfileList`.
#[cfg(any(windows, test))]
const PROFILE_LIST_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
Write-Output ('own ' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
    Where-Object { $_.PSChildName -like 'S-1-5-21-*' -or $_.PSChildName -like 'S-1-12-1-*' } |
    ForEach-Object { $path = [string]$_.GetValue('ProfileImagePath'); if ($path) { Write-Output ('entry ' + $_.PSChildName + ' ' + [Environment]::ExpandEnvironmentVariables($path)) } }"#;

// The profile list of this thread's tests. Without a list, nothing is a profile, as on a Windows
// runner whose temporary folders are no account's profile.
#[cfg(test)]
thread_local! {
    static TEST_PROFILES: std::cell::RefCell<ProfileList> =
        std::cell::RefCell::new(ProfileList::default());
}

/// Puts `paths` in the profile list of this thread until the guard drops. The first path is the
/// profile of the token of the process.
#[cfg(test)]
pub(crate) fn list_profiles(paths: &[&Path]) -> ProfileGuard {
    let list = ProfileList {
        own_sid: paths.first().map(|_| "S-1-5-21-1-1-1-1000".to_owned()),
        entries: paths
            .iter()
            .enumerate()
            .map(|(index, path)| ProfileEntry {
                sid: format!("S-1-5-21-1-1-1-{}", 1000 + index),
                path: path.to_path_buf(),
            })
            .collect(),
    };
    ProfileGuard(TEST_PROFILES.with(|profiles| profiles.replace(list)))
}

#[cfg(test)]
pub(crate) struct ProfileGuard(ProfileList);

#[cfg(test)]
impl Drop for ProfileGuard {
    fn drop(&mut self) {
        TEST_PROFILES.with(|profiles| profiles.replace(std::mem::take(&mut self.0)));
    }
}

// How many times this thread read the profile list, for the tests that show a command that needs
// no SYSTEM profile reads none.
#[cfg(test)]
thread_local! {
    pub(crate) static PROFILE_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn registered_profiles() -> Result<Option<ProfileList>> {
    PROFILE_READS.with(|reads| reads.set(reads.get() + 1));
    Ok(Some(
        TEST_PROFILES.with(|profiles| profiles.borrow().clone()),
    ))
}

/// The profiles of this machine, from `HKLM\...\ProfileList`, read once per process. `None` where
/// Windows keeps no such list.
#[cfg(all(windows, not(test)))]
fn registered_profiles() -> Result<Option<ProfileList>> {
    static LIST: std::sync::OnceLock<std::result::Result<ProfileList, String>> =
        std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        crate::schedule::windows_powershell(PROFILE_LIST_SCRIPT)
            .map(|output| ProfileList::parse(&output))
            .map_err(|error| format!("{error:#}"))
    })
    .clone()
    .map(Some)
    .map_err(|error| anyhow::anyhow!(error))
}

#[cfg(all(not(windows), not(test)))]
fn registered_profiles() -> Result<Option<ProfileList>> {
    Ok(None)
}

/// The install block, for an elevated Windows PowerShell 5.1 (`powershell.exe`). The .NET Framework
/// overloads that it uses do not exist in PowerShell 7, so the block stops there before it does
/// anything, and every text that offers it says so. It makes an administrator-only folder
/// with a name that no text predicts, checks that folder, downloads the package and a pinned Cosign
/// into it, verifies the signature and the hash, and installs with System32 `msiexec.exe`. The
/// folder stays, because Windows Installer repairs from it. The same block installs, upgrades and
/// reinstalls.
pub(crate) fn install_block(version: &Version) -> String {
    let tag = format!("v{version}");
    let base = format!("https://github.com/{REPOSITORY}/releases/download/{tag}");
    let identity = format!(
        "https://github.com/{REPOSITORY}/.github/workflows/client-release.yml@refs/tags/{tag}"
    );
    INSTALL_TEMPLATE
        .replace("@ASSERT_PROTECTED@", ASSERT_PROTECTED.trim())
        .replace("@BASE@", &powershell_literal(&base))
        .replace("@MSI@", &powershell_literal(MSI_NAME))
        .replace("@COSIGN_URL@", &powershell_literal(COSIGN_URL))
        .replace("@COSIGN_SHA256@", &powershell_literal(COSIGN_SHA256))
        .replace("@IDENTITY@", &powershell_literal(&identity))
        .replace("@ISSUER@", &powershell_literal(OIDC_ISSUER))
}

const INSTALL_TEMPLATE: &str = r#"& {
if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Run this block in Windows PowerShell 5.1: start powershell.exe as administrator, not pwsh.' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
@ASSERT_PROTECTED@
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this block from an elevated Windows PowerShell 5.1 prompt (powershell.exe).' }
$base = @BASE@
$msiName = @MSI@
$folder = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('open-pact-install-' + [guid]::NewGuid())
if (Test-Path -LiteralPath $folder) { throw 'The install folder exists. Run this block again.' }
$security = New-Object Security.AccessControl.DirectorySecurity
$security.SetAccessRuleProtection($true, $false)
$security.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $account = New-Object Security.Principal.SecurityIdentifier($sid)
    $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($account, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
[void][IO.Directory]::CreateDirectory($folder, $security)
AssertProtected $folder
foreach ($name in @($msiName, 'SHA256SUMS', 'SHA256SUMS.sigstore.json')) {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile (Join-Path $folder $name)
}
$cosign = Join-Path $folder 'cosign.exe'
Invoke-WebRequest -UseBasicParsing -Uri @COSIGN_URL@ -OutFile $cosign
if ((Get-FileHash -LiteralPath $cosign -Algorithm SHA256).Hash -ne @COSIGN_SHA256@) { throw 'cosign.exe does not match its pinned hash.' }
$sums = Join-Path $folder 'SHA256SUMS'
& $cosign verify-blob --bundle (Join-Path $folder 'SHA256SUMS.sigstore.json') --certificate-identity @IDENTITY@ --certificate-oidc-issuer @ISSUER@ $sums
if ($LASTEXITCODE -ne 0) { throw 'Cosign could not verify SHA256SUMS.' }
$lines = @(Get-Content -LiteralPath $sums | Where-Object { $_ -match '\S' -and (($_ -split '\s+', 2)[1].TrimStart('*') -eq $msiName) })
if ($lines.Count -ne 1) { throw 'SHA256SUMS must list the package once.' }
$msi = Join-Path $folder $msiName
if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ne ($lines[0] -split '\s+')[0]) { throw 'The package does not match SHA256SUMS.' }
$log = Join-Path $folder 'install.log'
$msiexec = Join-Path ([Environment]::SystemDirectory) 'msiexec.exe'
$install = Start-Process -FilePath $msiexec -ArgumentList ('/i "' + $msi + '" /qn /norestart /l*v "' + $log + '"') -Wait -PassThru
Write-Output ('msiexec exit code: ' + $install.ExitCode)
if ($install.ExitCode -eq 3010) { Write-Output 'Restart Windows to finish the install.' }
elseif ($install.ExitCode -ne 0) { throw ('The install failed. See ' + $log) }
}"#;

/// The winget line for IT deployments, once the package is published there.
fn winget_line() -> Option<&'static str> {
    WINGET_PUBLISHED.then_some(
        "For IT deployment, deploy the verified MSI with your deployment tool. Microsoft does not support the winget command-line tool as SYSTEM, even when Intune or Group Policy starts it.",
    )
}

/// The block that removes the SYSTEM task of `home` with Windows tools, for an elevated prompt. It
/// has no `Remove-Item`. With the machine client at `machine`, its last lines check that the file
/// exists, run `schedule off`, which waits for the state lock and removes the state folder, and throw
/// when the file is missing or the command fails, so the reader never uninstalls the package after a
/// failed cleanup. The client never runs these lines
/// itself.
pub(crate) fn removal_block(home: &Path, task_id: &str, machine: Option<&Path>) -> String {
    let id = powershell_literal(task_id);
    let task_path = if task_id.starts_with('\\') {
        task_id.to_owned()
    } else {
        format!("\\{task_id}")
    };
    let path = powershell_literal(&task_path);
    // The home goes in a single-quoted here-string, so an apostrophe in it needs no escape. The
    // check for the file and the reset of the exit code keep a missing client from passing as success.
    let last = machine
        .map(|machine| {
            format!(
                "\n  $q = {}\n  if (-not (Test-Path -LiteralPath $q -PathType Leaf)) {{ throw 'The machine client is missing. Install the package, then run this block again.' }}\n  $clientHome = @'\n{}\n'@\n  $global:LASTEXITCODE = $null\n  & $q --home $clientHome schedule off\n  if ($LASTEXITCODE -ne 0) {{ throw 'schedule off failed. Do not uninstall the package. Fix the error, then run this block again.' }}",
                powershell_literal(&machine.to_string_lossy()),
                home.to_string_lossy()
            )
        })
        .unwrap_or_default();
    let mut text = format!(
        r#"& {{
  $schtasks = Join-Path ([Environment]::SystemDirectory) 'schtasks.exe'
  function Test-TaskRegistered {{
    # The Task Scheduler COM API reports a missing task as HRESULT 0x80070002, in every display language.
    $service = New-Object -ComObject Schedule.Service
    $service.Connect()
    try {{
      [void]$service.GetFolder('\').GetTask({path})
      return $true
    }} catch {{
      $e = $_.Exception
      while ($e.InnerException) {{ $e = $e.InnerException }}
      if ($e.HResult -eq -2147024894) {{ return $false }}
      throw ('Could not query the task. ' + $_)
    }}
  }}
  function End-TaskQuietly {{
    # /End fails for a task that is not running. That does not matter here: /Delete decides.
    $ErrorActionPreference = 'Continue'
    & $schtasks /End /TN {id} 2>$null | Out-Null
  }}
  if (Test-TaskRegistered) {{
    End-TaskQuietly
    & $schtasks /Delete /TN {id} /F
    if ($LASTEXITCODE -ne 0) {{ throw 'The task was not removed. Run this block again from an elevated prompt.' }}
  }}
  if (Test-TaskRegistered) {{ throw 'The task is still registered. Run this block again.' }}{last}
}}"#
    );
    if machine.is_none() {
        text.push_str(&format!(
            "\nThe state folder {} stays. The next `schedule on --system` resets it.",
            system_state_folder(home).display()
        ));
    }
    let program_files = machine
        .and_then(|machine| machine.parent()?.parent())
        .map(Path::to_path_buf)
        .or_else(|| known_folder(Known::ProgramFiles).ok())
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    text.push_str(&format!(
        "\nThe old copy in {} stays. Remove that folder after you removed every open-pact SYSTEM task on this device.",
        program_files.join("open-pact").display()
    ));
    text
}

/// `<ProgramData>\open-pact\system\<sha256(home)>`, where the SYSTEM job keeps its state.
fn system_state_folder(home: &Path) -> PathBuf {
    use sha2::{Digest, Sha256};
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    program_data
        .join("open-pact")
        .join("system")
        .join(hex::encode(Sha256::digest(
            home.to_string_lossy().as_bytes(),
        )))
}

/// The command that runs `change` through the machine client at `machine`. `profile` is the owner's
/// profile when the caller knows it.
pub(crate) fn machine_command(
    home: &Path,
    change: &str,
    machine: &Path,
    profile: Option<&Path>,
) -> String {
    let mut command = apply_command(home, change, machine);
    if let Some(profile) = profile {
        command.push_str(&format!(
            " --user-home {}",
            powershell_literal(&profile.to_string_lossy())
        ));
    }
    command
}

/// The fix for a machine client that is not current, with the install block first. Nothing when
/// the machine client is current.
pub(crate) fn machine_fix(
    machine: &MachineClient,
    state: MachineState,
    path: &Path,
    running: &Version,
) -> Option<String> {
    let block = || {
        let mut text = install_block(running);
        if let Some(line) = winget_line() {
            text.push('\n');
            text.push_str(line);
        }
        text
    };
    match (state, machine) {
        (MachineState::Current, _) => None,
        (MachineState::Missing, _) => Some(format!(
            "The machine client is not installed at {}. Install it from an elevated Windows PowerShell 5.1 prompt (powershell.exe, not pwsh):\n{}",
            path.display(),
            block()
        )),
        (MachineState::Unprotected, MachineClient::Unprotected { reason }) => Some(format!(
            "{} is not protected ({reason}). Ask IT, or uninstall the machine client and install it again with this block:\n{}",
            path.display(),
            block()
        )),
        (MachineState::Outdated, MachineClient::Present { version }) => Some(format!(
            "The machine client at {} is version {version}, and this client is version {running}. Upgrade it from an elevated Windows PowerShell 5.1 prompt (powershell.exe, not pwsh):\n{}\nIf you just installed an update, restart Windows.",
            path.display(),
            block()
        )),
        (_, MachineClient::Unknown { reason }) => {
            Some(format!("Cannot read the machine client: {reason}."))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    fn state(machine: &MachineClient, running: &str) -> MachineState {
        machine_state(machine, &version(running))
    }

    #[test]
    fn the_package_state_follows_the_machine_client_and_the_running_version() {
        let present = |text: &str| MachineClient::Present {
            version: version(text),
        };
        assert_eq!(
            state(&MachineClient::Missing, "0.9.0"),
            MachineState::Missing
        );
        assert_eq!(
            state(&MachineClient::Unprotected { reason: "x".into() }, "0.9.0"),
            MachineState::Unprotected
        );
        assert_eq!(
            state(&MachineClient::Unknown { reason: "x".into() }, "0.9.0"),
            MachineState::Unknown
        );
        assert_eq!(state(&present("0.8.9"), "0.9.0"), MachineState::Outdated);
        assert_eq!(state(&present("0.9.0"), "0.9.0"), MachineState::Current);
        // A running client older than the machine client is no problem.
        assert_eq!(state(&present("0.9.1"), "0.9.0"), MachineState::Current);
        // A prerelease is below its release, and build metadata counts for nothing.
        assert_eq!(
            state(&present("0.9.0-rc.1"), "0.9.0"),
            MachineState::Outdated
        );
        assert_eq!(
            state(&present("0.9.0"), "0.9.0-rc.1"),
            MachineState::Current
        );
        assert_eq!(
            state(&present("0.9.0+build.5"), "0.9.0"),
            MachineState::Current
        );
        assert_eq!(
            serde_json::to_value(MachineState::Unprotected).unwrap(),
            serde_json::json!("unprotected")
        );
    }

    #[test]
    fn the_machine_client_is_read_from_the_probe_and_its_version() {
        let ok = || Ok("open-pact-client 0.9.0\n".to_owned());
        let from = |probe: &str| machine_client_from(Ok(probe.to_owned()), ok);
        assert_eq!(from("missing"), MachineClient::Missing);
        assert_eq!(
            from("present"),
            MachineClient::Present {
                version: version("0.9.0")
            }
        );
        assert_eq!(
            from("unprotected: Protected path ACL grants write or modify to a non-admin principal"),
            MachineClient::Unprotected {
                reason: "Protected path ACL grants write or modify to a non-admin principal".into()
            }
        );
        assert!(matches!(from(""), MachineClient::Unknown { .. }));
        assert!(matches!(from("garbage"), MachineClient::Unknown { .. }));
        assert!(matches!(
            machine_client_from(Err(anyhow::anyhow!("blocked")), ok),
            MachineClient::Unknown { reason } if reason == "blocked"
        ));
        for version_output in ["", "open-pact-client", "open-pact-client not-a-version"] {
            let client = machine_client_from(Ok("present".into()), || Ok(version_output.into()));
            assert!(
                matches!(client, MachineClient::Unknown { .. }),
                "{version_output}"
            );
        }
        assert!(matches!(
            machine_client_from(Ok("present".into()), || bail!("did not start")),
            MachineClient::Unknown { .. }
        ));
        // A missing client never starts the version command.
        assert_eq!(
            machine_client_from(Ok("missing".into()), || panic!(
                "no process for a missing file"
            )),
            MachineClient::Missing
        );
    }

    #[test]
    fn the_probe_checks_the_three_paths_with_the_literal_machine_path() {
        let script =
            machine_probe_script(Path::new(r"C:\Program Files\it's\open-pact-client.exe")).unwrap();
        assert!(script.contains(r"$machine = 'C:\Program Files\it''s\open-pact-client.exe'"));
        let program = script
            .find("AssertProtected (Split-Path -Parent $folder)")
            .unwrap();
        let folder = script.find("AssertProtected $folder").unwrap();
        let file = script.find("AssertProtected $machine").unwrap();
        assert!(program < folder && folder < file);
        assert!(
            script.contains("Write-Output 'missing'") && script.contains("Write-Output 'present'")
        );
    }

    #[test]
    fn the_machine_path_is_the_new_folder_under_program_files() {
        assert_eq!(
            machine_executable_in(Path::new(r"C:\Program Files")),
            Path::new(r"C:\Program Files")
                .join("open-pact-client")
                .join("open-pact-client.exe")
        );
        assert!(system_powershell().ends_with(r"WindowsPowerShell\v1.0\powershell.exe"));
        assert!(system_powershell().is_absolute() || !cfg!(windows));
    }

    #[test]
    fn version_output_names_the_version_in_its_last_word() {
        assert_eq!(
            parse_version("open-pact-client 0.9.0-rc.1\n").unwrap(),
            version("0.9.0-rc.1")
        );
        assert!(parse_version("").is_err());
    }

    #[test]
    fn windows_paths_compare_without_case_and_extended_prefix() {
        let protected = Path::new(r"C:\Program Files\open-pact-client\open-pact-client.exe");
        assert!(same_windows_path(
            Path::new(r"\\?\c:\program files\Open-Pact-Client\open-pact-client.exe"),
            protected
        ));
        assert!(!same_windows_path(
            Path::new(r"C:\Users\a\open-pact-client.exe"),
            protected
        ));
        assert!(!same_windows_path(
            Path::new(r"C:\Program Files\open-pact\open-pact-client.exe"),
            protected
        ));
    }

    #[test]
    fn a_profile_must_be_an_absolute_existing_folder_without_percent_or_control_characters() {
        let dir = tempfile::tempdir().unwrap();
        let percent = dir.path().join("%TEMP%");
        std::fs::create_dir(&percent).unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        let _listed = list_profiles(&[dir.path(), &percent, &file]);
        assert_eq!(validate_user_home(dir.path()).unwrap(), dir.path());
        assert!(validate_user_home(&dir.path().join("missing")).is_err());
        assert!(validate_user_home(Path::new("relative")).is_err());
        assert!(validate_user_home(&file).is_err());
        assert!(validate_user_home(&percent).is_err());
        assert!(validate_user_home(Path::new("/tmp/a\nb")).is_err());
    }

    #[test]
    fn a_profile_is_one_that_windows_lists_for_a_user_account_and_is_no_link() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("user");
        std::fs::create_dir(&profile).unwrap();
        let listed = |paths: &[&Path]| {
            let entries = paths
                .iter()
                .map(|path| ProfileEntry {
                    sid: "S-1-5-21-1-1-1-1000".into(),
                    path: path.to_path_buf(),
                })
                .collect();
            ProfileList {
                own_sid: None,
                entries,
            }
        };
        assert_eq!(
            validate_user_home_in(&profile, Some(&listed(&[&profile]))).unwrap(),
            profile
        );
        // Windows compares the paths without case.
        let loud = PathBuf::from(profile.to_string_lossy().to_uppercase());
        assert!(validate_user_home_in(&profile, Some(&listed(&[&loud]))).is_ok());
        // USERPROFILE and a task argument are the caller's words: a folder that is no listed
        // profile is refused, and so is an empty list.
        let other = dir.path().join("other");
        let error = validate_user_home_in(&profile, Some(&listed(&[&other]))).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not the profile of a user account")
        );
        assert!(validate_user_home_in(&profile, Some(&ProfileList::default())).is_err());
        // A system without the list (not Windows) has no second source.
        assert!(validate_user_home_in(&profile, None).is_ok());
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&profile, &link).unwrap();
            let error = validate_user_home_in(&link, None).unwrap_err();
            assert!(error.to_string().contains("must not be a link"), "{error}");
        }
    }

    #[test]
    fn the_default_profile_is_the_one_of_the_token_sid_and_never_userprofile() {
        let output = "own S-1-5-21-1-2-3-1001\r\n\
            entry S-1-5-21-1-2-3-1000 C:\\Users\\other\r\n\
            entry S-1-5-21-1-2-3-1001 C:\\Users\\my account\r\n\
            entry S-1-12-1-9 C:\\Users\\cloud\r\n\
            garbage\r\n\
            entry S-1-5-21-1-2-3-1002 \r\n";
        let list = ProfileList::parse(output);
        assert_eq!(list.own_sid.as_deref(), Some("S-1-5-21-1-2-3-1001"));
        assert_eq!(list.entries.len(), 3);
        // A standard user who sets USERPROFILE to the profile of another account changes nothing:
        // the answer comes from the SID.
        assert_eq!(
            list.own_profile(),
            Some(PathBuf::from(r"C:\Users\my account"))
        );
        assert_eq!(ProfileList::default().own_profile(), None);
        let unknown = ProfileList {
            own_sid: Some("S-1-5-21-9".into()),
            ..list
        };
        assert_eq!(unknown.own_profile(), None);
        // The one script reads both: the token SID and the list of user accounts.
        assert!(PROFILE_LIST_SCRIPT.contains("WindowsIdentity]::GetCurrent().User.Value"));
        assert!(
            PROFILE_LIST_SCRIPT.contains("S-1-5-21-*")
                && PROFILE_LIST_SCRIPT.contains("S-1-12-1-*")
        );
        assert!(!PROFILE_LIST_SCRIPT.contains("USERPROFILE"));
    }

    #[test]
    fn the_default_profile_in_a_test_comes_from_the_listed_profile_of_the_process() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other");
        {
            let _listed = list_profiles(&[dir.path(), &other]);
            assert_eq!(default_user_home(), Some(dir.path().to_path_buf()));
        }
        assert_eq!(default_user_home(), None);
    }

    #[test]
    fn only_a_machine_client_that_passed_its_protection_check_is_usable() {
        let usable: Vec<_> = [
            MachineState::Missing,
            MachineState::Unprotected,
            MachineState::Unknown,
            MachineState::Outdated,
            MachineState::Current,
        ]
        .into_iter()
        .map(|state| (state.usable(), state.usable_after_fix()))
        .collect();
        assert_eq!(
            usable,
            [
                (false, true),
                (false, false),
                (false, false),
                (true, true),
                (true, true)
            ]
        );
    }

    #[test]
    fn the_install_block_uses_full_path_tools_and_checks_before_it_trusts() {
        let block = install_block(&version("0.9.0"));
        // The folder name comes from a run-time GUID, in an administrator-only folder that is checked
        // before the first download.
        assert!(block.contains("[guid]::NewGuid()"));
        assert!(block.contains("Test-Path -LiteralPath $folder"));
        assert!(block.contains("[IO.Directory]::CreateDirectory($folder, $security)"));
        assert!(block.contains("$security.SetAccessRuleProtection($true, $false)"));
        let check = block.find("AssertProtected $folder").unwrap();
        assert!(check < block.find("Invoke-WebRequest").unwrap());
        assert!(block.contains("function AssertProtected"));
        // Cosign is pinned by hash, then it verifies the sums with the exact identity.
        assert!(block.contains(&format!("-ne '{COSIGN_SHA256}'")));
        assert!(block.find(COSIGN_SHA256).unwrap() < block.find("verify-blob").unwrap());
        assert!(block.contains(
            "--certificate-identity 'https://github.com/gaboe/open-pact/.github/workflows/client-release.yml@refs/tags/v0.9.0'"
        ));
        assert!(
            block.contains(
                "--certificate-oidc-issuer 'https://token.actions.githubusercontent.com'"
            )
        );
        assert!(
            block.contains(
                "if ($LASTEXITCODE -ne 0) { throw 'Cosign could not verify SHA256SUMS.' }"
            )
        );
        assert!(block.contains("releases/download/v0.9.0'"));
        // The package hash is checked against its SHA256SUMS line before msiexec runs.
        assert!(
            block.find("The package does not match SHA256SUMS").unwrap()
                < block.find("msiexec").unwrap()
        );
        // msiexec and every other tool start by full path; nothing starts by bare name.
        assert!(block.contains("Join-Path ([Environment]::SystemDirectory) 'msiexec.exe'"));
        assert!(block.contains("/qn /norestart /l*v"));
        assert!(!block.contains("& msiexec") && !block.contains("& powershell"));
        // PowerShell 7 lacks the .NET overloads of the block, so the block stops there at its
        // first line and names the program to start instead.
        assert!(
            block
                .lines()
                .nth(1)
                .unwrap()
                .contains("PSEdition -eq 'Core'")
        );
        assert!(block.contains("start powershell.exe as administrator, not pwsh"));
        assert!(block.contains("-eq 3010") && block.contains("Restart Windows"));
        assert!(block.starts_with("& {") && block.ends_with('}'));
        // It never installs from a folder that a name predicts.
        assert!(!block.contains("open-pact-install-0"));
        // The upgrade and the reinstall are the same block for the same version.
        assert_eq!(block, install_block(&version("0.9.0")));
        assert_ne!(block, install_block(&version("0.9.1")));
    }

    #[test]
    fn the_install_block_for_a_prerelease_names_its_tag() {
        let block = install_block(&version("0.9.0-rc.1"));
        assert!(block.contains("refs/tags/v0.9.0-rc.1"));
        assert!(block.contains("releases/download/v0.9.0-rc.1"));
    }

    #[test]
    fn the_removal_block_passes_only_a_missing_task_as_absent() {
        let id = "org.open-pact.report.0123456789abcdef";
        let block = removal_block(Path::new(r"C:\Users\pact"), id, None);
        assert_eq!(block.matches("Test-TaskRegistered").count(), 3);
        // The check asks the Task Scheduler COM API, not schtasks text, so it works in every language.
        assert!(block.contains("New-Object -ComObject Schedule.Service"));
        assert!(
            block.contains(r"GetFolder('\').GetTask('\org.open-pact.report.0123456789abcdef')")
        );
        assert!(block.contains("if ($e.HResult -eq -2147024894) { return $false }"));
        // Only HRESULT 0x80070002 (file not found) means absent; any other error still throws.
        assert!(block.contains("throw ('Could not query the task. ' + $_)"));
        // Only /End runs with Continue, inside its own function, and it ignores its exit code.
        let scope = block.find("$ErrorActionPreference = 'Continue'").unwrap();
        assert!(block.find("function End-TaskQuietly").unwrap() < scope);
        assert!(scope < block.find("& $schtasks /End /TN").unwrap());
        assert!(!block.contains("cannot find the file specified"));
        assert!(!block.contains("$text -match"));
        assert!(!block.contains("$LASTEXITCODE -eq 0) { return $true"));
    }

    #[test]
    fn schtasks_starts_from_the_system_folder_by_its_full_path() {
        let path = system_schtasks().to_string_lossy().to_ascii_lowercase();
        assert!(
            path.ends_with("system32\\schtasks.exe") || path.ends_with("system32/schtasks.exe"),
            "{path}"
        );
    }

    #[test]
    fn the_removal_block_uses_only_system32_task_tools_and_checks_each_step() {
        let home = Path::new(r"C:\Users\it's a\pact");
        let machine = Path::new(r"C:\Program Files\open-pact-client\open-pact-client.exe");
        let id = "org.open-pact.report.0123456789abcdef";
        let block = removal_block(home, id, Some(machine));
        assert!(block.contains("Join-Path ([Environment]::SystemDirectory) 'schtasks.exe'"));
        assert!(!block.contains("Remove-Item") && !block.contains("powershell.exe"));
        let end_fn = block.find("function End-TaskQuietly").unwrap();
        let end = block.find("    End-TaskQuietly\n").unwrap();
        let delete = block
            .find("/Delete /TN 'org.open-pact.report.0123456789abcdef' /F")
            .unwrap();
        let check = block
            .find("-ne 0) { throw 'The task was not removed")
            .unwrap();
        // The delete runs only for a registered task, so a second run of the block ends the same
        // way; the last query still fails the block when the task survives.
        let probe = block.find("if (Test-TaskRegistered)").unwrap();
        let query = block.rfind("if (Test-TaskRegistered)").unwrap();
        assert!(end_fn < probe && probe < end && end < delete && delete < check && check < query);
        // /Delete stays under the caller's Stop: the End function closes before it.
        assert!(block.contains(
            "  }\n  if (Test-TaskRegistered) {\n    End-TaskQuietly\n    & $schtasks /Delete"
        ));
        assert!(block.contains("{ throw 'The task is still registered."));
        // With the machine client, the last line of the block removes the state through it.
        let last = block.find("schedule off").unwrap();
        assert!(query < last);
        // The client file must exist, the old exit code is cleared, and the home passes as data.
        let exists = block
            .find("if (-not (Test-Path -LiteralPath $q -PathType Leaf)) { throw 'The machine client is missing.")
            .unwrap();
        let reset = block.find("$global:LASTEXITCODE = $null").unwrap();
        assert!(query < exists && exists < reset);
        assert!(block.contains("  $clientHome = @'\nC:\\Users\\it's a\\pact\n'@\n"));
        let off = block
            .find("\n  & $q --home $clientHome schedule off")
            .unwrap();
        assert!(reset < off);
        assert!(
            block.contains("$q = 'C:\\Program Files\\open-pact-client\\open-pact-client.exe'\n")
        );
        // A failed cleanup stops the block, so the next step never uninstalls the package.
        let exit = block.find("\n  if ($LASTEXITCODE -ne 0) { throw 'schedule off failed. Do not uninstall the package.").unwrap();
        assert!(off < exit && exit < block.find("\n}").unwrap());
        assert_eq!(block.matches("$LASTEXITCODE").count(), 2);
        assert!(block.contains("Remove that folder after you removed every open-pact SYSTEM task"));
        assert!(block.contains("open-pact stays."));
        // Without it, the state folder stays for the next install to reset.
        let without = removal_block(home, id, None);
        assert!(!without.contains("schedule off"));
        assert!(without.contains("The state folder") && without.contains("stays."));
        assert!(without.contains("resets it"));
    }

    #[test]
    fn every_printed_value_is_quoted_with_the_one_literal_function() {
        for quote in ['\'', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'] {
            let home = format!("C:\\Users\\a{quote}b");
            let doubled = format!("a{quote}{quote}b");
            assert_eq!(powershell_literal(&home), format!("'C:\\Users\\{doubled}'"));
            let block = removal_block(Path::new(&home), &home, Some(Path::new("q.exe")));
            assert!(block.contains(&format!(
                "/Delete /TN '{}' /F",
                home.replace(quote, &format!("{quote}{quote}"))
            )));
            // The home is data in a here-string, never text between quotes.
            assert!(block.contains(&format!("@'\n{home}\n'@")));
            #[cfg(windows)]
            {
                let command = machine_command(
                    Path::new(&home),
                    "schedule on --system",
                    Path::new("q.exe"),
                    Some(Path::new(&home)),
                );
                assert_eq!(command.matches(&doubled).count(), 2, "{quote:?}: {command}");
            }
        }
    }

    #[test]
    fn the_machine_command_adds_the_profile_only_when_it_is_known() {
        let home = Path::new(r"C:\Users\a\pact");
        let machine = Path::new(r"C:\Program Files\open-pact-client\open-pact-client.exe");
        assert_eq!(
            machine_command(home, "schedule on --system", machine, None),
            apply_command(home, "schedule on --system", machine)
        );
        let with_profile = machine_command(
            home,
            "schedule on --system",
            machine,
            Some(Path::new(r"C:\Users\a")),
        );
        assert!(with_profile.starts_with(&apply_command(home, "schedule on --system", machine)));
        assert!(with_profile.ends_with(r" --user-home 'C:\Users\a'"));
    }

    #[test]
    fn the_package_fix_is_the_install_block_with_the_state_in_front() {
        let path = Path::new(r"C:\Program Files\open-pact-client\open-pact-client.exe");
        let running = version("0.9.0");
        let fix = |machine: &MachineClient| {
            machine_fix(machine, machine_state(machine, &running), path, &running)
        };
        assert_eq!(
            fix(&MachineClient::Present {
                version: version("0.9.0")
            }),
            None
        );
        let missing = fix(&MachineClient::Missing).unwrap();
        assert!(missing.starts_with("The machine client is not installed at "));
        assert!(missing.contains(&install_block(&running)));
        let outdated = fix(&MachineClient::Present {
            version: version("0.8.5"),
        })
        .unwrap();
        assert!(outdated.contains("is version 0.8.5, and this client is version 0.9.0"));
        assert!(outdated.ends_with("If you just installed an update, restart Windows."));
        let unprotected = fix(&MachineClient::Unprotected {
            reason: "owner".into(),
        })
        .unwrap();
        assert!(unprotected.contains(
            "is not protected (owner). Ask IT, or uninstall the machine client and install it again"
        ));
        assert!(!unprotected.contains("reinstall alone"));
        assert_eq!(
            fix(&MachineClient::Unknown {
                reason: "boom".into()
            })
            .unwrap(),
            "Cannot read the machine client: boom."
        );
        // No text names winget until the package is published there.
        assert!(!missing.contains("winget"));
    }
}

#[cfg(test)]
mod doc_blocks {
    use super::*;
    use std::path::Path;

    const CLIENT: &str = include_str!("../../../docs/client.md");
    const WINDOWS_INSTALL: &str = include_str!("../../../docs/windows-machine-install.md");
    const RELEASE_NOTES: &str = include_str!("../../../docs/release-notes/v0.9.0.md");
    const README: &str = include_str!("../../../README.md");
    const RELEASE_REMOVE: &str = "### Step 1: Find and remove the old SYSTEM task";
    const RELEASE_INSTALL: &str = "### Step 2: Install the 0.9.0 package";
    const RELEASE_START: &str = "### Step 3: Start the SYSTEM job";
    const CLIENT_INSTALL: &str = "### Install the machine client for the SYSTEM job";
    const CLIENT_START: &str = "### Use Windows SYSTEM checks";
    const CLIENT_REMOVE: &str = "### Stop the scheduled claims and remove the client";
    const WINDOWS_INSTALL_HEADING: &str = "## Install with the block";
    const WINDOWS_START: &str = "## Start the SYSTEM job for each home";
    const WINDOWS_REMOVE: &str = "## Remove the package";
    const HOME: &str = r"C:\Users\example\pact";
    const TASK: &str = "org.open-pact.report.0123abcd";
    const MACHINE: &str = r"C:\Program Files\open-pact-client\open-pact-client.exe";
    /// The commands that start the SYSTEM job. The reader writes each value into a here-string, so an
    /// apostrophe in a path needs no escape. The commands check the file and the exit code.
    const START_COMMANDS: &str = r#"$q = Join-Path $env:ProgramW6432 'open-pact-client\open-pact-client.exe'
$clientHome = @'
<the absolute client home>
'@
$userHome = @'
<the profile folder of the user>
'@
if (-not (Test-Path -LiteralPath $q -PathType Leaf)) { throw 'The machine client is missing. Install the package, then run this command again.' }
$global:LASTEXITCODE = $null
& $q --home $clientHome schedule on --system --user-home $userHome
if ($LASTEXITCODE -ne 0) { throw 'schedule on failed. Fix the error, then run this command again.' }"#;
    /// The commands that remove a task that the machine client owns.
    const OFF_COMMANDS: &str = r#"$q = Join-Path $env:ProgramW6432 'open-pact-client\open-pact-client.exe'
$clientHome = @'
<the absolute client home>
'@
if (-not (Test-Path -LiteralPath $q -PathType Leaf)) { throw 'The machine client is missing. Install the package, then run this command again.' }
$global:LASTEXITCODE = $null
& $q --home $clientHome schedule off
if ($LASTEXITCODE -ne 0) { throw 'schedule off failed. Do not uninstall the package. Fix the error, then run this command again.' }"#;
    /// The commands that repair a package of the same version, and wait for the result.
    const REPAIR_COMMANDS: &str = r#"$msi = @'
<the full path of the verified MSI>
'@
$msiexec = Join-Path ([Environment]::SystemDirectory) 'msiexec.exe'
$repair = Start-Process -FilePath $msiexec -ArgumentList ('/fa "' + $msi + '" /qn /norestart') -Wait -PassThru
if ($repair.ExitCode -eq 3010) { Write-Output 'Restart Windows to finish the repair.' }
elseif ($repair.ExitCode -ne 0) { throw ('The repair failed. Exit code: ' + $repair.ExitCode) }"#;

    /// The commands that check the saved `--user-home` of an old task against the rule of 0.9.0, before
    /// the task is removed. The reader writes the value into a here-string.
    const PROFILE_CHECK: &str = r#"$userHome = @'
<the --user-home value of the task>
'@
$list = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$profiles = @(Get-ChildItem -LiteralPath $list | Where-Object { $_.PSChildName -like 'S-1-5-21-*' -or $_.PSChildName -like 'S-1-12-1-*' } | ForEach-Object { [Environment]::ExpandEnvironmentVariables([string]$_.GetValue('ProfileImagePath')) })
$folder = Get-Item -LiteralPath $userHome -Force -ErrorAction SilentlyContinue
$reason = $null
if ($userHome.Contains('%')) { $reason = 'The folder name contains %.' }
elseif (-not [IO.Path]::IsPathRooted($userHome)) { $reason = 'The folder is not an absolute path.' }
elseif (-not $folder -or -not $folder.PSIsContainer) { $reason = 'The folder does not exist.' }
elseif ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) { $reason = 'The folder is a link.' }
elseif (-not ($profiles | Where-Object { $_.TrimEnd('\') -eq $userHome.TrimEnd('\') })) { $reason = 'Windows does not list the folder as the profile of a user account.' }
if ($reason) { 'Not OK: ' + $reason; 'Profiles that Windows lists:'; $profiles } else { 'OK: version 0.9.0 accepts this profile.' }"#;

    /// The PowerShell script that lists the SYSTEM tasks that run one of `programs`. It selects by
    /// principal and by action, never by the name prefix alone, and it prints the arguments of
    /// each task, which hold `--home` and `--user-home`.
    fn task_list(programs: &[(&str, &str)]) -> String {
        let mut text = String::from("& {\n");
        for (name, relative) in programs {
            text.push_str(&format!(
                "  ${} = Join-Path $env:ProgramW6432 '{}'\n",
                name, relative
            ));
        }
        let names = programs
            .iter()
            .map(|(name, _)| format!("${}", name))
            .collect::<Vec<_>>()
            .join(", ");
        text.push_str(&format!(
            r#"  $system = @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18')
  $programs = @({names})
  Get-ScheduledTask -TaskPath '\' | Where-Object {{
    $_.TaskName -like 'org.open-pact.report.*' -and
    ($system -contains $_.Principal.UserId) -and
    @($_.Actions | Where-Object {{ $_.Execute -and ($programs -contains ($_.Execute.Trim('"') -replace '^\\\\\?\\', '')) }}).Count -gt 0
  }} | ForEach-Object {{
    'Task: ' + $_.TaskName
    'Program: ' + (($_.Actions | ForEach-Object {{ $_.Execute }}) -join ' ')
    'Arguments: ' + (($_.Actions | ForEach-Object {{ $_.Arguments }}) -join ' ')
  }}
}}"#
        ));
        text
    }

    fn legacy_list() -> String {
        task_list(&[("legacy", r"open-pact\open-pact-client.exe")])
    }

    fn both_list() -> String {
        task_list(&[
            ("legacy", r"open-pact\open-pact-client.exe"),
            ("machine", r"open-pact-client\open-pact-client.exe"),
        ])
    }

    /// The contents of each ````powershell` fence of `doc`, without the fence lines. A fence inside an
    /// HTML comment is not an instruction, so it does not count.
    fn fences(doc: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut current: Option<Vec<&str>> = None;
        let mut comment = false;
        for line in doc.lines() {
            if current.is_none() {
                if comment {
                    comment = !line.contains("-->");
                    continue;
                }
                if line.contains("<!--") && !line.contains("-->") {
                    comment = true;
                    continue;
                }
            }
            match (&mut current, line.trim_end()) {
                (None, "```powershell") => current = Some(Vec::new()),
                (Some(lines), "```") => {
                    found.push(lines.join("\n"));
                    current = None;
                }
                (Some(lines), _) => lines.push(line),
                (None, _) => {}
            }
        }
        found
    }

    /// The lines of `doc` from the line `heading` to the next heading of the same or a higher level.
    /// A line inside a fence is never a heading.
    fn section(doc: &str, heading: &str) -> String {
        let depth = heading.chars().take_while(|c| *c == '#').count();
        let mut found = false;
        let mut in_fence = false;
        let mut lines = Vec::new();
        for line in doc.lines() {
            if line.starts_with("```") {
                in_fence = !in_fence;
            } else if !in_fence && line.starts_with('#') {
                let level = line.chars().take_while(|c| *c == '#').count();
                if found && level <= depth {
                    break;
                }
                if line == heading {
                    found = true;
                }
            }
            if found {
                lines.push(line);
            }
        }
        assert!(found, "the heading `{heading}` is missing");
        lines.join("\n")
    }

    /// True when exactly one fence under the heading `heading` of `doc` is `script`. The same
    /// script under another heading does not count.
    fn shows(doc: &str, heading: &str, script: &str) -> bool {
        fences(&section(doc, heading))
            .iter()
            .filter(|fence| *fence == script)
            .count()
            == 1
    }

    fn install_text() -> String {
        install_block(&Version::parse("0.9.0").unwrap())
    }

    /// The removal block without the prose lines after it. Those lines name folders of this machine.
    fn removal_text(machine: Option<&Path>) -> String {
        removal_block(Path::new(HOME), TASK, machine)
            .split("\nThe ")
            .next()
            .unwrap()
            .to_owned()
    }

    /// The removal block with the machine client.
    fn removal_with_machine() -> String {
        removal_text(Some(Path::new(MACHINE)))
    }

    #[test]
    fn every_doc_shows_the_install_block_that_the_client_prints() {
        let block = install_text();
        for (name, doc, heading) in [
            ("docs/client.md", CLIENT, CLIENT_INSTALL),
            (
                "docs/windows-machine-install.md",
                WINDOWS_INSTALL,
                WINDOWS_INSTALL_HEADING,
            ),
            (
                "docs/release-notes/v0.9.0.md",
                RELEASE_NOTES,
                RELEASE_INSTALL,
            ),
        ] {
            assert!(
                shows(doc, heading, &block),
                "{name} must show exactly the install block for 0.9.0 under `{heading}`"
            );
        }
    }

    #[test]
    fn the_docs_show_the_removal_block_with_the_machine_client() {
        let block = removal_with_machine();
        for (name, doc, heading) in [
            ("docs/client.md", CLIENT, CLIENT_REMOVE),
            (
                "docs/windows-machine-install.md",
                WINDOWS_INSTALL,
                WINDOWS_REMOVE,
            ),
        ] {
            assert!(
                shows(doc, heading, &block),
                "{name} must show exactly the removal block with the machine client under `{heading}`"
            );
        }
    }

    #[test]
    fn the_release_notes_show_the_removal_block_without_the_machine_client() {
        assert!(
            shows(RELEASE_NOTES, RELEASE_REMOVE, &removal_text(None)),
            "the release notes must show exactly the removal block without the machine client"
        );
    }

    #[test]
    fn the_removal_block_stops_when_schedule_off_fails() {
        let block = removal_with_machine();
        assert!(block.ends_with(
            "\n  if ($LASTEXITCODE -ne 0) { throw 'schedule off failed. Do not uninstall the package. Fix the error, then run this block again.' }\n}"
        ));
        for doc in [CLIENT, WINDOWS_INSTALL] {
            assert!(doc.contains("Do not uninstall the package"));
        }
    }

    #[test]
    fn the_legacy_tasks_are_selected_by_principal_and_action() {
        for script in [legacy_list(), both_list()] {
            assert!(script.contains("$_.Principal.UserId"));
            assert!(script.contains("$_.Actions"));
            assert!(script.contains("$_.Execute"));
            assert!(script.contains("$env:ProgramW6432"));
            assert!(script.contains("$_.Arguments"));
        }
        assert!(shows(RELEASE_NOTES, RELEASE_REMOVE, &legacy_list()));
        assert!(shows(WINDOWS_INSTALL, WINDOWS_REMOVE, &both_list()));
        assert!(shows(CLIENT, CLIENT_REMOVE, &both_list()));
    }

    #[test]
    fn the_filters_accept_the_long_path_prefix_of_an_action() {
        for script in [legacy_list(), both_list()] {
            assert!(script.contains(r"-replace '^\\\\\?\\', ''"));
        }
    }

    #[test]
    fn the_release_notes_check_the_profile_before_they_remove_the_task() {
        assert!(shows(RELEASE_NOTES, RELEASE_REMOVE, PROFILE_CHECK));
        let step = section(RELEASE_NOTES, RELEASE_REMOVE);
        let check = step.find("ProfileList").unwrap();
        let removal = step.find("/Delete").unwrap();
        assert!(
            check < removal,
            "the profile check comes before the removal"
        );
        // The rule of 0.9.0: no %, an absolute folder that exists, not a link, listed as a profile.
        for part in [
            "Contains('%')",
            "IsPathRooted",
            "PSIsContainer",
            "ReparsePoint",
            "S-1-5-21-*",
            "S-1-12-1-*",
            "ProfileImagePath",
            "'OK: ",
            "'Not OK: ",
        ] {
            assert!(PROFILE_CHECK.contains(part), "the check lacks {part}");
        }
        assert!(PROFILE_LIST_SCRIPT.contains("ProfileList"));
        assert!(PROFILE_LIST_SCRIPT.contains("S-1-5-21-*"));
        assert!(PROFILE_LIST_SCRIPT.contains("S-1-12-1-*"));
        assert!(PROFILE_LIST_SCRIPT.contains("ProfileImagePath"));
    }

    #[test]
    fn a_block_under_the_wrong_heading_does_not_count() {
        let doc =
            "## Install\n\n```powershell\nstart\n```\n\n## Start\n\n```powershell\ninstall\n```\n";
        assert!(shows(doc, "## Install", "start"));
        assert!(shows(doc, "## Start", "install"));
        assert!(!shows(doc, "## Install", "install"));
        assert!(!shows(doc, "## Start", "start"));
        // A line that starts with # inside a fence ends no section.
        let doc = "## Install\n\n```powershell\n# note\ninstall\n```\n";
        assert!(shows(doc, "## Install", "# note\ninstall"));
    }

    #[test]
    fn the_install_and_start_blocks_stay_under_their_own_steps() {
        assert!(!shows(RELEASE_NOTES, RELEASE_START, &install_text()));
        assert!(!shows(RELEASE_NOTES, RELEASE_INSTALL, START_COMMANDS));
        assert!(!shows(CLIENT, CLIENT_START, &install_text()));
        assert!(!shows(CLIENT, CLIENT_INSTALL, START_COMMANDS));
        assert!(!shows(WINDOWS_INSTALL, WINDOWS_START, &install_text()));
        assert!(!shows(
            WINDOWS_INSTALL,
            WINDOWS_INSTALL_HEADING,
            START_COMMANDS
        ));
    }

    #[test]
    fn the_start_and_repair_commands_are_the_same_in_every_guide() {
        for (name, doc, start, repair) in [
            ("docs/client.md", CLIENT, CLIENT_START, CLIENT_INSTALL),
            (
                "docs/windows-machine-install.md",
                WINDOWS_INSTALL,
                WINDOWS_START,
                WINDOWS_INSTALL_HEADING,
            ),
            (
                "docs/release-notes/v0.9.0.md",
                RELEASE_NOTES,
                RELEASE_START,
                RELEASE_INSTALL,
            ),
        ] {
            assert!(
                shows(doc, start, START_COMMANDS),
                "{name} must show the start commands under `{start}`"
            );
            assert!(
                shows(doc, repair, REPAIR_COMMANDS),
                "{name} must show the repair commands under `{repair}`"
            );
        }
        for (name, doc, heading) in [
            ("docs/client.md", CLIENT, CLIENT_REMOVE),
            (
                "docs/windows-machine-install.md",
                WINDOWS_INSTALL,
                WINDOWS_REMOVE,
            ),
        ] {
            assert!(
                shows(doc, heading, OFF_COMMANDS),
                "{name} must show the removal commands under `{heading}`"
            );
        }
    }

    #[test]
    fn no_value_goes_between_quotes_and_every_block_is_a_known_one() {
        let known = [
            install_text(),
            removal_with_machine(),
            removal_text(None),
            legacy_list(),
            both_list(),
            PROFILE_CHECK.to_owned(),
            START_COMMANDS.to_owned(),
            OFF_COMMANDS.to_owned(),
            REPAIR_COMMANDS.to_owned(),
        ];
        for (name, doc) in [
            ("README.md", README),
            ("docs/client.md", CLIENT),
            ("docs/windows-machine-install.md", WINDOWS_INSTALL),
            ("docs/release-notes/v0.9.0.md", RELEASE_NOTES),
        ] {
            for fence in fences(doc) {
                // A value that the reader writes goes in a here-string, never between quotes.
                assert!(
                    !fence.contains("'<"),
                    "{name} asks the reader to paste a value between quotes:\n{fence}"
                );
                if fence.contains("--system")
                    || fence.contains("schedule off")
                    || fence.contains("verify-blob")
                    || fence.contains("schtasks")
                    || fence.contains("msiexec")
                {
                    assert!(
                        known.contains(&fence),
                        "{name} shows a block that no function generates:\n{fence}"
                    );
                }
            }
        }
    }

    #[test]
    fn no_elevated_example_runs_the_client_by_its_bare_name() {
        for (name, doc) in [
            ("README.md", README),
            ("docs/client.md", CLIENT),
            ("docs/windows-machine-install.md", WINDOWS_INSTALL),
            ("docs/release-notes/v0.9.0.md", RELEASE_NOTES),
        ] {
            for fence in fences(doc) {
                if fence.contains("--system") || fence.contains("schedule off") {
                    assert!(
                        !fence
                            .lines()
                            .any(|line| line.starts_with("open-pact-client")),
                        "{name} runs the client by name in an elevated example:\n{fence}"
                    );
                }
            }
        }
    }
}
