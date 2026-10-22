# Platform support

This page lists the built-in controls in `crates/open-pact-client/src/checks/mod.rs`. Each row gives the result type or the source that the client reads. A failed read returns `unknown` unless the table says `n/a`.

| Control | macOS | Windows | Linux | Required privilege |
| --- | --- | --- | --- | --- |
| `disk_encryption` | `full`, `none`, or `unknown` from FileVault | `full`, `partial`, `none`, or `unknown` from BitLocker | `full`, `partial`, `none`, or `unknown` from mounted writable, persistent local disks and swap; excludes boot and removable media | Run as the device user. |
| `firewall` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | Run as the device user. |
| `screen_lock` | `le_5min`, `le_15min`, `gt_15min`, `none`, or `unknown` | `le_5min`, `le_15min`, `gt_15min`, `none`, or `unknown` | `le_5min`, `le_15min`, `gt_15min`, `none`, or `unknown` | Windows SYSTEM reads interactive user profiles. Other checks use the device user. |
| `os_supported` | `yes`, `no`, or `unknown` | `yes`, `no`, or `unknown` | `yes`, `no`, or `unknown` | Run as the device user. |
| `os_patch_age_days` | Integer days or `unknown` | Integer days or `unknown` | Integer days or `unknown` | Windows needs administrator or SYSTEM access. macOS and Linux use the device user. |
| `os_auto_updates` | Automatic security data and critical updates enabled | Automatic updates enabled and not paused | Enabled and active apt or dnf timer with automatic installation configured | Settings read access. |
| `antimalware_realtime` | XProtect present and enabled | Defender real-time protection | Running `clamonacc` | Defender status read access on Windows. Device user elsewhere. |
| `antimalware_active_threats` | `n/a` | Integer active Defender threat count or `unknown` | `unknown` | Defender threat read access. |
| `work_account` | Current account in `admin` | Current token in Administrators, including UAC-filtered tokens; SYSTEM uses console user | Current account in `sudo` or `wheel` | Own token or groups; SYSTEM for Windows console token. |
| `uptime_days` | Whole days since boot | Whole days since boot | Whole days since boot | Device user with sysctl, CIM, or proc read access. |
| `password_set` | `unknown` | `unknown` | `unknown` | No privilege can make this check available. |
| `auto_login` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | Run as the device user. |
| `secure_boot` | `unknown` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | Run as the device user. |
| `antimalware_active` | `yes`, `no`, or `unknown` from XProtect | `yes`, `no`, or `unknown` from Security Center or Defender | `yes`, `no`, or `unknown` from ClamAV | Run as the device user. |
| `preboot_auth` | `user_secret`, `none`, or `unknown` | `user_secret`, `hardware_only`, `none`, or `unknown` | `none` or `unknown` | Windows needs administrator or SYSTEM access. macOS and Linux use the device user. |
| `antimalware_signature_age_days` | Integer days or `unknown` from XProtect receipt | Integer days or `unknown` from Defender | Integer days or `unknown` from the ClamAV database | Run as the device user. |
| `antimalware_full_scan_age_days` | `n/a` | Integer days or `unknown` | `unknown` | Run as the device user. |
| `web_protection` | `on`, `off`, `n/a`, or `unknown` from Chrome, Edge, Brave, and Firefox; Safari is not checked | `on`, `off`, or `unknown` from SmartScreen and supported browsers | `unknown` | Windows needs SYSTEM to inspect other user profiles. macOS and Linux use the device user. |
| `log_oldest_record_days` | `n/a`; unified log retention is size-based | Integer days or `unknown` from Security and System logs | Integer days or `unknown` from the system journal | Windows needs administrator or SYSTEM access. The Linux device user needs read access to the system journal. macOS uses the device user. |
| `process_audit` | `n/a` | `on`, `off`, or `unknown` | `n/a` | Windows needs administrator or SYSTEM access. |
| `powershell_logging` | `n/a` | `on`, `off`, or `unknown` | `n/a` | Run as the device user with registry read access. |
| `log_cleared` | `n/a` | RFC 3339 UTC time, JSON null, or `unknown` from Security and System logs | `n/a` | Windows needs administrator or SYSTEM access to read both logs. |
| VPN certificate installation | Supported | Supported; `vpn\current` pointer, flat copies can lag while another program holds them open | Supported | Device user. |
| Device key protection | `secure_enclave` or `os_permissions` | `tpm` or `os_permissions` | `os_permissions` | Joining user and SYSTEM on Windows. |
| Report scheduler | launchd LaunchAgent, every five minutes | Task Scheduler, every five minutes; limited user or SYSTEM | systemd user timer, every five minutes | Windows SYSTEM install and uninstall need an elevated prompt. Linux needs a running user manager. |

When a control returns `n/a`, the client sends `n/a` only if the manifest allows that value. Otherwise, it sends `unknown` when the manifest allows `unknown`. If neither value is allowed, the client omits the result. An omitted required result can cause the gateway to deny the claim.

## Windows access limits

Run `schedule install --system` from an elevated prompt to read machine-wide Windows settings. The SYSTEM task can read `preboot_auth`, `os_patch_age_days`, `log_oldest_record_days`, `process_audit`, and `log_cleared`. It can also inspect browser settings in other user profiles. The task reads settings. It does not change them.

The limited Windows task runs as the current user. It may report `unknown` when Windows denies access. To trigger an extra report after a Security log clear, add the task user to the built-in `Event Log Readers` group. SYSTEM can read the Security log without that group. Without either access, the Security log clear trigger is unavailable.

Defender controls require Microsoft Defender Antivirus in Normal mode with the service enabled. Other antivirus providers return `unknown` for Defender metrics. Active threat counts describe Defender threats that are still active.

## Key protection

On macOS, `join` uses an existing software key if one is present. Otherwise, it tries to create the device key in the Secure Enclave unless you pass `--software-key`. If Secure Enclave creation fails, the client warns and creates a software key. The client stores a wrapped key file in its home directory when it uses the Secure Enclave. That key cannot leave the Mac. The gateway records every claim as verified trust level `L0`.

On Linux, and on Windows or macOS with `--software-key`, the device key is a software key protected by operating-system file permissions. These keys report protection `os_permissions` and trust level `L0`. The owner signing key and VPN certificate key are software keys on every platform.

On Windows, TPM protection requires an elevated administrator join. A non-elevated join creates a software key and reports `key_protection = os_permissions`. Existing keys stay in use.

On Windows, a new join tries the Microsoft Platform Crypto Provider for a persisted,
non-exportable ECDSA P-256 TPM key. Only its public key leaves the provider.
The home holds a key-name marker in `device-tpm.key`, not private key material.
The machine-scope key ACL grants access to the joining user and SYSTEM.
Both limited user tasks and SYSTEM tasks can sign for that home. Other users do not receive access.
Machine-key creation requires elevation. If creation or ACL setup fails, the client warns
and creates an `os_permissions` software key. `--software-key` forces software for a new home.
An existing software key stays in use. To rotate to TPM, join again with a new home and
replace the old enrolment and scheduler registration. Copying the marker to another machine
cannot move the private key. Losing the marker or clearing the TPM requires a new join.
TPM claims request `L1`, like Secure Enclave claims. The gateway still records verified `L0`
because a key-protection label does not prove hardware attestation.
Windows CI tests the same CNG operations with the Microsoft Software Key Storage Provider,
including private-export refusal and signing under a standard user and SYSTEM.
Real TPM signing remains unverified until `windows_tpm_roundtrip` runs on a TPM machine.

## Schedule support

The SYSTEM task is available only on Windows. It reads the selected user's absolute `--home` path and stores its report state under `%ProgramData%`. It uses a shared client binary under `%ProgramFiles%`. The installer rejects a Windows home path that contains `%`.

## Log-clearing output

`log_cleared` uses `output = { timestamp = true, nullable = true, values = ["n/a"] }`.
A successful read returns the last clearing time as an RFC 3339 UTC string ending in `Z`.
JSON null means both Windows logs were readable and contain no retained clearing event.
The string `"unknown"` means the read failed. The string `"n/a"` means the check does not apply.
A TOML requirement uses `windows = "null"` to accept JSON null. It does not accept the string `"null"`.
Any timestamp fails that requirement. Claims retain actual JSON null through serialization.
These results describe retained log history. They cannot prove that a log was never cleared.
