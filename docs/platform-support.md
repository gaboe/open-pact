# Platform support

This page lists the built-in controls in `crates/open-pact-client/src/checks/mod.rs`. Each row gives the result type or the source that the client reads. A failed read returns `unknown` unless the table says `n/a`.

| Control | macOS | Windows | Linux | Required privilege |
| --- | --- | --- | --- | --- |
| `disk_encryption` | `full`, `none`, or `unknown` from FileVault | `full`, `partial`, `none`, or `unknown` from BitLocker | `full`, `partial`, `none`, or `unknown` from root-volume encryption | Run as the device user. |
| `firewall` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | Run as the device user. |
| `screen_lock` | `le_5min`, `le_15min`, `gt_15min`, `none`, or `unknown` | `le_5min`, `le_15min`, `gt_15min`, `none`, or `unknown` | `le_5min`, `le_15min`, `gt_15min`, `none`, or `unknown` | Windows SYSTEM reads interactive user profiles. Other checks use the device user. |
| `os_supported` | `yes`, `no`, or `unknown` | `yes`, `no`, or `unknown` | `yes`, `no`, or `unknown` | Run as the device user. |
| `os_patch_age_days` | Integer days or `unknown` | Integer days or `unknown` | Integer days or `unknown` | Windows needs administrator or SYSTEM access. macOS and Linux use the device user. |
| `password_set` | `unknown` | `unknown` | `unknown` | No privilege can make this check available. |
| `auto_login` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | Run as the device user. |
| `secure_boot` | `unknown` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | Run as the device user. |
| `antimalware_active` | `yes`, `no`, or `unknown` from XProtect | `yes`, `no`, or `unknown` from Security Center or Defender | `yes`, `no`, or `unknown` from ClamAV | Run as the device user. |
| `preboot_auth` | `user_secret`, `none`, or `unknown` | `user_secret`, `hardware_only`, `none`, or `unknown` | `none` or `unknown` | Windows needs administrator or SYSTEM access. macOS and Linux use the device user. |
| `antimalware_signature_age_days` | Integer days or `unknown` from XProtect receipt | Integer days or `unknown` from Defender | Integer days or `unknown` from the ClamAV database | Run as the device user. |
| `antimalware_full_scan_age_days` | `n/a` | Integer days or `unknown` | `unknown` | Run as the device user. |
| `antimalware_detections_7d` | `n/a` | Integer count or `unknown` | `unknown` | Run as the device user. |
| `antimalware_last_detection_hours` | `n/a` | Integer hours, `none`, or `unknown` | `unknown` | Run as the device user. |
| `web_protection` | `on`, `off`, `n/a`, or `unknown` from Chrome, Edge, Brave, and Firefox; Safari is not checked | `on`, `off`, or `unknown` from SmartScreen and supported browsers | `unknown` | Windows needs SYSTEM to inspect other user profiles. macOS and Linux use the device user. |
| `local_log_retention_days` | `n/a`; unified log retention is size-based | Integer days or `unknown` from Security and System logs | Integer days or `unknown` from the system journal | Windows needs administrator or SYSTEM access. macOS and Linux use the device user. |
| `process_audit` | `n/a` | `on`, `off`, or `unknown` | `n/a` | Windows needs administrator or SYSTEM access. |
| `powershell_logging` | `n/a` | `on`, `off`, or `unknown` | `n/a` | Run as the device user with registry read access. |
| `log_cleared_hours` | `n/a` | Integer hours, `none`, or `unknown` from Security and System logs | `n/a` | Windows needs administrator or SYSTEM access to read both logs. |
| Device key protection | `secure_enclave` or `os_permissions` with `--software-key` | `os_permissions` | `os_permissions` | Device user. |
| Report scheduler | launchd LaunchAgent, every five minutes | Task Scheduler, every five minutes; limited user or SYSTEM | systemd user timer, every five minutes | Windows SYSTEM install and uninstall need an elevated prompt. Linux needs a running user manager. |

## Windows access limits

Run `schedule install --system` from an elevated prompt to read machine-wide Windows settings. The SYSTEM task can read `preboot_auth`, `os_patch_age_days`, `local_log_retention_days`, `process_audit`, and `log_cleared_hours`. It can also inspect browser settings in other user profiles. The task reads settings. It does not change them.

The limited Windows task runs as the current user. It may report `unknown` when Windows denies access. To trigger an extra report after a Security log clear, add the task user to the built-in `Event Log Readers` group. SYSTEM can read the Security log without that group. Without either access, the Security log clear trigger is unavailable.

Defender controls require Microsoft Defender Antivirus in Normal mode with the service enabled. Other antivirus providers return `unknown` for Defender metrics. Detection values describe retained Defender history.

## Key protection

On macOS, `join` creates the device key in the Secure Enclave unless you pass `--software-key`. The client stores a wrapped key file in its home directory. The key cannot leave that Mac, but the client does not bind it to a signed application. The gateway cannot verify the claimed trust level. It records every claim as verified trust level `L0`.

On Windows and Linux, and on macOS with `--software-key`, the device key is a software key protected by operating-system file permissions. These keys report protection `os_permissions` and trust level `L0`. The owner signing key and VPN certificate key are software keys on every platform.

## Schedule support

The SYSTEM task is available only on Windows. It reads the selected user's absolute `--home` path and stores its report state under `%ProgramData%`. It uses a shared client binary under `%ProgramFiles%`. The installer rejects a Windows home path that contains `%`.
