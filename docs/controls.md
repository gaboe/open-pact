# Controls by platform

This page shows how the client measures each control on each platform. [Platform support](platform-support.md) gives the exact result values and the required privileges.

The client sends every control that the signed manifest declares. A control that cannot be measured returns `unknown`, which counts as failed. A control that does not apply to a platform returns `n/a` where the manifest allows it.

| Control | Windows | macOS | Linux |
| --- | --- | --- | --- |
| `disk_encryption` | BitLocker | FileVault | LUKS on local disks and swap |
| `preboot_auth` | BitLocker PIN or password | FileVault | `none` or `unknown` |
| `os_supported` | Vendor end-of-support date for the release | Supported macOS versions | Distribution support |
| `os_patch_age_days` | Latest cumulative update | Latest security update | Latest package update |
| `os_auto_updates` | Automatic updates on and not paused | Automatic security updates on | Active apt or dnf update timer |
| `screen_lock` | Lock timeout and password | Lock timeout and password | Lock timeout and password |
| `firewall` | Windows Firewall | Application Firewall | Host firewall |
| `antimalware_active` | Defender | XProtect | ClamAV |
| `antimalware_realtime` | Defender real-time protection | XProtect | `clamonacc` running |
| `antimalware_signature_age_days` | Defender signatures | XProtect data | ClamAV database |
| `antimalware_active_threats` | Active Defender threats | `n/a` | `unknown` |
| `antimalware_full_scan_age_days` | Last Defender full scan | `n/a` | `unknown` |
| `web_protection` | SmartScreen and supported browsers | Chrome, Edge, Brave and Firefox | `unknown` |
| `log_oldest_record_days` | Security and System logs | `n/a` | System journal |
| `process_audit` | Event 4688 with command line | `n/a` | `n/a` |
| `powershell_logging` | Event 4104 | `n/a` | `n/a` |
| `log_cleared` | Events 1102 and 104 | `n/a` | `n/a` |
| `work_account` | Administrators group | `admin` group | `sudo` or `wheel` group |
| `uptime_days` | Days since boot | Days since boot | Days since boot |

On Windows, the SYSTEM task also reads settings that a standard account cannot see, such as process audit and the Security log. On macOS, the unified log is deleted by size, so log age and log clearing return `n/a`. XProtect does not run full scans.
