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
| `password_set` | `unknown` | `unknown` | `unknown` | No supported password check. |
| `auto_login` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | Run as the device user. |
| `secure_boot` | `unknown` | `on`, `off`, or `unknown` | `on`, `off`, or `unknown` | Run as the device user. |
| `antimalware_active` | `yes`, `no`, or `unknown` from XProtect | `yes`, `no`, or `unknown` from Security Center or Defender | `yes`, `no`, or `unknown` from ClamAV | Run as the device user. |
| `preboot_auth` | `user_secret`, `none`, or `unknown` | `user_secret`, `hardware_only`, `none`, or `unknown` | `user_secret`, `hardware_only`, `none`, or `unknown` from root and swap LUKS mappings | Windows needs administrator or SYSTEM access. macOS and Linux use the device user. |
| `antimalware_signature_age_days` | Integer days or `unknown` from XProtect receipt | Integer days or `unknown` from Defender | Integer days or `unknown` from the ClamAV database | Run as the device user. |
| `antimalware_full_scan_age_days` | `n/a` | Integer days or `unknown` | `unknown` | Run as the device user. |
| `web_protection` | `on`, `off`, `n/a`, or `unknown` from Chrome, Edge, Brave, and Firefox; Safari is not checked | `on`, `off`, or `unknown` from SmartScreen and supported browsers | `on`, `off`, or `unknown` from standard Chrome, Chromium, and Firefox policy and profile files | Windows needs SYSTEM to inspect other user profiles. macOS and Linux use the device user. |
| `log_oldest_record_days` | `n/a`; unified log retention is size-based | Integer days or `unknown` from Security and System logs | Integer days or `unknown` from the system journal | Windows needs administrator or SYSTEM access. The Linux device user needs read access to the system journal. macOS uses the device user. |
| `process_audit` | `n/a` | `on`, `off`, or `unknown` | `n/a` | Windows needs administrator or SYSTEM access. |
| `powershell_logging` | `n/a` | `on`, `off`, or `unknown` | `n/a` | Run as the device user with registry read access. |
| `log_cleared` | `n/a` | RFC 3339 UTC time, JSON null, or `unknown` from Security and System logs | `n/a` | Windows needs administrator or SYSTEM access to read both logs. |
| VPN certificate installation | Supported | Supported; `vpn\current` pointer, flat copies can lag while another program holds them open | Supported | Device user. |
| Device key protection | `secure_enclave` or `os_permissions` | `os_permissions` | `os_permissions` | Device user. |
| Report scheduler | launchd LaunchAgent, every five minutes | Task Scheduler, every five minutes; limited user or SYSTEM | systemd user timer, every five minutes | Windows SYSTEM install and uninstall need an elevated prompt. Linux needs a running user manager. |

When a control returns `n/a`, the client sends `n/a` only if the manifest allows that value. Otherwise, it sends `unknown` when the manifest allows `unknown`. If neither value is allowed, the client omits the result. An omitted required result can cause the gateway to deny the claim.

## Windows access limits

Run `schedule install --system` from an elevated prompt to read machine-wide Windows settings. The SYSTEM task can read `preboot_auth`, `os_patch_age_days`, `log_oldest_record_days`, `process_audit`, and `log_cleared`. It can also inspect browser settings in other user profiles. The task reads settings. It does not change them.

The limited Windows task runs as the current user. It may report `unknown` when Windows denies access. To trigger an extra report after a Security log clear, add the task user to the built-in `Event Log Readers` group. SYSTEM can read the Security log without that group. Without either access, the Security log clear trigger is unavailable.

Defender controls require Microsoft Defender Antivirus in Normal mode with the service enabled. Other antivirus providers return `unknown` for Defender metrics. Active threat counts describe Defender threats that are still active.

## Key protection

On macOS, `join` uses an existing software key if one is present. Otherwise, it tries to create the device key in the Secure Enclave unless you pass `--software-key`. If Secure Enclave creation fails, the client warns and creates a software key. The client stores a wrapped key file in its home directory when it uses the Secure Enclave. That key cannot leave the Mac. The gateway records every claim as verified trust level `L0`.

On Windows and Linux, and on macOS with `--software-key`, the device key is a software key protected by operating-system file permissions. These keys report protection `os_permissions` and trust level `L0`. The owner signing key and VPN certificate key are software keys on every platform.

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

## Linux sources and limits

`preboot_auth` follows the root filesystem and active swap through the inverse `lsblk` block tree. It reads the matching mapper name in `/etc/crypttab`. A missing or unreadable mapping returns `unknown`. The third field `none`, `-`, or no third field cannot exclude automatic default keys, including keys in the initramfs. That mapping returns `unknown`. `try-empty-password=yes` also returns `unknown`. If the raw bytes of `/proc/cmdline` contain `luks` anywhere, the result is `unknown` because the check cannot safely infer how a LUKS unlock parameter combines with crypttab. This can also match `luks` inside an unrelated word. Other command lines do not affect the crypttab result. RAM-only zram swap is excluded. `tpm2-device=`, `fido2-device=`, and `clevis` options return `hardware_only`. Explicit `tpm2-pin=yes` and `fido2-pin=yes` options count as a required secret. A readable systemd token that requires a PIN returns `user_secret` when every keyslot requires a secret. A keyfile on a verified unencrypted block filesystem returns `none`. An inaccessible keyfile, an encrypted keyfile location, LUKS1 metadata without boot configuration, and an unsupported block topology return `unknown`.

These values describe readable boot configuration. They do not attest the initramfs contents. The client does not read passphrases or volume keys. A standard user often cannot read raw LUKS headers. The check still uses readable `crypttab` entries in that case. Clevis configuration can use a network unlock service, so `hardware_only` means that this boot mapping does not prompt for a user secret. It does not assert that every Clevis pin uses local hardware.

`os_auto_updates` requires an enabled, active installation timer and configuration that permits installation. `APT::Periodic::Enable "0"` disables APT installation. DNF reads `apply_updates` in `[commands]`. DNF5 also supports `dnf5-automatic.timer` and applies `/etc/dnf/automatic.conf` over its distribution defaults. A missing systemd manager returns `unknown`. `work_account` uses numeric membership in `sudo`, `wheel`, or `root`. It measures the account running the client. `antimalware_realtime` reports the presence of the `clamonacc` process. It does not prove that each filesystem has an active fanotify watch.

Linux `web_protection` reads standard package locations for Chrome, Chromium, and Firefox. Chrome and Chromium use mandatory policy, profile preferences, then recommended policy. Conflicting policy files return `unknown`. Firefox reads its installation policy or system policy and relative profiles in `profiles.ini`. Absolute Firefox profiles, conflicting policy providers, known sandboxed packages, unreadable files, and no supported browser return `unknown`. Portable browsers, cloud policy, and custom command-line profile directories are outside this file-based check.

`antimalware_active_threats` remains `unknown`. A ClamAV `FOUND` record does not say whether a later delete, move, or repair resolved the threat. `antimalware_full_scan_age_days` remains `unknown`. A completed `clamscan` log identifies the selected scan scope, which can be one file or a directory. It does not prove a complete device scan. `password_set` remains `unknown`. Standard users cannot read the shadow database, and a locked local password does not exclude other PAM authentication methods.

The Linux detection marker reads the newest system-journal `FOUND` record from `clamonacc` or `clamd`. It uses the journal's trusted process name and microsecond timestamp. The scheduled five-minute poll can send an extra report when that marker advances. The scheduler retains a detection across failed sends and VPN disconnection. A journal permission warning returns an unknown read and preserves the previous baseline. File-only ClamAV logging has no supported event marker because a line without a trusted timestamp cannot supply a reliable event time. Operators must route ClamAV detections to the readable system journal for this trigger.

`log_cleared` stays `n/a` on Linux. Journal rotation and vacuuming remove old files without a retained, authoritative last-clear timestamp. An oldest visible entry cannot distinguish administrative clearing from retention or a new installation.

The source contracts are documented by [systemd crypttab](https://www.freedesktop.org/software/systemd/man/crypttab.html), [cryptsetup LUKS metadata](https://man7.org/linux/man-pages/man8/cryptsetup-luksDump.8.html), [ClamAV on-access scanning](https://docs.clamav.net/manual/OnAccess.html), [Chromium Linux policy](https://www.chromium.org/administrators/linux-quick-start/), and [Firefox policy locations](https://mozilla.github.io/policy-templates/), and [DNF5 automatic updates](https://dnf5.readthedocs.io/en/stable/dnf5_plugins/automatic.8.html).
