# Linux check containers

`scripts/linux-checks.sh` builds the client test binary once per distro
(`Dockerfile.ubuntu`, `Dockerfile.fedora`), then starts one container per state
variant. `entrypoint.sh` prepares the variant and runs
`checks::run_all(Os::Linux)` through the ignored `print_run_all_on_this_machine`
test. All sample data is fictional.

Real tools run wherever a container can run them: `gsettings` (keyfile backend),
`firewall-cmd`, `lsblk`, `gzip`, `dnf`. Only `systemctl` is replaced by a shim
(variants `ufw-*`, `clamav-*`), and `dnf` in `patch-stale` and `patch-rotated`
on Fedora, because a container has no systemd and cannot fake a past date.
`patch-real` uses the history the image build wrote with the real package
manager.

## Checks that report `unknown` in a container, and why

| Check | Baseline value | Reason |
| --- | --- | --- |
| `disk_encryption` | `unknown` | The container root is an overlay mount. `lsblk` lists no device mounted at `/`, so the root cannot be classified. |
| `firewall` | `unknown` | `firewall-cmd` cannot reach firewalld (no D-Bus, no daemon). `systemctl is-active ufw` fails without systemd as init. |
| `screen_lock` | `unknown` | `XDG_CURRENT_DESKTOP` is unset. No desktop session runs. |
| `auto_login` | `unknown` | No display manager config file exists. |
| `secure_boot` | `unknown` | No `mokutil` and no EFI variables in the container. |
| `antimalware_active` | `unknown` | `systemctl` cannot query units without systemd. |
| `password_set` | `unknown` | The check has no Linux implementation. |

`os_supported` and `os_patch_age` give real answers: `/etc/os-release`,
`/var/log/apt/history.log` and `dnf history` all exist in the container.
