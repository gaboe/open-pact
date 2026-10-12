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
That `dnf` shim reports no security advisories. `patch-real` uses the history
the image build wrote with the real package manager. The images keep the
package metadata of their build, so the real security query runs against it.
`patch-no-metadata` deletes that metadata, and the check must report `unknown`.

## Expected values

`expected.txt` lists the value each check must report per distro and variant.
`scripts/linux-checks.sh` fails on any difference, on a nonzero container exit
(the entrypoint exits with the test status), on a panic, and on a slow run.
`selftest.sh` runs the script against a fake `docker` and proves it rejects a
corrupted cell, an all-`unknown` run, and a failed process.

Two cells depend on the clock and accept several values. `os_patch_age` in the
real-history variants must be a date bucket, because the image build date sets
it. Fedora `os_supported` follows the Fedora 43 end-of-life date.

## What the checks count

`disk_encryption` reads `lsblk -s` and judges every writable, non-removable,
persistent block filesystem plus swap: `full` when all have a crypt ancestor,
`partial` when some do, `none` when none do. Read-only and removable media,
loop and optical devices, zram, squashfs/iso/tmpfs/overlay, and the boot
mounts (`/boot`, `/boot/efi`, `/efi`) are excluded.

`firewall` reports ufw as on only when `/etc/ufw/ufw.conf` has `ENABLED=yes`
and the service is active. firewalld counts when `firewall-cmd --state` says
`running`.

`os_patch_age` counts a whole-system upgrade. A single application install or
upgrade does not reset it, and neither does a dnf upgrade with a subset flag
before or after the verb. The check reports `unknown` unless the security
query (`apt-get -s upgrade` or `dnf -C -q updateinfo list --security`) exits
zero, its output is understood, and it lists no outstanding update. APT also
needs downloaded package lists.

## Checks that report `unknown` in a container, and why

| Check | Baseline value | Reason |
| --- | --- | --- |
| `disk_encryption` | `unknown` | The container root is an overlay mount. `lsblk` lists no device mounted at `/`, so the root cannot be classified. |
| `firewall` | `off` on Ubuntu, `unknown` on Fedora | `firewall-cmd` cannot reach firewalld (no D-Bus, no daemon). Ubuntu has no `ufw.conf` with `ENABLED=yes` and `systemctl is-active ufw` reports inactive, so it reads `off`. Fedora has neither, so it reads `unknown`. |
| `screen_lock` | `unknown` | `XDG_CURRENT_DESKTOP` is unset. No desktop session runs. |
| `auto_login` | `unknown` | No display manager config file exists. |
| `secure_boot` | `unknown` | No `mokutil` and no EFI variables in the container. |
| `antimalware_active` | `unknown` | `systemctl` cannot query units without systemd. |
| `password_set` | `unknown` | The check has no Linux implementation. |

`os_supported` and `os_patch_age` give real answers: `/etc/os-release`,
`/var/log/apt/history.log` and `dnf history` all exist in the container.
