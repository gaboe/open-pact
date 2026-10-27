# Install and use the client

The client sends results only for controls and outputs that the signed manifest permits. On Windows, a selected check can run a cached PowerShell batch that also reads other controls, browser profiles, and event sources. The client sends only permitted results in its claim or report. It sends a signed claim when you run `check`. It sends a separate status report when you run `report` or install a report schedule.

## Verify a release

Run the verification script with a release tag:

```sh
scripts/verify-client-release.sh v0.2.0
```

The script checks every checksum and Sigstore bundle. It keeps the verified files in a private temporary directory when verification succeeds. It removes the directory if verification fails. It prints the directory path on the last line. Copy that path for the install command.

Set `verified_dir` to the printed path:

```sh
verified_dir="/path/printed/by/script"
```

For Apple Silicon macOS, run:

```sh
mkdir -p "$HOME/.local/bin"
install -m 0755 "$verified_dir/open-pact-client-aarch64-apple-darwin" "$HOME/.local/bin/open-pact-client"
```

For Intel macOS, install this binary:

```sh
install -m 0755 "$verified_dir/open-pact-client-x86_64-apple-darwin" "$HOME/.local/bin/open-pact-client"
```

For Linux x86-64, install this binary:

```sh
install -m 0755 "$verified_dir/open-pact-client-x86_64-unknown-linux-musl" "$HOME/.local/bin/open-pact-client"
```

Set `$verifiedDir` to the printed path in PowerShell:

```powershell
$verifiedDir = 'C:\path\printed\by\script'
```

For Windows x86-64, run:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\bin" | Out-Null
Copy-Item "$verifiedDir\open-pact-client-x86_64-pc-windows-msvc.exe" "$env:USERPROFILE\bin\open-pact-client.exe"
```

The script needs GitHub CLI, Cosign, and `sha256sum` or `shasum`. Set `GH_REPO` when you verify a release from a fork.

## Join and check the gateway

On Windows, set `HOME` before you run the client. The client does not use `USERPROFILE` or `APPDATA` as a fallback. In PowerShell, set an absolute path with `$env:HOME = Join-Path $env:USERPROFILE 'pact'`.

Get a one-time `opi1:` invitation from the gateway operator. Confirm the gateway key fingerprint with the operator over a second channel. Join with the invitation:

```sh
open-pact-client join 'opi1:replace-with-your-invitation'
```

The client checks the gateway keys and transparency checkpoint before it displays the manifest. Read the manifest before you approve the signature prompt. The owner key signs the manifest hash and the device enrolment statement. The gateway leaves the device pending until an operator approves its device code.

On macOS, `join` reuses an existing device key. It creates a Secure Enclave key only when no key exists and creation succeeds. If creation fails, the client warns and uses a software key. Pass `--software-key` to select a software key for a new device. Windows and Linux use software keys. The owner key and the VPN certificate key are software keys on every platform.

After the operator approves the device, check it:

```sh
open-pact-client check
```

The client runs the checks in the signed manifest and sends one signed claim. It verifies the response and log checkpoint. It installs the VPN certificate and CA when the gateway accepts the claim. On Windows, read the consistent pair through `vpn\current`. The README section on the client home describes this pointer. A denied check returns the gateway's reason. A log verification failure raises an alarm and exits with status 2.

Run `open-pact-client log head` to show the last verified checkpoint. Run `open-pact-client log prove` to verify the inclusion proof for this device's enrolment. Run `open-pact-client log show` to print the local record of claims and gateway responses.

## Declare the device configuration

Run `open-pact-client config example` after enrolment. Copy the sections you need into `open-pact.toml` beside `manifest.toml` in the client home. The example includes the enrolled requirements as comments. It writes nothing.

```toml
[report]
collector = "https://collector.internal.example.org/status"
# Optional. Defaults to the collector host and port.
# vpn_probe = "vpn.example.org:443"

[schedule]
enabled = true
run_as = "user"

[managed_repos]
folders = ["~/work"]
```

Every section is optional. The client never writes this file. Unknown sections or keys cause an error that names the file and key. Folder entries must be absolute after `~` expands to your user home. The loader does not inspect those paths. Folder paths stay on the device. These folders are reserved for managed repository checks.

Run `check` to see one row per manifest control. Each row shows the requirement for your OS, the device setting that feeds it, and the result. A missing or invalid configuration prints what to add or fix. Other controls still run.

The client scans for repositories that match the signed `remotes` patterns. It counts each matching repository inside the registered folders in `managed_repos_total`. It counts each matching repository outside those folders in both `managed_repos_total` and `managed_repos_outside`. The client stores paths locally and reports only counts. See [client controls](controls.md) for the scan rules and limits.

On macOS, grant Full Disk Access to the client binary in System Settings before you use repository counts. Open Privacy & Security, select Full Disk Access, and add the client binary. If a scan still cannot read some folders, `check` reports `unknown` and prints the client binary path. It does not print denied folder paths.

## Send a report

Declare `[report].collector`, then inspect the signed payload:

```sh
open-pact-client report --dry-run
```

The command prints the JSON report and its compact ES256 JWS. It sends nothing. Run `open-pact-client report` to send it. The HTTPS collector must verify the JWS with the enrolled device's public key and return HTTP 2xx to acknowledge it.

A report includes `spec_version = "1.1"`, the enrolled device pseudonym in `device_id`, a random `report_id`, UTC time, client version, OS, key protection type, and manifest control results. `report_type` is `connect`, `event`, or `periodic`. Manual reports use `periodic`. Reports contain no public key or folder paths. The gateway does not receive this separate report.

## Apply the schedule

Choose a collector that the device can reach only through the VPN. Set `[schedule].enabled = true`, then run:

```sh
open-pact-client apply --dry-run
open-pact-client apply
open-pact-client apply
```

The first apply prints `schedule: install`. The second prints `no changes`. Dry run writes nothing. A collector or run-as edit produces `schedule: update`. Keep the client binary at its installed path. Use the same absolute `--home` for each apply.

The scheduled run reads the file each time. It probes the collector host and port every five minutes. Set `[report].vpn_probe = "host:port"` to override the target. Use brackets around IPv6 addresses. Both the collector and probe must be unreachable outside the VPN. A public collector does not prevent off-VPN sends.

The job probes before report preparation and again before sending. It sends after a detected connection, then after at least 55 minutes since the last acknowledgment. A failed send retries later. A lost acknowledgment can cause a duplicate report. A required control that changes from compliant to non-compliant triggers an extra report. Missing results and `unknown` count as non-compliant without grace. Controls with no requirement do not trigger.

On Windows, a new Security event 1102 or Defender detection also triggers an event report. A limited task needs Event Log Readers access to read Security events. SYSTEM can read that log. The first successful read sets each event baseline. The job keeps pending events while offline. It sends at most one report per run. Only acknowledgment clears pending events.

macOS uses a launchd LaunchAgent. Linux uses a systemd user timer and needs a running user manager. Windows uses a limited Task Scheduler task when `run_as = "user"`.

If an old job exists without `open-pact.toml`, `check` and `apply` print the content that reproduces it. Create that file before applying. Until then, apply changes nothing. Successful apply removes the old `report-schedule.json`. Setup uses only the configuration file and apply.

### Use Windows SYSTEM checks

Set `[schedule].run_as = "system"`. Run apply from an elevated PowerShell prompt:

```powershell
open-pact-client --home 'C:\Example User\pact' apply
```

Without elevation, apply prints the exact elevated command and changes nothing. Other operating systems reject `system`. The installer copies the client into `%ProgramFiles%\open-pact\open-pact-client.exe` and refuses a directory that non-administrators can write. SYSTEM reads the selected absolute client home and keeps report state under protected `%ProgramData%`. Choose a home path without `%`. The task reads Windows settings and does not change them. See [platform support](platform-support.md) for checks that need SYSTEM access.

### Stop reports and remove the client

Set `[schedule].enabled = false` or remove the schedule section. Run `apply` with the same absolute `--home` before deleting the binary or client home. Apply removes the job, the applied-settings receipt, and report state. It keeps `open-pact.toml`. If the entire client home is already missing, apply removes the remaining job without recreating it. Run `stop` to print these instructions.

Limited Windows operations leave orphaned protected state and the shared binary unchanged. To remove those leftovers, set `run_as = "system"` with `enabled = false` and run apply elevated. SYSTEM removal needs elevation and uses the existing protected state lock. A held lock stops task removal and asks you to retry. Removal cleans up the shared binary only when no SYSTEM task uses it. If cleanup fails, retry apply after the client stops or Windows restarts. Keep the configuration file until cleanup succeeds.

## Understand what leaves the device

`join` sends the invitation, signed manifest, owner and device public keys, and signatures that bind the owner, device, invitation, and manifest. It sends no private keys.

`check` sends the signed claim fields that the manifest permits. These include control results and permitted device metadata. The VPN certificate request travels beside the claim. Its private key stays on the device. The client stores claims and responses in `claims.jsonl`.

`report` sends a separate signed payload to the HTTPS collector. It contains report metadata and control results. It contains no raw system logs, public key, or folder paths.

## Troubleshoot common failures

| Symptom | Action |
| --- | --- |
| Release verification fails | Use the script from the matching release tag. Check GitHub CLI and Cosign. |
| Join refuses the gateway | Confirm the invitation, company fingerprint, certificate, and log key with the operator. |
| Manifest hash mismatch | Get a new invitation. Review and sign the current manifest. Ask the operator to approve the device. |
| Device is pending | Give the device code to the operator. Wait for approval. |
| Windows control returns unknown | Use SYSTEM or administrator access for machine-wide controls. |
| Windows events do not trigger | Check Event Log Readers access and Defender history access. |
| Apply cannot reach systemd | Start the user systemd manager. Run apply again. |
| Schedule does not send | Check the HTTPS collector, VPN-only routing, probe, and binary path. |
| Apply cannot find the job | Use the same absolute client home as the original apply. |
| Apply names an unknown key | Correct the named section and key in open-pact.toml. Run apply again. |
