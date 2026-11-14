# Install and use the client

The client sends results only for controls and outputs that the signed manifest permits. On Windows, a selected check can run a cached PowerShell batch that also reads other controls, browser profiles, and event sources. The client sends only permitted results in its claim. It sends a signed claim when you run `check` and, while the device is on the company VPN, from the scheduled job.

## Install with a package manager

Install the client with the package manager for your platform:

```sh
brew install gaboe/tap/open-pact
```

On Windows, add the Scoop bucket and install the client:

```powershell
scoop bucket add gaboe https://github.com/gaboe/scoop-bucket
scoop install gaboe/open-pact
```

For Debian or Ubuntu, download the `.deb` from the [client releases](https://github.com/gaboe/open-pact/releases), then run:

```sh
sudo apt install ./open-pact-client_0.4.9_amd64.deb
```

For Fedora, download the `.rpm` from the [client releases](https://github.com/gaboe/open-pact/releases), then run:

```sh
sudo dnf install ./open-pact-client-0.4.9-1.x86_64.rpm
```

Homebrew and Scoop check the SHA-256 value recorded in their formula or manifest. They do not verify the Cosign signature. The Linux commands install local files, so verify them with the release steps below before you install them. Run `brew upgrade` or `scoop update open-pact` to update an installed client. For APT or DNF, download and install each new release when you choose to update.

## Verify a release

Run the verification script with a release tag:

```sh
scripts/verify-client-release.sh v0.4.9
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

The verified directory includes the `.deb` and `.rpm` packages. Install them with the matching package manager:

```sh
sudo apt install "$verified_dir/open-pact-client_0.4.9_amd64.deb"
sudo dnf install "$verified_dir/open-pact-client-0.4.9-1.x86_64.rpm"
```

## Join and check the gateway

On Windows, set `HOME` before you run the client. The client does not use `USERPROFILE` or `APPDATA` as a fallback. In PowerShell, set an absolute path with `$env:HOME = Join-Path $env:USERPROFILE 'pact'`.

Get a one-time `opi1:` invitation from the gateway operator. Confirm the gateway key fingerprint with the operator over a second channel. Join with the invitation:

```sh
open-pact-client join 'opi1:replace-with-your-invitation'
```

The client checks the gateway keys and transparency checkpoint before it displays the manifest. Read the manifest before you approve the signature prompt. The owner key signs the manifest hash and the device enrolment statement. The gateway leaves the device pending until an operator approves its device code. After it prints the code, `join` checks for approval every 10 seconds. It reports approval only after it verifies the device's `device_approved` entry in the signed log. Press Ctrl+C to stop waiting. The enrolment stays on disk, so run `join` again or run `check` later. Pass `--no-wait` to print the code and exit without polling.

Before you sign, step 2 of `join` prints the manifest summary and the absolute path of a file that holds the whole text. Open that file and read all of it. The company wrote it; it is the one file that says what is checked, what is sent and when. After an interactive `join` verifies approval, the wizard asks only for your own choices: whether to send claims automatically (only when the manifest defines automatic sending), on Windows whether the job runs as you or as SYSTEM, and the folders that hold your repositories (only when the manifest counts repositories). It then installs the job if you said yes and offers the first claim. You edit no file. If you stop, run `join` again to resume.

On macOS, `join` reuses an existing device key. It creates a Secure Enclave key only when no key exists and creation succeeds. If creation fails, the client warns and uses a software key. Pass `--software-key` to select a software key for a new device. On Windows, an elevated administrator join tries a TPM key. A non-elevated join or an unavailable provider uses a software key. Marker write and key ACL failures stop join. Linux uses software keys. The owner key and the VPN certificate key are software keys on every platform.

To run a later check after device approval, use:

```sh
open-pact-client check
```

The client runs the checks in the signed manifest and sends one signed claim. It verifies the response and log checkpoint. It installs the VPN certificate and CA when the gateway accepts the claim. On Windows, read the consistent pair through `vpn\current`. The README section on the client home describes this pointer. A denied check returns the gateway's reason. A log verification failure raises an alarm and exits with status 2.

Log entries are private. The public `/v1/log/entries` and `/v1/log/proof/inclusion` routes return 404. An approved device uses `POST /v1/log/mine` to get its signed manifest and its own device entries with inclusion proofs. The log key, signed checkpoint and consistency proofs remain public. Witnesses receive checkpoints and consistency proofs by push; they do not download entries.

Public consistency proofs expose leaf hashes for log changes. An outsider who polls checkpoints can count and time changes. The outsider can recognize manifest and retention-purge entries, then identify the remaining changes as device events. Salted commitments stop the outsider from linking a device event to a device. Entry contents remain private. Witnesses verify checkpoint consistency, and each approved device verifies its own entries.

The first sync verifies the gateway signature with the pinned log key and enforces the signed manifest’s witness quorum and cosignature age. It does not download the full log. Later syncs also verify consistency from the stored checkpoint. A manifest that explicitly permits split views with no witnesses accepts a gateway-signed checkpoint alone and prints a warning. `log prove [index]` can show only the manifest and device entries returned for this device.

If private log access is denied, `check` asks for this device's status. A pending device gets an IT approval message. A revoked device gets a revocation message. Both return exit code 1 without sending a claim.

Run `open-pact-client log head` to show the last verified checkpoint. Run `open-pact-client log prove` to verify the inclusion proof for this device's enrolment. Run `open-pact-client log show` to print claims and gateway responses.

### Accept a changed manifest

When the company changes the manifest, `check` prints a line that names the new hash and asks you to run `accept`. The device keeps its approval and VPN access meanwhile. Controls that the new manifest adds or tightens fail now. The gateway accepts claims for the length of each control's grace and warns you. When the grace runs out, access ends.

```sh
open-pact-client accept
```

The client fetches the new manifest and checks its company signature, the pinned keys and the log checkpoint under the new manifest's log policy. It shows the manifest and what changed against the one you signed: added, removed, and changed controls, `disclosed_metadata`, `claim_retention`, `claim_recipients`, `data_controller`, the minimum trust level, `unknown_grace`, `claim_max_age`, the issuer, the validity date and the log policy. A changed control shows its requirement for each operating system that differs. If you confirm, the owner key and the device key sign the new hash. The gateway moves the device to the new manifest without a new invitation or approval. The client then stores the new manifest, and the next `check` runs its checks. Pass `--yes` to sign without the prompt.

Before you sign, `accept` prints the absolute path of a copy of the whole new manifest, so you can read all of it. The copy is removed when the command ends. A change to `[schedule]` appears in the list of changes in plain words, such as `Automatic claims: only while vpn.example.org answers at 10.0.0.1:443, every 55 minutes, and at once when a check result changes`. Until you accept, the job keeps the policy of the manifest you signed.

Run `open-pact-client manifest show` to review the signed manifest stored on this device. It checks that `manifest.toml` still matches the hash in `enrolment.json`, then prints the manifest summary, signed hash, and the absolute path of the full text. It also prints the automatic-claims line. It also prints the manifest's transparency log entry index when the client has it. If the index is not stored, use `open-pact-client log prove` to verify the entries available to this device. This command reads local files and does not contact the gateway.

## Choose your folders

You edit no settings file. The company's rules are in the signed manifest. Your own choices are in `device.json` in the client home. The client writes that file atomically and does not expect you to edit it. It holds three things: whether automatic sending is on, on Windows who runs the job (you or SYSTEM), and the repository folders.

The wizard asks for the folders only when the manifest has a repository control. Change them later with:

```sh
open-pact-client folders list
open-pact-client folders add ~/projects
open-pact-client folders remove ~/projects
```

`~` expands to your user home. The command stores an absolute path and prints a note when the folder does not exist yet. Folder paths stay on the device. The next `check` shows them.

An `open-pact.toml` from an earlier client is ignored. When the file exists, `check` and the job print once that it is ignored and where each value went: the schedule moved to the signed manifest, `enabled` and `run_as` moved to `schedule on`, and the folders moved to `folders add`. The first read of a home without `device.json` imports its folders into `device.json`, because they were your own choice, and `folders list` shows them. The wizard still asks step 5. On Windows, an installed SYSTEM job keeps `run_as` SYSTEM, and the notice prints the exact elevated command, `schedule on --system` with the full path of the client. The client never deletes the file. Delete it yourself when you no longer need it.

Run `check` to see one row per manifest control. Each row shows the requirement for your OS, the device setting that feeds it, and the result.

The client scans for repositories that match the signed `remotes` patterns. It counts each matching repository inside your folders in `managed_repos_total`. It counts each matching repository outside those folders in both `managed_repos_total` and `managed_repos_outside`. The client stores paths locally and sends only counts. See [client controls](controls.md) for the scan rules and limits.

On macOS, grant Full Disk Access to the client binary in System Settings before you use repository counts. Open Privacy & Security, select Full Disk Access, and add the client binary. If a scan still cannot read some folders, `check` reports `unknown` and prints the client binary path. It does not print denied folder paths.

## See what a claim sends

Inspect the claim that `check` would send now:

```sh
open-pact-client check --dry-run
```

The command runs the same local checks as `check` and prints the claim as JSON. It adds `manifest_toml` when the gateway enforces another manifest than the one you signed. It asks the gateway the same questions as `check`: the enforced manifest, the log keys, the checkpoint and its consistency proof, your own log entries (one nonce request and one signed `log/mine` request), and your device status when the gateway denies log access. It sends no claim and writes no file, so it leaves `repo-scan.json`, the stored checkpoint, `enrolment.json`, and `claims.jsonl` as they are. The gateway issues the one nonce for the log request, and no claim uses it. When `check` would send nothing, because the device waits for approval, IT revoked it, the manifest awaits `accept`, or the log does not verify, the dry run prints the reason and no request. The nonce, the time of sending, and the VPN certificate request appear as placeholders, because the client creates them when it sends. The scheduled job sends this same claim.

## Send claims automatically

The company decides whether the job may send, and how, in the `[schedule]` table of the signed manifest. The table is part of the signed text and its hash. You decide only whether to turn it on. The job runs the claim pipeline of `check` and sends the same claim. The gateway is the only server.

```toml
[schedule]
mode = "vpn"
vpn_probe = "10.0.0.1:443"
vpn_probe_name = "vpn.example.org"
interval = "55m"
```

- `mode = "vpn"` sends only while `vpn_probe` answers. It needs `vpn_probe`. `vpn_probe_name` is optional.
- `mode = "always"` sends on any network. It takes no `vpn_probe` and no `vpn_probe_name`. The client says so in plain words: `Automatic claims: every 55 minutes on any network`.
- `interval` is the time between periodic claims, from `5m` to `24h`, written as whole minutes or hours such as `55m` or `2h`, without a sign or a leading zero. The client prints it in words: `55 minutes`, `1 hour`, `90 minutes`. It is the shortest time between two automatic claims.
- A manifest without `[schedule]` means the company did not define automatic sending. `schedule on` refuses, and you send claims by hand with `check`.

Turn the job on, look at it, or turn it off:

```sh
open-pact-client schedule on --dry-run
open-pact-client schedule on
open-pact-client schedule status
open-pact-client schedule off
```

`schedule on` prints the policy line, then `schedule: install`. A second run prints `no changes`, and a changed executable path prints `schedule: update`. Dry run prints the planned change and writes nothing. `schedule status` shows the company's policy, your choice, and the state of the job. Keep the client binary at its installed path. Use the same absolute `--home` for each command. If the entire client home is already missing, `schedule off` removes the remaining job without recreating that home. The job reads the policy from the manifest you signed. A manifest change needs no new `schedule on`.

Choose a `vpn_probe` that connects only on the company VPN. With `mode = "vpn"`, the job tries a TCP connection to it every five minutes, with a two-second timeout. Use brackets around IPv6 addresses. An address that also answers off the VPN makes the job send off the VPN.

A private address such as `10.0.0.1:443` can also exist on other networks, such as hotel or home routers, so a TCP connection alone can match the wrong network. With `vpn_probe_name`, the probe connects to `vpn_probe` without a DNS lookup of the name, and it needs a TLS certificate that is valid for that name. The certificate must chain to a root that the client trusts for its HTTPS requests. The probe has five seconds in total, and any HTTP status counts as an answer. The probe does not use a proxy. An empty value or an IP address for `vpn_probe_name` is an error in the manifest.

With `mode = "vpn"`, the job probes before it prepares the claim, again at the start of the send before any gateway request (the manifest, the log, a nonce), and once more before the POST of the claim. It sends when the last attempt that the gateway answered is older than `interval`, or when there is none. A connection that returns inside the interval does not send. With `mode = "always"`, it does not probe and sends every `interval`. An accepted claim and a denied claim both count as answered. So does an answer without a verdict: the device waits for approval, IT revoked it, the manifest awaits `accept`, or the log did not verify. The job then asks again only after the interval, and writes each piece of news to `schedule.log` once. A send that gets no answer (a network error) retries on the next run. It scans repositories at most once a day, before it takes the claim lock, and uses the stored counts between scans. The job takes the same lock as `check` and `accept` only for the gateway part, and it skips a run while one of them holds it. A command you start waits up to 60 seconds for the lock and prints one line that it waits for the scheduled job. A required control that changes from compliant to non-compliant triggers an extra claim at once, inside the interval. Missing results and `unknown` count as non-compliant without grace. Controls with no requirement do not trigger.

When the company changes the manifest and you have not yet run `accept`, the job keeps the policy of the manifest you signed. It writes the accept notice to `schedule.log`. The job also does nothing while automatic sending is off.

On Windows, a new Security event 1102 or Defender detection also triggers an extra claim. A limited task needs Event Log Readers access to read Security events. SYSTEM can read that log. The first successful read sets each event baseline. The job keeps pending events while offline. It sends at most one claim per run. Only an answer from the gateway clears pending events.

The job cannot ask you anything. When only you can fix a problem, it writes a dated line to `schedule.log` in the client home: a changed manifest (run `accept`), a gateway denial and its reasons, a device that waits for approval or that IT revoked, a transparency log alarm, or an error. The log keeps one old copy: the job moves `schedule.log` to `schedule.log.1` at the start of a run when the file has reached 256 KiB. The OS appends the job's output to the same file. Run `check` to see the full result. `claims.jsonl` keeps every claim and response, as for `check`.

macOS uses a launchd LaunchAgent. Linux uses a systemd user timer and needs a running user manager. Windows uses a limited Task Scheduler task when the job runs as you.

A `[report]` table in an old `open-pact.toml` has no effect. The client sends no separate report to a collector.

### Use Windows SYSTEM checks

The wizard asks whether the job runs as SYSTEM. Later, choose it with `schedule on --system`, and go back with `schedule on --user`. Run `schedule on --system` from an elevated PowerShell prompt:

```powershell
open-pact-client --home 'C:\Example User\pact' schedule on --system
```

Without elevation, the command prints the exact elevated command and changes nothing. Other operating systems reject `--system`. The installer copies the client into `%ProgramFiles%\open-pact\open-pact-client.exe` and refuses a directory that non-administrators can write. The SYSTEM job runs with `--system --user-home <profile>`. It reads the selected absolute client home, uses the repository folders from `device.json`, and keeps its state under protected `%ProgramData%`. Choose a home path without `%`. The task reads Windows settings and does not change them. See [platform support](platform-support.md) for checks that need SYSTEM access.

### Stop the scheduled claims and remove the client

Run `open-pact-client schedule off` with the same absolute `--home` before deleting the binary or client home. It removes the job, the applied-settings receipt, and the job state, and it records your no in `device.json`. Run `stop` to print these instructions. On Windows it prints the full path of the client and says that a SYSTEM job needs an elevated PowerShell prompt.

Limited Windows operations leave orphaned protected state and the shared binary unchanged. To remove those leftovers, run `schedule off` from an elevated PowerShell prompt. SYSTEM removal needs elevation and uses the existing protected state lock. A held lock stops task removal and asks you to retry. Removal cleans up the shared binary only when no SYSTEM task uses it. If cleanup fails, retry `schedule off` after the client stops or Windows restarts.

## Understand what leaves the device

`join` sends the invitation, signed manifest, owner and device public keys, and signatures that bind the owner, device, invitation, and manifest. It sends no private keys.

`accept` sends the new manifest hash, the owner public key, and signatures by the owner and device keys over both manifest hashes and a gateway nonce.

`check` and the scheduled job send the signed claim fields that the manifest permits. When the gateway enforces another manifest, they also send the manifest text that you signed, so the gateway can apply its terms. These include control results and permitted device metadata. The VPN certificate request travels beside the claim. Its private key stays on the device. The client stores claims and responses in `claims.jsonl`. `check --dry-run` prints the claim and sends none of it.

## Troubleshoot common failures

| Symptom | Action |
| --- | --- |
| Release verification fails | Get `scripts/verify-client-release.sh` from the matching repository tag or its source archive. Check that GitHub CLI and Cosign are installed. Run the script with a release tag. Install the matching binary from the printed directory after the script succeeds. |
| `join` refuses the gateway | Confirm the invitation URL, company key fingerprint, HTTPS certificate, and pinned log key with the gateway operator. |
| `check` reports that the manifest changed | Run `open-pact-client accept`. Review the changes and sign the new manifest. You need no new invitation or approval. |
| `check` says the device is pending | Give the device code to the gateway operator. Wait for approval. |
| A check returns `unknown` on Windows | Run the task as an elevated administrator when the control needs machine-wide access. Run `schedule on --system` from an elevated PowerShell prompt. |
| Windows event claims do not trigger | Check Event Log Readers access for the limited task user. Check that Defender history can be read. |
| Linux `schedule on` cannot reach systemd | Start the user systemd manager. Run `schedule on` again. |
| `schedule on` says the company did not define automatic sending | The signed manifest has no `[schedule]`. Send claims by hand with `check`, or ask the company to add the table. |
| Schedule does not send | Run `schedule status`. Read `schedule.log` in the client home. With `mode = "vpn"`, check that `vpn_probe` connects while the VPN is up and that the binary remains at its installed path. With `vpn_probe_name`, check that the probe presents a certificate for that name from a trusted root. |
| `schedule off` cannot find the job | Use the same absolute `--home` path that you used for `schedule on`. |
| The client says `open-pact.toml` is ignored | The file belongs to an earlier client. Use `schedule on` and `folders add` instead, then delete the file. |

## Remove the device key

To rotate or remove the device key, run `open-pact-client schedule off` first. Then run `open-pact-client --home <home> delete-device-key` before you delete the home or binary. Schedule removal alone keeps the key.

On Windows, use the account that created the CNG key or SYSTEM. A different administrator has no explicit access to the key. Windows CI tests deletion with the software CNG provider. Hosted runners do not verify deletion from a real TPM.

## Linux checks and detection reports

Run the client as the account that uses the device. `work_account` reports `admin` for membership in `sudo`, `wheel`, or `root`. The systemd user timer needs a running user manager. A container without that manager cannot install or exercise the user timer.

To use the Linux ClamAV detection trigger, route `clamonacc` or `clamd` detection output to the system journal. Give the client account read access to that journal. The client reads trusted process names and `FOUND` records. The scheduled job checks every five minutes while the VPN is connected. File-only logs do not supply this trigger. A denied journal read preserves the saved detection baseline.

The boot authentication check reads root and active swap mappings from `lsblk` and `/etc/crypttab`. An unspecified crypttab key reports `unknown` because automatic keys cannot be excluded. Explicit hardware PIN options report `user_secret`. A configured TPM2, FIDO2, or Clevis unlock reports `hardware_only`. A keyfile on a verified unencrypted filesystem reports `none`. Missing evidence reports `unknown`.

The check returns `unknown` if it cannot read `/proc/cmdline` or if its raw bytes contain `luks` anywhere. This conservative check avoids guessing how a LUKS unlock parameter combines with crypttab. A match inside an unrelated word also returns `unknown`. A command line without `luks` does not change the `lsblk` and `/etc/crypttab` result. See [Linux source limits](platform-support.md#linux-sources-and-limits) for policy locations and controls that remain unknown.

To run the Linux container scenarios, use `tests/linux-docker/run.sh`. Set `DISTROS=ubuntu` to run Ubuntu only. Set `PLATFORM=linux/amd64` or `PLATFORM=linux/arm64` to choose the target. The Docker build runs format verification, Clippy, and workspace tests before the scenarios. It builds the client and its check printer inside Linux. The test containers are removed after each run.
