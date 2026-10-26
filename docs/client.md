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

## Send a report

Use `report --dry-run` to inspect a report without sending it:

```sh
open-pact-client report --collector https://collector.example.org/status --dry-run
```

The command prints the JSON report and its compact ES256 JWS. It sends nothing. The HTTPS collector must verify the JWS with the enrolled device's public key. A non-dry-run report sends the JWS to that collector. The collector must return an HTTP 2xx response.

A report includes `spec_version` set to `1.1`, the device pseudonym in `device_id`, a random `report_id`, UTC time, client version in `solution`, OS name, and OS version. `device_id` is the enrolled device pseudonym, `pseudonym:` followed by the SHA-256 hash of its uncompressed SEC1 public key. The gateway stores this identifier. `solution` is `open-pact-client <version>`. `report_type` is `connect`, `event`, or `periodic`. Manual reports use `periodic`. A connection report takes precedence over a pending event. It also includes the key protection type and the results of the manifest checks. It does not include the public key. The gateway does not receive this report. It is a separate endpoint from the gateway claim API.

## Schedule reports while the VPN is connected

Choose a collector URL that the device can reach only through the VPN. Install a schedule with the same client binary that you will keep at that path:

```sh
open-pact-client schedule install --collector https://collector.internal.example.org/status
```

The scheduler checks a TCP connection to the collector host every five minutes. It sends the first report after it detects a VPN connection. A transition from disconnected to connected also triggers a report. Otherwise, it sends again after at least 55 minutes have passed since the last acknowledged report. It checks the VPN probe before preparing the report and again before sending it. Set `--vpn-probe host:port` if the collector host is not a suitable probe. A failed send retries on a later run. A lost acknowledgement can cause a duplicate report.

Every task run evaluates results against the signed manifest's requirements for this OS. A change from compliant to non-compliant triggers an extra report within the next five-minute run. Missing results and `unknown` count as non-compliant, without grace. Reported-only controls never trigger. The first acknowledged report sets a compliance baseline. The task replaces that baseline only after the collector acknowledges the results sent.

On Windows, a new Security event 1102 or any new Defender detection also triggers an extra report. A resolved detection still triggers. The first successful read of each event source sets its baseline. Later event marker advances are saved only after acknowledgment. The task sends at most one report per run.

The task evaluates locally while the VPN is down and holds detected events until the next connection. A compliance failure stays pending even if the control recovers before that connection. The connection report sends current results. A failed send keeps the event pending. Only acknowledgment clears it. Events before the first successful baseline read are part of that baseline.

For a limited Windows task, add the task user to the built-in `Event Log Readers` group to read Security event 1102. A SYSTEM task can read the Security log without that group. Without either access, the Security log clear trigger is unavailable. The Defender detection trigger still works when Defender history is readable.

macOS uses a launchd LaunchAgent. Linux uses a systemd user timer and needs a running user manager. Windows uses a limited Task Scheduler task by default. No client daemon runs until you install the schedule.

Uninstall the schedule before you remove the binary or its home directory:

```sh
open-pact-client schedule uninstall
```

Use the same `--home` value for install and uninstall. The schedule keeps its configuration and state in the client home. The command removes the operating-system job, schedule configuration, and report state.

### Install a Windows SYSTEM task

Run an elevated prompt to install the task as SYSTEM:

```powershell
open-pact-client --home 'C:\Example User\pact' schedule install --system --collector https://collector.internal.example.org/status
```

The installer copies the binary to `%ProgramFiles%\open-pact\open-pact-client.exe`. It refuses a binary directory that non-administrators can write. SYSTEM reads the selected user's absolute `--home` path and stores report state under `%ProgramData%`. Choose a home path without `%`. The task reads Windows settings. It does not change them. See the [platform support table](platform-support.md) for controls that need SYSTEM or administrator access.

Remove a limited task with `open-pact-client --home 'C:\Example User\pact' schedule uninstall`. Run the command as the task user. If the command finds a SYSTEM task, use an elevated prompt and remove it with:

```powershell
open-pact-client --home 'C:\Example User\pact' schedule uninstall --system
```

SYSTEM uninstall can remove this home's limited or SYSTEM task. It also removes protected report state and cleans up the shared binary when no SYSTEM task uses it. Keep the absolute `--home` value from installation. If cleanup remains incomplete, retry from an elevated prompt after the client stops or after Windows restarts.

## Understand what leaves the device

`join` sends the invitation, signed manifest, owner and device public keys, and signatures that bind the owner, device, invitation, and manifest. It does not send private keys.

`check` sends a signed claim. It includes the manifest hash, device pseudonym, public key, nonce, time, client version, OS, asserted trust level, and VPN request hash. The manifest lists this metadata and each control's allowed outputs. It can also list `virtualized` and `log_checkpoint`. The claim includes those fields only when the manifest lists them. The claim includes results only for controls in the manifest.

The VPN certificate request travels beside the signed claim. It contains the VPN public key. The private VPN key stays on the device. The gateway stores the signed claim and certificate hash, not the request. The client also stores each claim and response in `claims.jsonl`.

`report` sends a separate signed JSON Web Signature to the HTTPS collector. It contains the fields listed above and the control results. It does not contain raw system logs or the device public key. A scheduled report uses this same payload and sends only when the VPN probe succeeds.

## Troubleshoot common failures

| Symptom | Check |
| --- | --- |
| Release verification fails | Get `scripts/verify-client-release.sh` from the matching repository tag or its source archive. Check that GitHub CLI and Cosign are installed. Run the script with a release tag. Install the matching binary from the printed directory after the script succeeds. |
| `join` refuses the gateway | Confirm the invitation URL, company key fingerprint, HTTPS certificate, and pinned log key with the gateway operator. |
| `check` reports a manifest hash mismatch | Get a new invitation for the current manifest. Run `join` with that invitation. Review the manifest. Sign its hash during `join`. Ask the gateway operator to approve the device again for the current manifest. `join` reuses the existing device key, so the device code stays the same. |
| `check` says the device is pending | Give the device code to the gateway operator. Wait for approval. |
| A check returns `unknown` on Windows | Run the task as an elevated administrator or install it with `schedule install --system` when the control needs machine-wide access. |
| Windows event reports do not trigger | Check Event Log Readers access for the limited task user. Check that Defender history can be read. |
| Linux schedule install cannot reach systemd | Start the user systemd manager. Run `schedule install` again. |
| Schedule does not send | Check that the collector uses HTTPS, the VPN probe is reachable only through the VPN, and the binary remains at its installed path. |
| `schedule uninstall` cannot find the job | Use the same absolute `--home` path that you used to install it. |

## Linux checks and detection reports

Run the client as the account that uses the device. `work_account` reports `admin` for membership in `sudo`, `wheel`, or `root`. The systemd user timer needs a running user manager. A container without that manager cannot install or exercise the user timer.

To use the Linux ClamAV detection trigger, route `clamonacc` or `clamd` detection output to the system journal. Give the client account read access to that journal. The client reads trusted process names and `FOUND` records. The report timer checks every five minutes while the VPN is connected. File-only logs do not supply this trigger. A denied journal read preserves the saved detection baseline.

The boot authentication check reads root and active swap mappings from `lsblk` and `/etc/crypttab`. An unspecified crypttab key reports `unknown` because automatic keys cannot be excluded. Explicit hardware PIN options report `user_secret`. A configured TPM2, FIDO2, or Clevis unlock reports `hardware_only`. A keyfile on a verified unencrypted filesystem reports `none`. Missing evidence reports `unknown`.

The check returns `unknown` when the raw bytes of `/proc/cmdline` contain `luks` anywhere. This conservative check avoids guessing how a LUKS unlock parameter combines with crypttab. It can also return `unknown` when `luks` appears inside an unrelated word. Other command lines, such as `quiet splash root=UUID=...`, do not change the crypttab result. See [Linux source limits](platform-support.md#linux-sources-and-limits) for policy locations and controls that remain unknown.

To run the Linux container scenarios, use `tests/linux-docker/run.sh`. Set `DISTROS=ubuntu` to run Ubuntu only. Set `PLATFORM=linux/amd64` or `PLATFORM=linux/arm64` to choose the target. The Docker build runs format verification, Clippy, and workspace tests before the scenarios. It builds the client and its check printer inside Linux. The test containers are removed after each run.
