# Install and use the client

The client runs only the checks that the signed manifest names. It sends a signed claim to the gateway when you run `check`. It sends a separate status report only when you run `report` or install a report schedule.

## Verify and install a release

Download the client release files and the verification script from the same repository. Verify the release before you install the binary:

```sh
scripts/verify-client-release.sh v0.2.0
```

The script checks the release hashes and Sigstore signatures against the tagged release workflow. It needs GitHub CLI, Cosign, and `sha256sum` or `shasum`. Set `GH_REPO` when you verify a release from a fork. Install the verified binary in a directory that your account can execute.

## Join and check the gateway

Get a one-time `opi1:` invitation from the gateway operator. Confirm the company key fingerprint with the operator over a second channel. Join with the invitation:

```sh
open-pact-client join 'opi1:replace-with-your-invitation'
```

The client checks the gateway keys and transparency checkpoint before it displays the manifest. Read the manifest before you approve the signature prompt. The owner key signs the manifest hash and the device enrolment statement. The gateway leaves the device pending until an operator approves its device code.

On macOS, `join` stores the device key in the Secure Enclave when one is available. Pass `--software-key` to use a software key instead. Windows and Linux use software keys. The owner key and the VPN certificate key are software keys on every platform.

After the operator approves the device, check it:

```sh
open-pact-client check
```

The client runs the checks in the signed manifest and sends one signed claim. It verifies the response and log checkpoint. It installs the VPN certificate and CA when the gateway accepts the claim. A denied check returns the gateway's reason. A log verification failure raises an alarm and exits with status 2.

Run `open-pact-client log head` to show the last verified checkpoint. Run `open-pact-client log prove` to verify the inclusion proof for this device's enrolment. Run `open-pact-client log show` to print the local record of claims and gateway responses.

## Send a report

Use `report --dry-run` to inspect a report without sending it:

```sh
open-pact-client report --collector https://collector.example.org/status --dry-run
```

The command prints the JSON report and its compact ES256 JWS. It sends nothing. The HTTPS collector must verify the JWS with the enrolled device's public key. A non-dry-run report sends the JWS to that collector. The collector must return an HTTP 2xx response.

A report includes `spec_version`, the device pseudonym in `device_id`, a random `report_id`, UTC time, client version in `solution`, OS name, and OS version. It also includes the key protection type and the results of the manifest checks. It does not include the public key. The gateway does not receive this report. It is a separate endpoint from the gateway claim API.

## Schedule reports while the VPN is connected

Choose a collector URL that the device can reach only through the VPN. Install a schedule with the same client binary that you will keep at that path:

```sh
open-pact-client schedule install --collector https://collector.internal.example.org/status
```

The scheduler checks a TCP connection to the collector host every five minutes. It sends the first report after it detects a VPN connection. It sends again after at least 55 minutes have passed since the last acknowledged report. It checks the VPN probe before preparing the report and again before sending it. Set `--vpn-probe host:port` if the collector host is not a suitable probe. A failed send retries on a later run. A lost acknowledgement can cause a duplicate report.

On Windows, the task also sends an extra report after it detects a new Security event 1102 or a new Defender detection. The next task run occurs within five minutes. The first successful read of each event source sets its baseline and does not send an event report. Later events trigger at most one extra report per five-minute run. The task saves event markers only after the collector acknowledges the report.

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
| Release verification fails | Download the script, checksums, signature bundles, and binary from the same release. Check that Cosign and GitHub CLI are installed. |
| `join` refuses the gateway | Confirm the invitation URL, company key fingerprint, HTTPS certificate, and pinned log key with the gateway operator. |
| `join` says the manifest needs consent | Read the displayed changes. Sign only if you accept the new manifest hash. |
| `check` says the device is pending | Give the device code to the gateway operator and wait for approval. |
| A check returns `unknown` on Windows | Run the task as an elevated administrator or install it with `schedule install --system` when the control needs machine-wide access. |
| Windows event reports do not trigger | Check Event Log Readers access for the limited task user. Check that Defender history can be read. |
| Linux schedule install cannot reach systemd | Start the user systemd manager, then run `schedule install` again. |
| Schedule does not send | Check that the collector uses HTTPS, the VPN probe is reachable only through the VPN, and the binary remains at its installed path. |
| `schedule uninstall` cannot find the job | Use the same absolute `--home` path that you used to install it. |
