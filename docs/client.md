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
sudo apt install ./open-pact-client_0.8.5_amd64.deb
```

For Fedora, download the `.rpm` from the [client releases](https://github.com/gaboe/open-pact/releases), then run:

```sh
sudo dnf install ./open-pact-client-0.8.5-1.x86_64.rpm
```

Homebrew and Scoop check the SHA-256 value recorded in their formula or manifest. They do not verify the Cosign signature. The Linux commands install local files, so verify them with the release steps below before you install them. Run `brew upgrade` or `scoop update open-pact` to update an installed client. For APT or DNF, download and install each new release when you choose to update.

## Verify a release

Run the verification script with a release tag:

```sh
scripts/verify-client-release.sh v0.8.5
```

The script checks every checksum and Sigstore bundle. For a release that has them, it also checks the desktop app zips (`open-pact-desktop-<version>-macos.zip` and `open-pact-desktop-<version>-windows-x64.zip`).

The desktop installers, `desktop/scripts/install-desktop.sh` and `install-desktop.ps1`, check the zip against its line in `SHA256SUMS`. They do not verify the Cosign signature.

The script keeps the verified files in a private temporary directory when verification succeeds. It removes the directory if verification fails. It prints the directory path on the last line. Copy that path for the install command.

A release can also include the Windows package `open-pact-client-x86_64-pc-windows-msvc.msi`. Install it with the block in [Install the machine client](#install-the-machine-client-for-the-system-job).

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

For Windows x86-64, run this copy for your own user. The SYSTEM job does not use it:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\bin" | Out-Null
Copy-Item "$verifiedDir\open-pact-client-x86_64-pc-windows-msvc.exe" "$env:USERPROFILE\bin\open-pact-client.exe"
```

The script needs GitHub CLI, Cosign, and `sha256sum` or `shasum`. Set `GH_REPO` when you verify a release from a fork.

The verified directory includes the `.deb` and `.rpm` packages. Install them with the matching package manager:

```sh
sudo apt install "$verified_dir/open-pact-client_0.8.5_amd64.deb"
sudo dnf install "$verified_dir/open-pact-client-0.8.5-1.x86_64.rpm"
```

## Run the Windows client under app control

The Windows binaries in a release of this repository are not Authenticode-signed, unless the repository sets the Artifact Signing variables. A release that an organization builds with its own signing, as in the next section, is signed. Windows checks a Windows binary in three ways:

- **SmartScreen.** A downloaded file can show "Windows protected your PC". Select **More info**, then **Run anyway**.
- **Smart App Control.** When it is on, Windows blocks an unsigned file and gives no way to run it. It runs a file that is signed with a certificate from a certificate authority in the Microsoft Trusted Root Program.
- **App Control for Business.** A managed device runs only what the organization's policy allows.

### Sign releases with Azure Artifact Signing

An organization can run the release workflow in its own fork and get Authenticode-signed Windows files. The workflow signs the three executables and the machine package `.msi` with [Azure Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/overview). The executables inside the desktop zip are signed; the zip itself is not. Signing is off until the repository sets the variables below. Without them, the release stays unsigned, with the same assets as before.

You need:

- An Artifact Signing account with a Public Trust certificate profile. Public Trust needs identity validation of the organization.
- An app registration in Microsoft Entra ID for the workflow. Give it the role "Artifact Signing Certificate Profile Signer" on the certificate profile.
- A federated credential on the app registration. The issuer is `https://token.actions.githubusercontent.com` and the audience is `api://AzureADTokenExchange`. The subject of a release run must match the subject format that the repository sends for a tag. The name-only format is `repo:<owner>/<repo>:ref:refs/tags/vX.Y.Z`. The immutable format is `repo:<owner>@<owner id>/<repo>@<repository id>:ref:refs/tags/vX.Y.Z`, and GitHub sends it by default for repositories created after 15 July 2026. Check which format your repository sends, then use the matching subject. See the [GitHub immutable subject claims](https://docs.github.com/en/actions/reference/security/oidc#immutable-subject-claims) and the [Microsoft Entra guide](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-github-immutable-subjects). A plain federated credential matches the subject exactly and allows no wildcard, so add one credential for each tag. To cover every tag with one credential, use a flexible federated credential (preview). For the name-only format, use the expression `claims['sub'] matches 'repo:<owner>/<repo>:ref:refs/tags/v*' and claims['repository_id'] eq '<repository id>'`. For the immutable format, use `claims['sub'] matches 'repo:<owner>@<owner id>/<repo>@<repository id>:ref:refs/tags/v*' and claims['repository_id'] eq '<repository id>'`.

Set these repository variables (Settings, Secrets and variables, Actions, Variables). They are identifiers, not secrets, and the login needs no secret:

| Variable | Value |
| --- | --- |
| `AZURE_CLIENT_ID` | Application (client) ID of the app registration |
| `AZURE_TENANT_ID` | Directory (tenant) ID |
| `AZURE_SUBSCRIPTION_ID` | Subscription ID of the signing account |
| `ARTIFACT_SIGNING_ENDPOINT` | Endpoint of the account, for example `https://eus.codesigning.azure.net` |
| `ARTIFACT_SIGNING_ACCOUNT` | Name of the signing account. The workflow signs only when this is set. |
| `ARTIFACT_SIGNING_PROFILE` | Name of the certificate profile |

Then push a version tag, as in the release steps of `CLAUDE.md`. The workflow signs in this order: it signs the three executables, builds the MSI from the signed client and the desktop zip from the signed executables, and then signs the MSI. It checks that every signed file has a valid signature and a timestamp, and stops the release when one does not. It then makes `SHA256SUMS` and the Cosign signature over the signed files. The Cosign signature is still made by the `sign` job of `client-release.yml` only. The signing job is a separate workflow, `authenticode.yml`, so its identity token cannot stand in for the release signature.

Verify a fork's release with the repository name of the fork:

```sh
GH_REPO=<owner>/<repo> scripts/verify-client-release.sh vX.Y.Z
```

The release workflow builds the client and the desktop apps with `OPEN_PACT_REPOSITORY` set to its own repository. The update check, the machine install block, and the desktop updater of that build then read releases of the fork. A build without this variable reads `gaboe/open-pact`. The package manager files that the release generates name the fork too.

A new certificate gets SmartScreen reputation only over time. A signed file can still show the SmartScreen prompt for a while.

### Sign a downloaded release yourself

An organization that uses Smart App Control or App Control for Business and does not run the release workflow signs the release itself:

1. Verify the release with `scripts/verify-client-release.sh`, as in [Verify a release](#verify-a-release).
2. Sign each Windows executable with the organization's code-signing certificate. Use the timestamp URL of the certificate authority:

   ```powershell
   signtool sign /fd sha256 /td sha256 /tr <timestamp-url> /a open-pact-client-x86_64-pc-windows-msvc.exe
   ```

   Sign the executables in the desktop app zip in the same way.
3. Give the signed files to users through the organization's own channel, such as Intune, a file share, or its own Scoop bucket.
4. For App Control for Business, allow the organization's signing certificate as a publisher, or allow each file by its hash.

The signature changes each file, so its SHA-256 value no longer matches `SHA256SUMS`. Verify the release before you sign it, and publish the new hashes in your own channel. The desktop installer checks the release zip against `SHA256SUMS`, so install signed desktop apps through your own channel. A new certificate gets SmartScreen reputation only over time; until then, users can still see the SmartScreen prompt.

## Join and check the gateway

On Windows, set `HOME` before you run the client. The client does not use `USERPROFILE` or `APPDATA` as a fallback. In PowerShell, set an absolute path with `$env:HOME = Join-Path $env:USERPROFILE 'pact'`.

Get a one-time `opi1:` invitation from the gateway operator. Confirm the gateway key fingerprint with the operator over a second channel. Join with the invitation:

```sh
open-pact-client join 'opi1:replace-with-your-invitation'
```

The client checks the gateway keys and transparency checkpoint before it displays the manifest. Read the manifest before you approve the signature prompt. The owner key signs the manifest hash and the device enrolment statement. The gateway leaves the device pending until an operator approves its device code. After it prints the code, `join` checks for approval every 10 seconds. It reports approval only after it verifies the device's `device_approved` entry in the signed log. Press Ctrl+C to stop waiting. The enrolment stays on disk, so run `join` again or run `check` later. Pass `--no-wait` to print the code and exit without polling.

Before you sign, step 2 of `join` prints the manifest summary and the absolute path of a file that holds the whole text. Open that file and read all of it. The company wrote it; it is the one file that says what is checked, what is sent and when. After an interactive `join` verifies approval, the wizard asks only for your own choices: whether to send claims automatically (only when the manifest defines automatic sending), on Windows whether the job runs as you or as SYSTEM, and the folders that hold your repositories (only when the manifest counts repositories). It then installs the job if you said yes and offers the first claim. You edit no file. If you stop, run `join` again to resume.

On macOS, `join` reuses an existing device key. It creates a Secure Enclave key only when no key exists and creation succeeds. If creation fails, the client warns and uses a software key. Pass `--software-key` to select a software key for a new device. On Windows, a new join needs an elevated administrator process and tries a TPM key. A non-elevated join stops before it sends anything, unless the home already holds a device key or `--software-key` is set; open PowerShell with Run as administrator and run the same command again. An unavailable provider uses a software key. Marker write and key ACL failures stop join. Linux uses software keys. The owner key and the VPN certificate key are software keys on every platform.

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

## Check a manifest draft

IT can test a draft before it publishes it. The command reads the draft from stdin and applies the rules that clients and the gateway apply to a new manifest: the core manifest rules, then the check that this client implements every builtin. It needs no home, no enrolment and no network.

```sh
open-pact-client manifest check < manifest.toml
open-pact-client manifest check --json < manifest.toml
```

It prints `Manifest is valid.` and exits 0, or prints one line per error and exits 1. Wrong arguments exit 2. With `--json`, stdout holds one document: `{"ok":true,"errors":[]}`, or `{"ok":false,"errors":[{"message":"...","line":12,"key":"log.witness_quorum"}]}`. `line` is the 1-based line of a TOML error, and `key` is the manifest key a rule error names. Each is `null` when the error has none. A draft that passes can still need a newer client if it uses a builtin that the client in your hand does not have.

`open-pact-client manifest builtins` lists each built-in check that this client runs, with its default text: one line per check, the check name such as `builtin:firewall@1`, two spaces, then the text. With `--json` it prints one array of objects with `check`, `id` and `about`. The default text lives only in the client. A control's `description` in the manifest replaces it in the manifest summary, and the apps read the default from this command.

### Accept a changed manifest

When the company changes the manifest, `check` prints a line that names the new hash and asks you to run `accept`. The device keeps its approval and VPN access meanwhile. Controls that the new manifest adds or tightens fail now. The gateway accepts claims for the length of each control's grace and warns you. When the grace runs out, access ends.

```sh
open-pact-client accept
```

The client fetches the new manifest and checks its company signature, the pinned keys and the log checkpoint under the new manifest's log policy. It shows the manifest and what changed against the one you signed: added, removed, and changed controls, `disclosed_metadata`, `claim_retention`, `claim_recipients`, `data_controller`, the minimum trust level, `unknown_grace`, `claim_max_age`, the issuer, the validity date and the log policy. A changed control shows its requirement for each operating system that differs. If you confirm, the owner key and the device key sign the new hash. The gateway moves the device to the new manifest without a new invitation or approval. The client then stores the new manifest, and the next `check` runs its checks. Pass `--yes` to sign without the prompt.

When a new manifest adds automatic sending, changes its mode or probe, shortens an interval, checks more often, or turns the wait for the interval at a connect into an immediate claim, `accept` turns automatic sending off after the gateway confirms the new manifest. Run `open-pact-client schedule on` to agree to the new schedule.

Before you sign, `accept` prints the absolute path of a copy of the whole new manifest, so you can read all of it. The copy is removed when the command ends. A change to `[schedule]` appears in the list of changes in plain words, such as the consent line above. When automatic sending stays on, `accept` also prints the new consent line and when the next check and the next claim fall due. Until you accept, the job keeps the policy of the manifest you signed.

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

The command runs the same local checks as `check` and prints the claim as JSON. It adds `manifest_toml` when the gateway enforces a different manifest. It makes GET requests for the manifest, log key, checkpoint, and any needed consistency proof. It sends no nonce request or signed POST. It writes no file. The dry run never suppresses the claim. When the saved device status is pending or revoked, it prints one `Last known status` line after the claim, because `check` asks the gateway again. It cannot verify private log entries or current device status because those checks need a signed request. When the dry run prints a claim, it also prints this line: `check also asks the gateway whether this device may send; the dry run skips that signed request.` The nonce, time, and VPN certificate request appear as placeholders. The scheduled job sends the same claim.

Add `--timings` to measure what one run costs:

```sh
open-pact-client check --dry-run --timings
```

It prints, on the error stream and after the claim, the wall time of the whole run and the CPU time (user and system) of the client process and of its child processes: `Timings: wall time of the whole run 0.62 s`, then one line for each. Unix reads both from `getrusage`. On Windows it reads the client process, and for the child processes it adds the CPU time of each command that a check ran, such as the PowerShell batch. Run it about twenty times on each kind of device and read the median before you set a short `check` period. `--timings` works only with `--dry-run`, and it writes and sends nothing more than the dry run does.

## Send claims automatically

The company decides whether the job may check and send, and how, in the `[schedule]` table of the signed manifest. The table is part of the signed text and its hash. You decide only whether to turn it on. The job runs the claim pipeline of `check` and sends the same claim. The gateway is the only server.

```toml
[schedule.vpn]                    # while the company VPN answers
probe = "10.0.0.1:443"            # host:port that answers only on the company VPN
probe_name = "vpn.example.org"    # optional TLS name that the probe must present
interval = "1h"                   # the longest time between claims on the VPN: 5m to 24h
check = "5m"                      # optional: how often the device checks itself on the VPN, 1m to 24h; default 5m

[schedule.always]                 # optional: on any network
interval = "24h"
```

- `[schedule.vpn]` works while `probe` answers. It needs `probe` and `interval`. `probe_name` and `check` are optional.
- `[schedule.always]` works on any network and needs no probe. The manifest needs at least one of the two tables.
- `interval` is a time from `5m` to `24h`, written as whole minutes or hours such as `55m` or `2h`, without a sign or a leading zero. `check` uses the same text. The client prints times in words: `5 minutes`, `1 hour`, `90 minutes`.
- The consent line says all of it in plain words, for example: `Automatic claims: on the company VPN (vpn.example.org at 10.0.0.1:443) checks every 5 minutes, sends at once on connect or when a result gets worse, and at least every hour; on any network every 24 hours, and at once when a result gets worse.` `schedule on`, `schedule status`, `accept`, and `manifest show` print this line. It is the text you agree to.
- The older flat table (`mode = "vpn"` or `"always"`, `vpn_probe`, `vpn_probe_name`, `interval`) still works and keeps its old meaning, with one exception that the next paragraphs name. A manifest without `[schedule]` means the company did not define automatic sending. `schedule on` refuses, and you send claims by hand with `check`.

Turn the job on, look at it, or turn it off:

```sh
open-pact-client schedule on --dry-run
open-pact-client schedule on
open-pact-client schedule status
open-pact-client schedule off
```

`schedule on` prints the policy line, then `schedule: install`, then `Your choice: automatic sending is on.` A second run prints `no changes` and the same choice line, and a changed executable path prints `schedule: update`. A job that client 0.7 installed wakes every five minutes: `schedule on` prints `schedule: update` and rewrites it to wake every minute on macOS, Linux and Windows. After a client update, a job that you run as your own user rewrites itself to the new definition on its first wake, once for each client version, and only while automatic sending is on and the signed manifest defines `[schedule]`; on macOS a short helper job reloads the LaunchAgent after the run ends. Dry run prints the planned change and writes nothing. `schedule status` shows the consent line, your choice, the state of the job, the last claim that the gateway answered, the last check, and when the next check and the next claim fall due. For a SYSTEM job on Windows it reads that job's protected state: run it from an elevated prompt. When the state cannot be read, `schedule status` and `accept` say that the times are unknown and why. It derives the due times from the same rules as the job, and it assumes that the device stays where the last run found it (on the VPN or not). Keep the client binary at its installed path. Use the same absolute `--home` for each command. If the entire client home is already missing, `schedule off` removes the remaining job without recreating that home. The job reads the policy from the manifest you signed. A manifest change that keeps or narrows the schedule needs no new `schedule on`. After `accept` signs a manifest that widens it, run `schedule on` again. A change that only checks more often counts as widening.

A SYSTEM job on Windows runs the machine client in Program Files. To upgrade it, run the install block in [Install the machine client](#install-the-machine-client-for-the-system-job). When the machine client is older than the client you run, `status`, `schedule status` and `check` say so. A newer machine client counts as current. So does one of the same version in another file.

### What one wake does

The OS wakes the job every minute. A wake costs one process start and, with a VPN table, one probe. It decides first, from the saved state and the clock, whether anything is due. When nothing is due, it exits at once: no check, no repository scan, no gateway request. `check --dry-run --timings` measures what a run costs on your machine.

- **On the VPN** the job checks every `check` period (at least five minutes on Windows, because one Windows check starts PowerShell) and on the first wake after the VPN connects. It sends at once on a connect, at once when a required control changes from compliant to non-compliant, and at least every `interval`. A connect claim goes at most once every five minutes: when the gateway answered a claim less than five minutes ago, a VPN that comes and goes does not send again, and the periodic claim and any change still do.
- **Off the VPN** the job only probes. It runs no check and sends nothing. With `[schedule.always]` it checks every five minutes, sends at once when a result gets worse, and sends every `interval` of that table.
- A claim that is due always runs fresh checks first.
- The flat 0.7 form keeps its interval gating: with `mode = "vpn"` it sends when the last answered attempt is older than `interval`, also at a connect, and with `mode = "always"` it sends every `interval`. The faster wake changes only how often it checks: every five minutes while the VPN answers (and every five minutes with `mode = "always"`), and on the first wake after a connect. It no longer runs checks off the VPN.

### Access ends when the device stops being compliant

The VPN accepts only a certificate that the gateway issued after a compliant claim, and the gateway never issues one that outlives the nearest grace deadline. The client adds a second step on the device. When a check finds a required control non-compliant and that control's grace has ended on this device, the job deletes the installed VPN certificate (`vpn/current`, every generation, and the files `ca.pem` and `vpn-cert.pem`), writes one line to `schedule.log` (`Removed the VPN certificate: firewall failed and its grace ended. A claim goes out at once.`), and sends a claim at once. Grace counts from the first check on this device that saw the failure, as the gateway counts from the first claim it saw. A grace of `0d` ends at once. A result that cannot be read counts against `unknown_grace`, also on a control with no grace. A control that passes starts its grace again. The client first saves the pending claim in its state file, so a crash after the deletion still sends the claim on the next run. Then it writes a `vpn-removal-pending` file in the client home and syncs it to disk, so an interruption (a crash, a power loss) cannot leave a usable certificate behind: the next claim, and on Windows the next start of a command that recovers the VPN files, finishes the deletion and never restores the certificate. If the deletion fails, for example because another program holds the file, the job logs the error once and still sends the claim at once. The claim does not wait for the deletion: a blocked recovery step before the send is logged and the claim goes out. A later claim that the gateway accepts installs a new certificate as always and removes that file. A denied claim installs none, so the device stays off the VPN until the control passes.

Choose a `probe` that connects only on the company VPN. The job tries a TCP connection to it, with a two-second timeout. Use brackets around IPv6 addresses. An address that also answers off the VPN makes the job send off the VPN.

A private address such as `10.0.0.1:443` can also exist on other networks, such as hotel or home routers, so a TCP connection alone can match the wrong network. With `probe_name`, the probe connects to `probe` without a DNS lookup of the name, and it needs a TLS certificate that is valid for that name. The certificate must chain to a root that the client trusts for its HTTPS requests. The probe has five seconds in total, and any HTTP status counts as an answer. The probe does not use a proxy. An empty value or an IP address for `probe_name` is an error in the manifest. (The flat form names them `vpn_probe` and `vpn_probe_name`.)

Where the schedule has a VPN table, the job probes on every wake, before it prepares the claim, again at the start of the send before any gateway request (the manifest, the log, a nonce), and once more before the POST of the claim. It sends nothing more when a probe fails. An accepted claim and a denied claim both count as answered. So does an answer without a verdict: the device waits for approval, IT revoked it, the manifest awaits `accept`, or the log did not verify. The job then asks again only after the interval, and writes each piece of news to `schedule.log` once. A send that gets no answer (a network error) retries on the next run. It scans repositories at most once a day, before it takes the claim lock, and uses the stored counts between scans. The job takes the same lock as `check` and `accept` only for the gateway part, and it skips a run while one of them holds it. A command you start waits up to 60 seconds for the lock and prints one line that it waits for the scheduled job. A required control that changes from compliant to non-compliant triggers an extra claim at once, inside the interval, when the next check finds it. Missing results and `unknown` count as non-compliant without grace. Controls with no requirement do not trigger.

When the company changes the manifest and you have not yet run `accept`, the job keeps the policy of the manifest you signed. It writes the accept notice to `schedule.log`. The job also does nothing while automatic sending is off.

On Windows, a new Security event 1102 or Defender detection also triggers an extra claim. A limited task needs Event Log Readers access to read Security events. SYSTEM can read that log. The first successful read sets each event baseline. The job keeps pending events while offline. It sends at most one claim per run. Only an answer from the gateway clears pending events.

The job cannot ask you anything. When only you can fix a problem, it writes a dated line to `schedule.log` in the client home (a Windows SYSTEM job writes it to its protected state directory below `C:\ProgramData\open-pact\system`, which an elevated prompt can read, and `status` reads there too: from a prompt that is not elevated it prints one line with the log path and says that reading it needs an elevated prompt, and `--json` gives that line as `last_job_log_note`): a changed manifest (run `accept`), a gateway denial and its reasons, a device that waits for approval or that IT revoked, a transparency log alarm, or an error. The log keeps one old copy: the job moves `schedule.log` to `schedule.log.1` at the start of a run when the file has reached 256 KiB. The OS appends the job's output to the same file. Run `check` to see the full result. `claims.jsonl` keeps every claim and response, as for `check`.

macOS uses a launchd LaunchAgent. Linux uses a systemd user timer and needs a running user manager. Windows uses a limited Task Scheduler task when the job runs as you.

A `[report]` table in an old `open-pact.toml` has no effect. The client sends no separate report to a collector.

### Install the machine client for the SYSTEM job

The SYSTEM job runs the machine client, which the package installs in the 64-bit Program Files folder. By default this is `C:\Program Files\open-pact-client\open-pact-client.exe`. Install the package before you run `schedule on --system`. Run this block in an elevated Windows PowerShell 5.1 prompt (`powershell.exe`, not `pwsh`). The block installs exactly version 0.9.0. It upgrades an older package. It does not change a newer package:

```powershell
& {
if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Run this block in Windows PowerShell 5.1: start powershell.exe as administrator, not pwsh.' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = 'Stop'
function AssertProtected($path) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Protected path is a reparse point' }
    $acl = if ($item.PSIsContainer) { [IO.Directory]::GetAccessControl($path) } else { [IO.File]::GetAccessControl($path) }
    $allowed = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $owner) { throw 'Protected path has a non-admin owner' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and ($rule.FileSystemRights -band 0xD0156) -and $allowed -notcontains $rule.IdentityReference.Value) {
            throw 'Protected path ACL grants write or modify to a non-admin principal'
        }
    }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this block from an elevated Windows PowerShell 5.1 prompt (powershell.exe).' }
$base = 'https://github.com/gaboe/open-pact/releases/download/v0.9.0'
$msiName = 'open-pact-client-x86_64-pc-windows-msvc.msi'
$folder = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('open-pact-install-' + [guid]::NewGuid())
if (Test-Path -LiteralPath $folder) { throw 'The install folder exists. Run this block again.' }
$security = New-Object Security.AccessControl.DirectorySecurity
$security.SetAccessRuleProtection($true, $false)
$security.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $account = New-Object Security.Principal.SecurityIdentifier($sid)
    $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($account, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
[void][IO.Directory]::CreateDirectory($folder, $security)
AssertProtected $folder
foreach ($name in @($msiName, 'SHA256SUMS', 'SHA256SUMS.sigstore.json')) {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile (Join-Path $folder $name)
}
$cosign = Join-Path $folder 'cosign.exe'
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-windows-amd64.exe' -OutFile $cosign
if ((Get-FileHash -LiteralPath $cosign -Algorithm SHA256).Hash -ne '9b85a88ebff2d9dd30ff4984a6f61f2cedc232dd87d81fa7f2ff3c0ed96c241c') { throw 'cosign.exe does not match its pinned hash.' }
$sums = Join-Path $folder 'SHA256SUMS'
& $cosign verify-blob --bundle (Join-Path $folder 'SHA256SUMS.sigstore.json') --certificate-identity 'https://github.com/gaboe/open-pact/.github/workflows/client-release.yml@refs/tags/v0.9.0' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' $sums
if ($LASTEXITCODE -ne 0) { throw 'Cosign could not verify SHA256SUMS.' }
$lines = @(Get-Content -LiteralPath $sums | Where-Object { $_ -match '\S' -and (($_ -split '\s+', 2)[1].TrimStart('*') -eq $msiName) })
if ($lines.Count -ne 1) { throw 'SHA256SUMS must list the package once.' }
$msi = Join-Path $folder $msiName
if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ne ($lines[0] -split '\s+')[0]) { throw 'The package does not match SHA256SUMS.' }
$log = Join-Path $folder 'install.log'
$msiexec = Join-Path ([Environment]::SystemDirectory) 'msiexec.exe'
$install = Start-Process -FilePath $msiexec -ArgumentList ('/i "' + $msi + '" /qn /norestart /l*v "' + $log + '"') -Wait -PassThru
Write-Output ('msiexec exit code: ' + $install.ExitCode)
if ($install.ExitCode -eq 3010) { Write-Output 'Restart Windows to finish the install.' }
elseif ($install.ExitCode -ne 0) { throw ('The install failed. See ' + $log) }
}
```

Exit code 3010 means that Windows needs a restart to finish the install.

To repair a package of the same version, run the next commands in the same prompt. Write the full path of the verified MSI between `@'` and `'@`. The install block leaves that MSI in its folder under `%ProgramData%`. The commands wait for `msiexec`. They stop when it fails.

```powershell
$msi = @'
<the full path of the verified MSI>
'@
$msiexec = Join-Path ([Environment]::SystemDirectory) 'msiexec.exe'
$repair = Start-Process -FilePath $msiexec -ArgumentList ('/fa "' + $msi + '" /qn /norestart') -Wait -PassThru
if ($repair.ExitCode -eq 3010) { Write-Output 'Restart Windows to finish the repair.' }
elseif ($repair.ExitCode -ne 0) { throw ('The repair failed. Exit code: ' + $repair.ExitCode) }
```

For a deployment with Intune or Group Policy, see [Windows machine install](windows-machine-install.md).

### Use Windows SYSTEM checks

The wizard asks whether the job runs as SYSTEM. Later, choose SYSTEM with `schedule on --system`. Run it from an elevated Windows PowerShell 5.1 prompt. Call the machine client by its full path, so that an older client on PATH never runs. Pass the profile of the user. The commands stop when the client file is missing or when the command fails.

To go back to a job that runs as you, do two steps for this one home. Do not uninstall the package.

- In an elevated prompt, remove the SYSTEM task of this home. Use the `--home` value of the task.
  - For a task of the machine client, use the command in [Stop the scheduled claims and remove the client](#stop-the-scheduled-claims-and-remove-the-client).
  - For a task of the old copy, use the removal block in the same section.
- In your own prompt, not an elevated one, run the command below with the same absolute client home that you used above.

```powershell
$clientHome = @'
<the absolute client home>
'@
open-pact-client --home $clientHome schedule on --user
```

1. Replace the line `<the absolute client home>` with the absolute client home of the user.
2. Replace the line `<the profile folder of the user>` with the profile folder of the user.
3. Keep each value on its own line, between `@'` and `'@`. Do not add quotes. A path with an apostrophe then needs no escape.

```powershell
$q = Join-Path $env:ProgramW6432 'open-pact-client\open-pact-client.exe'
$clientHome = @'
<the absolute client home>
'@
$userHome = @'
<the profile folder of the user>
'@
if (-not (Test-Path -LiteralPath $q -PathType Leaf)) { throw 'The machine client is missing. Install the package, then run this command again.' }
$global:LASTEXITCODE = $null
& $q --home $clientHome schedule on --system --user-home $userHome
if ($LASTEXITCODE -ne 0) { throw 'schedule on failed. Fix the error, then run this command again.' }
```

Without elevation, `schedule on --system` prints the exact elevated command and changes nothing. When the package is missing, a client that can run prints the install block before it checks for elevation. The start commands above stop with a short message in that case. Other operating systems reject `--system`. The package installs the machine client at `%ProgramFiles%\open-pact-client\open-pact-client.exe`, in a folder that non-administrators cannot write. The SYSTEM job runs only that file, and nothing is copied.

The SYSTEM job runs with `--system --user-home <profile>`. It reads the selected absolute client home. It uses the repository folders from `device.json`. It keeps its state under protected `%ProgramData%`. Choose a home path without `%`. `--user-home` must be the profile folder of a user account that Windows lists in its profile registry, and not a link. The client ignores `USERPROFILE` and the arguments of a task that a user can write. The install block that the client prints runs in an elevated Windows PowerShell 5.1 prompt (`powershell.exe`), not in `pwsh`. The task reads Windows settings and does not change them. See [platform support](platform-support.md) for checks that need SYSTEM access.

A SYSTEM job reads repositories only below the user profile. A worktree whose repository lies outside it, for example on `D:\`, makes the repository counts unknown. Keep the repository below the profile. To run the job as you instead, follow the two steps above, and remove the SYSTEM task first.

### Stop the scheduled claims and remove the client

For a job that you run as your user, run `open-pact-client schedule off` with the same absolute `--home` before deleting the binary or client home. For a SYSTEM job on Windows, follow the steps below instead.

`schedule off` removes the job, the applied-settings receipt, and the job state. It saves automatic sending as off in an existing client home.

Run `stop` to print these instructions. For a SYSTEM job on Windows, `stop` prints the full path of the client when the machine client can run. When it cannot, `stop` prints a block that uses Windows tools only and has no client path. Either way, a SYSTEM job needs an elevated PowerShell prompt.

On Windows, remove each SYSTEM task before you uninstall the package. Uninstalling the package does not remove SYSTEM tasks. Run every command in an elevated Windows PowerShell 5.1 prompt.

First, list the SYSTEM tasks. The command selects tasks by their principal and by the program that they run, never by the name prefix alone. A task of a limited user is not listed. Write down the task name, the number of actions, the program and the `--home` value of each task:

```powershell
& {
  $legacy = Join-Path $env:ProgramW6432 'open-pact\open-pact-client.exe'
  $machine = Join-Path $env:ProgramW6432 'open-pact-client\open-pact-client.exe'
  $system = @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18')
  $programs = @($legacy, $machine)
  Get-ScheduledTask -TaskPath '\' | Where-Object {
    $_.TaskName -like 'org.open-pact.report.*' -and
    ($system -contains $_.Principal.UserId) -and
    @($_.Actions | Where-Object { $_.Execute -and ($programs -contains ($_.Execute.Trim('"') -replace '^\\\\\?\\', '')) }).Count -gt 0
  } | ForEach-Object {
    'Task: ' + $_.TaskName
    'Actions: ' + @($_.Actions).Count
    'Program: ' + (($_.Actions | ForEach-Object { $_.Execute }) -join ' ')
    'Arguments: ' + (($_.Actions | ForEach-Object { $_.Arguments }) -join ' ')
  }
}
```

A task whose program is the machine client needs one command. It removes the task, the job state, and the applied-settings receipt. It saves automatic sending as off in an existing client home. It clears a pending SYSTEM choice. The command stops when the client file is missing or when `schedule off` fails.

1. Replace the line `<the absolute client home>` with the `--home` value of the task.
2. Keep the value on its own line, between `@'` and `'@`. Do not add quotes.

```powershell
$q = Join-Path $env:ProgramW6432 'open-pact-client\open-pact-client.exe'
$clientHome = @'
<the absolute client home>
'@
if (-not (Test-Path -LiteralPath $q -PathType Leaf)) { throw 'The machine client is missing. Install the package, then run this command again.' }
$global:LASTEXITCODE = $null
& $q --home $clientHome schedule off
if ($LASTEXITCODE -ne 0) { throw 'schedule off failed. Do not uninstall the package. Fix the error, then run this command again.' }
```

A task whose Actions line is not 1 is not a task of the client. `schedule off` refuses such a task. Open it in Task Scheduler and read every action. When you know each action, remove the task in Task Scheduler.

A task whose program is the old copy, `open-pact\open-pact-client.exe`, and whose Actions line is 1, needs the removal block. The list can show the program with a `\\?\` prefix. It is the same file. The block shows two samples.

1. Replace the task name `org.open-pact.report.0123456789abcdef` in every place where it appears.
2. Replace the home line `C:\Users\example\pact`, between `@'` and `'@`, with the `--home` value of the task. Do not add quotes.

 The client prints this block with the values of your device when it refuses to change an old task.

```powershell
& {
  $schtasks = Join-Path ([Environment]::SystemDirectory) 'schtasks.exe'
  function Test-TaskRegistered {
    # The Task Scheduler COM API reports a missing task as HRESULT 0x80070002, in every display language.
    $service = New-Object -ComObject Schedule.Service
    $service.Connect()
    try {
      [void]$service.GetFolder('\').GetTask('\org.open-pact.report.0123456789abcdef')
      return $true
    } catch {
      $e = $_.Exception
      while ($e.InnerException) { $e = $e.InnerException }
      if ($e.HResult -eq -2147024894) { return $false }
      throw ('Could not query the task. ' + $_)
    }
  }
  function End-TaskQuietly {
    # /End fails for a task that is not running. That does not matter here: /Delete decides.
    $ErrorActionPreference = 'Continue'
    & $schtasks /End /TN 'org.open-pact.report.0123456789abcdef' 2>$null | Out-Null
  }
  if (Test-TaskRegistered) {
    End-TaskQuietly
    & $schtasks /Delete /TN 'org.open-pact.report.0123456789abcdef' /F
    if ($LASTEXITCODE -ne 0) { throw 'The task was not removed. Run this block again from an elevated prompt.' }
  }
  if (Test-TaskRegistered) { throw 'The task is still registered. Run this block again.' }
  $q = Join-Path $env:ProgramW6432 'open-pact-client\open-pact-client.exe'
  if (-not (Test-Path -LiteralPath $q -PathType Leaf)) { throw 'The machine client is missing. Install the package, then run this block again.' }
  $clientHome = @'
C:\Users\example\pact
'@
  $global:LASTEXITCODE = $null
  & $q --home $clientHome schedule off
  if ($LASTEXITCODE -ne 0) { throw 'schedule off failed. Do not uninstall the package. Fix the error, then run this block again.' }
}
```

The block deletes the task. It then checks that the machine client exists and runs `schedule off` with it. `schedule off` waits for the state lock, then removes the job state. When the file is missing or `schedule off` fails, for example because a tick holds the lock, the block throws. Do not uninstall the package then. Fix the error and run the block again.

Run the first command again. It must print nothing. Then uninstall the package. A SYSTEM task that runs another program can come from an older open-pact client. The client does not change it. To remove it without the package, follow [Remove a task without the package](windows-machine-install.md#remove-a-task-without-the-package). That block uses Windows tools only. It deletes the task name that you give it and does not check the program.

## Read the output as JSON

A desktop app can drive the client through these flags. Each prints JSON on stdout and nothing else; warnings stay on stderr. A failure prints `{"error": "<text>"}` on stdout and exits non-zero. This includes a command line that does not parse, which exits 2, and a panic. A command that cannot write its JSON, because stdout is closed or full, exits non-zero instead of reporting success. `status --json` follows the same rule. Without the flag the output is the text you read in the other sections.

| Command | Prints |
| --- | --- |
| `join --preview 'opi1:…'` | One document, then exit 0. It does what `join` does up to the manifest: it checks the invitation, the gateway, the company key against the invitation, and the manifest and its signature. It signs nothing, writes no file and sends no POST. |
| `join --yes --json ['opi1:…']` | One line per wizard step event, then a last line. Nothing is asked. |
| `check --json` | One document after the claim was sent. |
| `accept --preview` | One document. It signs nothing, writes no file and sends only GET requests. |

### `join --preview`

```json
{
  "company": {"name": "company.example", "key_fingerprint": "sha256:…", "matches_invitation": true},
  "gateway": "https://pact.example.com",
  "manifest_hash": "sha256:…",
  "controls": [
    {"id": "password_min_length", "title": "Password min length", "requirement": ">= 10", "rationale": "…"}
  ],
  "disclosed_metadata": ["os", "client_version"],
  "schedule": {"mode": "vpn", "vpn_probe": "10.0.0.1:443", "interval": "55m"},
  "folders": ["/home/example/work"]
}
```

- `company.name` is the manifest issuer. `matches_invitation` is false when the gateway's company key or log key differs from the invitation. The command still prints the document, then exits 1. Do not sign.
- `title` is the control id in words. `requirement` is the rule for this operating system, `n/a`, or `report only`. `rationale` appears only when the manifest has one.
- `schedule` is the manifest's `[schedule]` table, or null when the manifest defines no automatic sending.
- `folders` lists the folders the repository checks would use: the folders already chosen on this device plus the folders that hold the managed repositories a read-only scan finds. It is empty when the manifest has no repository control. The scan stores nothing.

### `join --json`

`--json` needs `--yes`. Give the answers that step 5 asks for as flags:

- `--folder <path>`, repeatable: a folder that holds your repositories. The client uses it only when the manifest counts repositories.
- `--auto-send on|off`: send claims automatically. The default is `off`. The client turns it on only when the manifest defines automatic sending.

Every step prints `{"step": 1-6, "title": "...", "state": "started"|"done"|"waiting"|"skipped", "detail": {...}}`. `detail` is optional. Step 4 prints `waiting` with `{"device_code": "..."}` while it waits for IT; give the code to IT. Steps that do not run, for example because the device is enrolled already, print `skipped`. The last line is `{"result": "enrolled"|"approved"|"done", "device": "pseudonym:…", "manifest_hash": "sha256:…"}`:

- `enrolled`: the device is enrolled and waits for approval. `--no-wait` stops here.
- `approved`: IT approved the device, but setup did not finish or the first claim was denied. A denied first claim exits 1; its reasons are in the `detail` of step 6.
- `done`: setup is complete and the first claim was accepted.

On a failure the last line is `{"error": "..."}`. A failure that an app can act on adds a fixed `"code"`: `"needs_elevation"` means a new Windows join ran without administrator rights and sent nothing. When the command has no error of its own, the text is the last message it would have printed. Ctrl+C prints `{"error": "interrupted"}` and exits 130. Run `join --json` without the invitation to resume an enrolled device.

### `check --json`

```json
{
  "sent_at": "2026-11-02T10:00:00Z",
  "accepted": true,
  "warnings": [],
  "reasons": [],
  "controls": [{"id": "os_supported", "value": "yes", "ok": true}]
}
```

`accepted` is false when the gateway denied the claim; `reasons` then says why and the exit code is 1. `warnings` appear on an accepted claim. `value` is what the device reported. `ok` tells whether the manifest requires the control on this system and accepts the value; it is null for a control the manifest does not require. A claim that was not sent, such as for a pending device or after a log alarm, prints `{"error": "..."}` instead (exit code 1, or 2 for a log alarm).

### `accept --preview`

```json
{
  "signed_hash": "sha256:…",
  "published_hash": "sha256:…",
  "changes": [
    {"id": "password_min_length", "before": null, "after": ">= 10 on linux …; check builtin:password_min_length@1"}
  ],
  "schedule_widened": false
}
```

`changes` has one entry per change that the text list of `accept` shows. `id` is the control id, or one of `disclosed_metadata`, `claim_retention`, `claim_recipients`, `data_controller`, `issuer`, `valid_from`, `claim_max_age`, `unknown_grace`, `min_trust_level`, `schedule`, `log_witnesses`, `log_witness_quorum`, `log_allows_split_views`, `log_checkpoint_max_age`. `before` is null for an added control and `after` is null for a removed one. `schedule_widened` is true when the new schedule adds automatic sending, changes its mode or probe, or shortens its interval; `accept` then turns automatic sending off. When the device signed the manifest the gateway enforces, `changes` is empty.

## Show the device status

Run `status` to see where the device stands. It reads the client home and prints a summary. It never runs the checks, never sends a claim, never accepts a manifest, and writes no file.

```sh
open-pact-client status
open-pact-client status --online
open-pact-client status --json
```

The summary shows:

- a headline: no known problem, action needed, log alarm, or some status unknown
- one numbered item for each problem, with the fix, the command to run, and the deadline
- whether IT approved, left pending, or revoked this device
- your choice for automatic sending, the state of the job, the signed schedule, and the VPN probe
- the send time and the response time of the last claim, and whether the gateway accepted or denied it
- the time of the last claim that the scheduled job sent, when it differs from the last claim
- whether the manifest you signed is the manifest the gateway enforces
- the state of the transparency log

The local view is the default. It reads only the files in the client home and makes no network or OS query. It marks approval and manifest agreement as saved or unknown, and it prints the `status --online` command to refresh them. `--online` asks the gateway for the current approval, manifest, and log checkpoint, probes the VPN address from the signed schedule, and asks the OS about the job. It authenticates to the gateway only after the pinned keys and the checkpoint verify, and it stops with an alarm when they do not. It does not store the checkpoint.

`status` cannot tell you that the device is compliant now. Only `check` runs the checks and gets a new answer. The gateway words its grace warning as a time left, for example `access ends in 23h`. The summary adds the absolute time, which is the time of the response plus that span. The gateway rounds the span down, so the time is approximate. Without such a span in the warning, the deadline is unknown.

The exit code tells a script what to do:

| Code | Meaning |
| --- | --- |
| 0 | No known problem. Only an online report can return it: approved, same manifest, accepted last claim, and a job that matches your choice. |
| 1 | Action needed. At least one item has a fix. |
| 2 | Alarm. A log or key verification failed. Keep the checkpoint and tell IT. |
| 3 | Unknown. Some status is unconfirmed, or enrolment is missing or damaged. Local mode cannot return 0. It returns 1 or 2 when a recorded issue takes precedence, and otherwise returns 3. |

`--json` prints the same evidence, items, and exit code as one JSON document. `schedule status` stays the detailed view of the schedule and the job.

`status --online` also asks GitHub for the latest release of the client. The request is one GET to `api.github.com` with the User-Agent `open-pact-client/<version>`, with a 3 second limit. When a newer release exists, the report ends with a line that names it, and it gives the update command for a Homebrew or Scoop install. Set `OPEN_PACT_NO_UPDATE_CHECK=1` to send no request. A failed check adds nothing to the report and does not change the exit code.

## Understand what leaves the device

`join` sends the invitation, signed manifest, owner and device public keys, and signatures that bind the owner, device, invitation, and manifest. It sends no private keys.

`accept` sends the new manifest hash, the owner public key, and signatures by the owner and device keys over both manifest hashes and a gateway nonce.

`check` and the scheduled job send the signed claim fields that the manifest permits. When the gateway enforces another manifest, they also send the manifest text that you signed, so the gateway can apply its terms. These include control results and permitted device metadata. The VPN certificate request travels beside the claim. Its private key stays on the device. The client stores claims and responses in `claims.jsonl`. `check --dry-run` makes GET requests only, prints the claim that `check` would send, and sends no claim.

## Troubleshoot common failures

| Symptom | Action |
| --- | --- |
| Release verification fails | Get `scripts/verify-client-release.sh` from the matching repository tag or its source archive. Check that GitHub CLI and Cosign are installed. Run the script with a release tag. Install the matching binary from the printed directory after the script succeeds. |
| `join` refuses the gateway | Confirm the invitation URL, company key fingerprint, HTTPS certificate, and pinned log key with the gateway operator. |
| `check` reports that the manifest changed | Run `open-pact-client accept`. Review the changes and sign the new manifest. You need no new invitation or approval. |
| `check` says the device is pending | Give the device code to the gateway operator. Wait for approval. |
| A check returns `unknown` on Windows | Run the task as an elevated administrator when the control needs machine-wide access. For a SYSTEM job, follow [Use Windows SYSTEM checks](#use-windows-system-checks). Run its full-path commands in an elevated PowerShell 5.1 prompt. |
| Windows event claims do not trigger | Check Event Log Readers access for the limited task user. Check that Defender history can be read. |
| Linux `schedule on` cannot reach systemd | Start the user systemd manager. Run `schedule on` again. |
| `schedule on` says the company did not define automatic sending | The signed manifest has no `[schedule]`. Send claims by hand with `check`, or ask the company to add the table. |
| Schedule does not send | Run `schedule status`. Read `schedule.log` in the client home. Check that `probe` (flat form `vpn_probe`) connects while the VPN is up and that the binary remains at its installed path. With `probe_name`, check that the probe presents a certificate for that name from a trusted root. A wake that finds nothing due writes nothing: `schedule status` shows when the next check and claim fall due. |
| `schedule off` cannot find the job | Use the same absolute `--home` path that you used for `schedule on`. |
| The client says `open-pact.toml` is ignored | The file belongs to an earlier client. Use `schedule on` and `folders add` instead, then delete the file. |

## Remove the device key

To rotate or remove the device key, remove the schedule first. For a job that runs as you, run `open-pact-client schedule off`. For a Windows SYSTEM job, remove the task of this home only, as [Stop the scheduled claims and remove the client](#stop-the-scheduled-claims-and-remove-the-client) describes. Do not uninstall the package. Then run `open-pact-client --home <home> delete-device-key` before you delete the home or binary. Schedule removal alone keeps the key.

On Windows, use the account that created the CNG key or SYSTEM. A different administrator has no explicit access to the key. Windows CI tests deletion with the software CNG provider. Hosted runners do not verify deletion from a real TPM.

## Linux checks and detection reports

Run the client as the account that uses the device. `work_account` reports `admin` for membership in `sudo`, `wheel`, or `root`. The systemd user timer needs a running user manager. A container without that manager cannot install or exercise the user timer.

To use the Linux ClamAV detection trigger, route `clamonacc` or `clamd` detection output to the system journal. Give the client account read access to that journal. The client reads trusted process names and `FOUND` records. The scheduled job reads it on each check: every `check` period (five minutes unless the manifest says otherwise) while the VPN is connected. File-only logs do not supply this trigger. A denied journal read preserves the saved detection baseline.

The boot authentication check reads root and active swap mappings from `lsblk` and `/etc/crypttab`. An unspecified crypttab key reports `unknown` because automatic keys cannot be excluded. Explicit hardware PIN options report `user_secret`. A configured TPM2, FIDO2, or Clevis unlock reports `hardware_only`. A keyfile on a verified unencrypted filesystem reports `none`. Missing evidence reports `unknown`.

The check returns `unknown` if it cannot read `/proc/cmdline` or if its raw bytes contain `luks` anywhere. This conservative check avoids guessing how a LUKS unlock parameter combines with crypttab. A match inside an unrelated word also returns `unknown`. A command line without `luks` does not change the `lsblk` and `/etc/crypttab` result. See [Linux source limits](platform-support.md#linux-sources-and-limits) for policy locations and controls that remain unknown.

To run the Linux container scenarios, use `tests/linux-docker/run.sh`. Set `DISTROS=ubuntu` to run Ubuntu only. Set `PLATFORM=linux/amd64` or `PLATFORM=linux/arm64` to choose the target. The Docker build runs format verification, Clippy, and workspace tests before the scenarios. It builds the client and its check printer inside Linux. The test containers are removed after each run.
