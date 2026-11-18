# open-pact

Verifiable security checks on personally owned devices, without blanket monitoring. The owner signs the company's manifest once. Each time the device connects, the client sends one small signed claim to the company gateway, and a compliant device gets a short-lived VPN client certificate. Read [PAPER.md](PAPER.md) for the design.

Status: proof of concept, not for production. On macOS, `join` tries a Secure Enclave device key. On Windows, an elevated administrator join tries a TPM device key. These keys report trust level L1. If the Windows provider is unavailable, if macOS hardware key creation fails, on Linux, or with `join --software-key`, the device key is a software key with trust level L0. The gateway has no attestation, so it counts every claim as L0 whatever the client reports. The gateway enforces [examples/manifest.toml](examples/manifest.toml), or the file in `MANIFEST_PATH`.

## Layout

- `crates/open-pact-core` manifest, signatures, narrowing, claims (RFC 8785 + JWS), evaluation, the Merkle transparency log and signed checkpoints
- `crates/open-pact-client` CLI: `join <invitation>`, `check`, `status [--online] [--json]`, `accept`, `manifest show`, `schedule on|off|status`, `folders list|add|remove`, `log head`, `log prove`, `log show`, `stop`
- `crates/open-pact-gateway` HTTP gateway, small CA and transparency log, backed by PostgreSQL; admin commands `invite` and `devices`
- `deploy/helm/open-pact` Helm chart (values use placeholders)

## Guides

See the [deployment and client guides](docs/README.md).

## Run

```sh
docker compose up -d --build
scripts/smoke.sh http://localhost:8080
scripts/demo.sh http://localhost:8080      # PAUSE=1 waits for Enter between steps
open http://localhost:8080
docker compose down -v
```

`GATEWAY_PORT=8091 docker compose up -d` publishes the gateway on another host port. The scripts take only the gateway URL; they run the admin commands with `docker compose exec`, or with the command in `OPEN_PACT_ADMIN`, for example `kubectl exec -i deploy/pact-gateway -- open-pact-gateway`.

Run the client by hand:

```sh
docker compose exec -T gateway open-pact-gateway invite --note "first laptop"   # prints opi1:...
cargo run -p open-pact-client -- join 'opi1:...'
docker compose exec -T gateway open-pact-gateway devices approve <device code from join>
cargo run -p open-pact-client -- check
cargo run -p open-pact-client -- log head
```

The client refuses a plain `http://` gateway unless it is `localhost` or a loopback address. `--insecure-dev` allows it for development.

The client keeps its files in `~/.config/open-pact/`, or in the directory given with `--home`:

| File | Content |
| --- | --- |
| `owner-dev.pem` | owner key; signs the manifest hash |
| `device-tpm.key` | Windows TPM device key name; private key stays in the machine key store with access for the joining user and SYSTEM |
| `device-se.key` | device key on a Mac: a Secure Enclave key wrapped for this Mac only; signs the enrolment statement and claims, its public key's hash is the pseudonym |
| `device-dev.pem` | device key as a software file, instead of `device-se.key` |
| `vpn-key.pem` | VPN certificate key; only its certificate request leaves the device |
| `manifest.toml`, `enrolment.json` | the signed manifest, gateway URL and the salt that opens the enrolment commitment |
| `vpn-cert.pem`, `ca.pem` | the last VPN client certificate and the gateway CA; Unix links into `vpn/current/`, Windows flat copies |
| `vpn/current` | Unix directory link to `vpn/<generation>/`; Windows text file containing the selected generation name |
| `company-key.txt`, `log-key.txt` | the company key fingerprint and the log key, pinned from the invitation at `join` |
| `log-checkpoint.txt` | the last verified, gateway-signed log checkpoint |
| `claims.jsonl` | every claim sent and every response, byte for byte |
| `schedule.log` | notes from the scheduled job that need you: a changed manifest, a denial, a log alarm, an error. The OS also appends the job's output here. The job moves the file to `schedule.log.1` at the start of a run when it has reached 256 KiB, and keeps one old copy |
| `claim.lock` | lock that keeps `check`, `accept`, and the gateway part of the scheduled job from running at the same time |
| `legacy-notice.json` | which surfaces already showed the notice about an ignored `open-pact.toml` |
| `repo-scan.json` | the local scan time, counts, matching repository paths, and up to five scan causes |

Managed-repository claims send only the counts. Matching repository paths stay in `repo-scan.json` and appear only in local setup proposals and `check` output. See [client controls](docs/controls.md) for scan depth, skipped folders, and limits.

On macOS, grant Full Disk Access to the client binary in System Settings before you use repository counts. If `check` reports unknown repository values, add the printed client binary under Privacy & Security, then Full Disk Access. A partial scan prints up to five unreadable paths and error kinds. These paths stay local.

On Unix, `vpn/current/` is a directory link. The two top-level links can straddle a replacement between two reads.

On Windows, `vpn/current` is a text pointer, not a directory. A pair reader reads its generation name, reads both files from `vpn/<generation>/`, then reads `vpn/current` again. If the name changed or a file is missing, the reader discards both files and retries. The client keeps the current and previous generations. A home-wide OS file lock serializes Windows installation and recovery.

Windows replaces the flat copies sequentially, so they can briefly differ. The selected pair stays complete because readers use `vpn/current` and `vpn/<generation>/`. If a program holds a flat copy open, replacement can fail. The client keeps the new generation selected, marks the flat copies stale, and reports the locked file. Close the program that holds it and run `check` again. Every later start retries the flat-copy refresh. Startup recovery tries the VPN lock without waiting. If another process holds it, recovery warns and continues. `schedule` and `log` never wait for the VPN lock. `install` and `check` take the lock. New Windows files and directories inherit the home ACL. The client does not preserve an explicit ACL from a replaced file.

No scheduled job runs until the signed manifest defines `[schedule]` and you run `open-pact-client schedule on` or answer yes in the join wizard. Before you delete the binary or client home, run `open-pact-client schedule off`. To remove the device key, run `open-pact-client --home <home> delete-device-key` before you delete the home.

## Install the client

Install the client with your platform's package manager:

```sh
brew install gaboe/tap/open-pact
```

On Windows, add the Scoop bucket and install the client:

```powershell
scoop bucket add gaboe https://github.com/gaboe/scoop-bucket
scoop install gaboe/open-pact
```

For Debian or Ubuntu, download the `.deb` from the [client releases](https://github.com/gaboe/open-pact/releases) and install it:

```sh
sudo apt install ./open-pact-client_0.8.1_amd64.deb
```

For Fedora, download the `.rpm` from the [client releases](https://github.com/gaboe/open-pact/releases) and install it:

```sh
sudo dnf install ./open-pact-client-0.8.1-1.x86_64.rpm
```

Homebrew and Scoop check release SHA-256 hashes. The Linux commands install local files. Verify those packages with the release verification steps below before installation. These tools do not update the client automatically. Run `brew upgrade` or `scoop update open-pact` to update an installed client. For APT or DNF, download and install each new release when you choose to update.

## Install the desktop apps

The release also ships two desktop apps: `open-pact` for the employee whose device sends claims, and `open-pact-admin` for the person who writes the manifest and approves devices. Both apps come in one zip per platform. The client app runs the client itself and can install the command-line client for you.

On macOS, run the installer of a release tag. It installs the latest release into `~/Applications`:

```sh
curl -fsSL https://raw.githubusercontent.com/gaboe/open-pact/v0.8.1/desktop/scripts/install-desktop.sh | sh
```

On Windows, use Scoop, or the PowerShell installer when you do not use Scoop. The installer puts the apps in `%LOCALAPPDATA%\open-pact-desktop`:

```powershell
scoop bucket add gaboe https://github.com/gaboe/scoop-bucket
scoop install gaboe/open-pact-desktop
```

```powershell
irm https://raw.githubusercontent.com/gaboe/open-pact/v0.8.1/desktop/scripts/install-desktop.ps1 | iex
```

"Latest" skips prereleases. To install a prerelease or one fixed version, set `OPEN_PACT_DESKTOP_VERSION` first, for example `OPEN_PACT_DESKTOP_VERSION=0.8.1` on macOS or `$env:OPEN_PACT_DESKTOP_VERSION = '0.8.1'` on Windows. The Scoop manifest exists only for stable releases. Run the same command again to update.

Both installers check the zip against its line in `SHA256SUMS` before they replace anything. The macOS installer also checks each app's signature. The apps are not notarized by Apple and not Authenticode-signed, so a browser download can be blocked: install with the commands above instead. On Windows, SmartScreen may warn the first time. To also check the Cosign signature of `SHA256SUMS`, run `scripts/verify-client-release.sh` first; it checks the desktop zips too.

## Verify a release

Client releases include binaries for macOS, Linux, and Windows, plus `.deb` and `.rpm` packages. They also include `NOTICE`, `SHA256SUMS`, and Sigstore bundles for each binary, package, `NOTICE`, and `SHA256SUMS`. Verify a client release with `scripts/verify-client-release.sh v0.8.1`. The script downloads these files from the GitHub release, checks their hashes, and verifies their signatures against the tagged release workflow. It needs GitHub CLI, Cosign, and `sha256sum` or `shasum`. Set `GH_REPO` to check a release from a fork. See the [client release verification procedure](docs/client.md#verify-a-release) to save and install a verified binary or Linux package.

The gateway image is reproducible: a pinned toolchain and builder, a static musl binary, `FROM scratch`, and timestamps fixed to the commit time. CI builds each release twice on separate runners and fails when the digests differ. The witness image (`ghcr.io/<owner>/open-pact-witness`, the Dockerfile `witness` target) is built and checked the same way. To check a release yourself, run `scripts/verify-release.sh v0.0.1 ghcr.io/<owner>/open-pact-gateway@sha256:<digest>`, or add `--target witness` and the witness image reference. It rebuilds the tag from the public source, prints the digest, and exits nonzero on a mismatch. It needs Docker with buildx and takes several minutes. The image carries no system CA bundle. Optional SIEM TLS uses its explicitly mounted CA file. Do not use `sslmode=verify-full` for PostgreSQL without providing its CA.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE). Earlier releases were published under the Apache License, Version 2.0.

## Gateway API

| Request | Response |
| --- | --- |
| `GET /v1/manifest` | `{toml, company}`: the enforced manifest and the company's signature over its hash |
| `POST /v1/enroll {signed_manifest, device_key, invitation_code, owner_signature, device_signature}` | `{status: "enrolled", device, state, salt, log_index, manifest_log_index, log_checkpoint}`. See [Enrolment](#enrolment). `state` is `pending` until IT approves. |
| `POST /v1/nonce` | `{nonce}`, single use, valid 5 minutes; 429 after `NONCE_MAX_PER_WINDOW` (default 600) nonces in `NONCE_WINDOW_SECS` (default 60) from one address, IPv6 per /64; 503 while `NONCE_MAX_OUTSTANDING` (default 10000) unexpired nonces exist. Expired nonces are deleted every minute |
| `POST /v1/claim {jws, csr_pem?, manifest_toml?}` | `{status: "accepted", warnings, certificate_pem, ca_pem, log_checkpoint}`, or 403 `{status: "denied", reasons}`. `manifest_toml` is the manifest the device signed, sent while the gateway enforces another; the gateway accepts it only when its hash is the one the device signed |
| `POST /v1/device/status {pseudonym, nonce, device_key, signature}` | `{state}` of this device's enrolment in use, signed with the device key; 403 for any other device |
| `POST /v1/device/accept {pseudonym, device_key, nonce, previous, manifest, owner, owner_signature, device_signature}` | `{status: "accepted", state, manifest}`. Moves the device to the enforced manifest and keeps its state. The owner and device sign the statement. A repeat answers the same |
| `POST /v1/log/mine {pseudonym, nonce, signature}` | Approved device only; `{checkpoint, manifest, device}`, each entry with an inclusion proof |
| `GET /v1/log/key` | the log verifier key, `<origin>+<key id>+<base64 key>` |
| `GET /v1/log/checkpoint` | the signed checkpoint note, with stored witness cosignatures |
| `GET /v1/log/proof/consistency?from=&to=` | `{from, to, proof}` |
| `GET /v1/log` | 410: the v0.1.0 hash-chain endpoint is gone |
| `GET /` | public page: enforced manifest, company key, log checkpoint, witness key count, VPN CA; no device or claim data |

A claim is accepted only if the device is enrolled for the enforced manifest and approved, the `client` field is exactly `open-pact-client <major>.<minor>.<patch>`, optionally followed by `-alpha.<n>`, `-beta.<n>` or `-rc.<n>`, the nonce is unused, the claim time is within `claim_max_age` and not more than 5 minutes ahead, and the results meet the manifest. The client posts `{"jws": ..., "csr_pem": ...}`. The certificate request travels beside the JWS, and the signed claim carries only `csr_sha256`, the SHA-256 of the request's DER. The request must carry a P-256 public key and nothing else: canonical PEM with no text around it, an empty subject, and no attributes or extensions. If the request matches `csr_sha256`, the gateway issues a client certificate for its public key: CN = the pseudonym's 64 hex digits, extended key usage `clientAuth`, key usage `digitalSignature` and an authority key identifier, valid 24 hours or `claim_max_age` if shorter. The gateway stores the signed claim and the certificate's SHA-256, never the request. Each version component in `client` is a `u32` without leading zeros, so the field stays short.

**Grace.** The gateway stores, per device, manifest and control, the time it first saw a required control fail or report `unknown`. A passing value clears it; a missing result denies at once and keeps it. While the failure is younger than the control's `grace` (or `unknown_grace` for `unknown`), the claim is accepted with a warning such as `firewall = off, on required, access ends in 23h`. After that it is denied with `firewall = off, on required, grace 1d ended`. `grace = "0d"` denies the first failed claim. Changing between a failed value and `unknown` keeps the first time. Only a claim that passes the client, manifest, time, trust level and disclosure checks from an enrolled device changes the stored times.

## SIEM export

The gateway can send one JSON event for each committed claim evaluation from an enrolled device. This includes allow and deny verdicts for pending, approved, and revoked devices. It exports nothing for invalid signatures, invalid or used nonces, unenrolled devices, disclosure violations, or failed database commits. There is no collector-report endpoint. The counterparty needs no collector on the device.

Export is off by default. Configure one sink:

| Variable | Meaning |
| --- | --- |
| `GATEWAY_SIEM_SYSLOG_URL` | `tls://siem.example.com:6514`, with an explicit port. No credentials, path, query, or fragment. Plain TCP and UDP are refused. |
| `GATEWAY_SIEM_CA` | Path to PEM CA certificates for that receiver. Only these CAs are trusted. The receiver certificate must match the URL hostname or IP address. |
| `GATEWAY_SIEM_FILE` | Alternative sink. Append one JSON object per line to this path. Its parent directory must exist and be writable by the gateway. |
| `GATEWAY_SIEM_FILE_MODE` | Optional file mode for new event files. Use `0600` for owner access or `0640` to opt in to group read. The default is `0600`. |
| `GATEWAY_SIEM_RETENTION_DAYS` | Optional whole, nonnegative days. Startup warns when this exceeds the manifest's calendar `claim_retention`. |

An invalid sink configuration disables export and logs a warning. It does not prevent the gateway from serving claims. Configuring both sinks is invalid. The gateway is the only writer to a file sink. If a write fails after part of a line, the next attempt adds a newline before the retried event. The damaged prefix stays an invalid line.

New files use mode `0600`, including files created after rotation. Set `GATEWAY_SIEM_FILE_MODE=0640` only when a Wazuh reader needs group access. Add the gateway process to a group that can read the file. The mode accepts only `0600` or `0640`.

In Helm, set `siem.enabled=true`, `siem.syslogUrl`, `siem.caSecret.name`, and `siem.retentionDays`. The existing Secret's `siem.caSecret.key` defaults to `ca.pem`. The chart mounts it read-only. Restart the gateway after you change the CA Secret. The chart exposes `siem.fileMode`, but its built-in sink uses TLS, so this mode applies only when you configure a file sink.

Claim handling queues events without network or file writes. The delivery thread retries failures after 1, 2, 4, 8, 16, and 32 seconds, then every 60 seconds. Connect, socket read, and socket write timeouts are 5 seconds. DNS resolution runs only in the delivery thread.

The queue holds at most 1024 events, including the event being sent. Overflow drops the oldest event and increments `siem_dropped_total`. A separate reporter logs the drop count delta once per minute when it changes. It reports drops even if delivery is blocked. No metrics endpoint exists.

An event already being sent can still arrive after the queue drops it. A retry cannot remove a newer event. The queue is in memory, so a restart or shutdown loses queued events. TLS write success does not prove manager ingestion. Retries can produce duplicates. This export does not guarantee audit delivery.

The SIEM keeps its own copy. Gateway retention does not delete that copy. The manifest's `claim_retention` must not be shorter than the retention of SIEM events, receiver files, indexes, archives, and backups. Declare the SIEM recipients in `claim_recipients` before the owner signs. `GATEWAY_SIEM_RETENTION_DAYS` checks a configuration statement. It cannot enforce the SIEM's retention.

### Event schema version 1

Each JSON event has exactly one top-level key, `open_pact`. Its fields are flat. Reasons and warnings are arrays of gateway-generated strings. All control results use `result_<control id>` so a control cannot replace event metadata. The value keeps its original JSON type, string or integer. Only declared control results that the claim actually supplied are included. Missing results remain absent. No raw logs, public keys, nonce, JWS, certificate request, certificate, source address, or other device data are exported.

| Field under `open_pact` | Type and meaning |
| --- | --- |
| `schema_version` | Integer, currently `1`. |
| `time` | RFC 3339 UTC time from the signed claim. |
| `device_pseudonym` | String, the enrolled device's pseudonym. |
| `manifest_hash` | String, the hash in the signed claim. |
| `client_version` | String, for example `open-pact-client 0.5.0`. |
| `os` | `macos`, `windows`, or `linux`. |
| `verified_trust_level` | `L0` until the gateway supports attestation. |
| `asserted_trust_level` | `L0`, `L1`, or `L2`, as asserted by the client. |
| `verdict` | `allow` or `deny`, including enrolment state and certificate-request checks. |
| `reasons` | Array, empty for allow. |
| `warnings` | Array, including failures still within grace on an allow verdict. |
| `access_until` | RFC 3339 UTC time, the end of the VPN certificate that the claim got, or `null` when it got none. |
| `result_<control id>` | The result exactly as disclosed, with no derived values. For example `result_os_patch_age_days: 31`. |

TLS sends RFC 5424 messages with facility `local0`, severity `informational`, app name `open-pact`, and message ID `status`. The timestamp and hostname in the syslog header are NILVALUE. The JSON body contains the signed claim time. RFC 5425 octet counting prefixes the UTF-8 byte length of the complete syslog message and one space. File output contains only JSON and a newline, without a syslog header or length prefix.

### Wazuh receiver

Sample files are in [deploy/wazuh](deploy/wazuh). Terminate TLS with the sample [rsyslog configuration](deploy/wazuh/rsyslog.conf) beside the Wazuh manager. Install the rsyslog GnuTLS module and a receiver certificate. Restrict its TLS port to the gateway at the firewall. This sample authenticates the receiver to the gateway. It does not authenticate the gateway with a client certificate. The receiver writes only JSON message bodies to `/var/log/open-pact/events.jsonl`. Give that file to a Wazuh agent with [agent-localfile.xml](deploy/wazuh/agent-localfile.xml). A gateway on the receiver host can instead write that file directly with `GATEWAY_SIEM_FILE`. Set file permissions, rotation, and retention for the gateway writer and Wazuh reader.

Install [rules.xml](deploy/wazuh/rules.xml) in the manager's local rules directory. Reserve IDs 100500 through 100505 or change them to avoid local conflicts. Wazuh's [JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html) reads these events and exposes dynamic fields. An optional [decoder.xml](deploy/wazuh/decoder.xml) shows the same JSON plugin for a receiver with a custom decoder chain. Rules match fields, so either JSON decoder can supply them. See the official [decoder syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html).

The rules alert on deny, numeric `os_patch_age_days > 30`, numeric `antimalware_signature_age_days > 3`, numeric `antimalware_active_threats > 0`, and a present `log_cleared` other than null or `n/a`. These are control IDs, not check names. The manifest must declare these exact IDs and numeric outputs for the numeric rules. The export does not turn bucketed results such as `gt_30d` into numbers. Wazuh can select one matching child rule for an event with several failures; inspect the event's complete fields and reasons.

A missing event cannot trigger these event-driven rules. On the SIEM side, maintain an expected-device list and a last-ingestion time per `open_pact.device_pseudonym`. Run a scheduled check every few minutes and emit a separate alert when an expected device has no event for more than two hours. Use receiver ingestion time, not the signed claim time. Include devices that never sent a first report, and remove devices that no longer need reports. A two-hour silence policy also requires an agreed claim schedule. The optional collector schedule sends device status to a collector endpoint separate from this gateway.

The XML is checked for well-formedness. The samples are unverified against a real Wazuh manager. Before use, run `/var/ossec/bin/wazuh-logtest` with allow, deny, threshold-boundary, `none`, `n/a`, and absent-field fixtures on the target manager. Validate the rsyslog configuration there with `rsyslogd -N1`.

## Enrolment

IT creates a one-time invitation on the gateway. In Kubernetes, run it with `kubectl exec`:

```sh
open-pact-gateway invite --ttl 72h --note "laptop for the new contractor"
```

It prints the `opi1:` string on stdout and a readable form on stderr. The string is base64url JSON with the gateway URL (`--url`, default `PUBLIC_URL`), the company key fingerprint, the log key, and a code of 256 random bits. The gateway stores only the SHA-256 of the code, its expiry (at most 30 days) and the note. The note never reaches the log.

The owner runs `open-pact-client join 'opi1:...'`. Before it shows the manifest or sends anything, the client checks that the gateway serves the company key and the log key that the invitation names, and verifies the signed checkpoint. Then it pins both keys. The owner key and the device key both sign one statement over the manifest hash, the invitation hash and both public keys. The gateway checks both signatures, its own company key and the enforced manifest. Then it consumes the invitation and stores the device as `pending`, in one transaction. Running `join` again with the same invitation from the same device changes nothing. A device enrolled before invitations existed stays approved, but the client has no pinned keys; the owner joins again with a new invitation, which binds to the device and keeps its state.

After `join` prints the device code, it checks for IT approval every 10 seconds. It reports approval only after it verifies this device's `device_approved` entry in the signed log. Press Ctrl+C to stop waiting. The enrolment stays on disk, so run `join` again or run `check` later. Pass `--no-wait` to print the code and exit without polling.

IT approves the device by the code that `join` prints, which is the first 12 hex digits of the pseudonym. The owner reads it out:

```sh
open-pact-gateway devices list                 # state, pseudonym, manifest, enrolment time, invitation note
open-pact-gateway devices approve 0a1b2c3d4e5f # at least 8 hex digits; must match exactly one pending device
open-pact-gateway devices revoke pseudonym:0a1b2c3d4e5f...   # the full pseudonym; final
```

`approve` and `revoke` append `device_approved` or `device_revoked` with the same commitment as the enrolment, never the pseudonym. Repeating either changes nothing and appends nothing. A revoked device key stays revoked for every manifest; the owner joins again with a new device key. `/v1/claim` denies a pending device with "device awaiting IT approval" and a revoked one with "device revoked". `AUTO_APPROVE=true` approves at enrolment and logs it; the default is `false`.

| Attack | Defence |
| --- | --- |
| Enrolling a device with only the public manifest | a valid invitation is required, and IT approves each device |
| Guessing or enumerating codes | 256-bit codes; unknown, expired, used and someone else's codes get the same 403 "invalid or used invitation"; after `ENROL_MAX_FAILURES` (default 10) refused enrolments of any kind (malformed body, bad signature, wrong manifest, invalid invitation) in `ENROL_FAILURE_WINDOW_SECS` (default 600) from one address, IPv6 per /64, the gateway answers 429 |
| Using one invitation twice, also concurrently | one `UPDATE ... WHERE used_at IS NULL AND expires_at > now()` inside the enrolment transaction; smoke races three devices for one code |
| Reading codes from a database dump | only SHA-256 hashes are stored |
| A fake gateway at first contact | the client compares the company key fingerprint and the log key with the invitation before it shows or sends anything |
| A gateway that changes keys later | `check` and `log prove` compare both keys with the pins; a change is an alarm with exit status 2 |
| Enrolling or squatting someone else's device key | the device key signs the enrolment statement (proof of possession) |
| Binding a device to an owner who did not consent | the owner key signs the device key in the same statement |
| Downgrade to plain HTTP, or a redirect to it | the client refuses `http://` except loopback and follows no redirects; the Helm chart turns ingress TLS on |
| Free text in a claim | `client` must be a bare version; other values are denied and not stored |
| A stolen or lost device | `devices revoke`; its next claim is denied and it gets no new certificate |


## Transparency log

The log is a Merkle tree with RFC 9162 (Certificate Transparency 2.0) hashing. A leaf is the RFC 8785 canonical JSON of `{kind, data}`. The leaf hash is `sha256(0x00 || leaf)` and an inner node is `sha256(0x01 || left || right)`. The index is not part of the leaf, because the position in the tree fixes it.

- `manifest_published` `{manifest}` is appended once per new manifest hash at gateway start.
- `device_enrolled` `{commitment}` holds `sha256(salt || pseudonym)`, not the pseudonym. The owner keeps the 256-bit salt and can prove the entry is theirs.
- `device_approved` and `device_revoked` `{commitment}` carry the same commitment when IT approves or revokes the device.
- `retention_purge` `{claims, period_keys}` counts the claims and month keys that the retention job deleted. It holds no device data. A client older than this entry kind cannot read a log that contains one.

Log entries are private. The public `/v1/log/entries` and `/v1/log/proof/inclusion` routes return 404. An approved device uses `POST /v1/log/mine` to get its signed manifest and its own device entries with inclusion proofs. The log key, signed checkpoint and consistency proofs remain public. Witnesses receive checkpoints and consistency proofs by push; they do not download entries.

Public consistency proofs expose leaf hashes for log changes. An outsider who polls checkpoints can count and time changes. The outsider can recognize manifest and retention-purge entries, then identify the remaining changes as device events. Salted commitments stop the outsider from linking a device event to a device. Entry contents remain private. Witnesses verify checkpoint consistency, and each approved device verifies its own entries.

**Checkpoints.** The gateway signs a checkpoint, the C2SP [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) body `<origin>\n<size>\n<base64 root>\n`, in C2SP [signed-note](https://c2sp.org/signed-note) format. Set `LOG_ORIGIN` to the gateway's stable log identity before startup. The key name is this origin. The log key is ECDSA P-256, signed-note type `0x02` as transparency-dev/formats implements it: a DER signature over SHA-256, and a key ID from the DER public key. Most C2SP tools use Ed25519. P-256 keeps the log key in the same hardware as the other keys.

**Witnesses.** A witness is a separate service, `open-pact-witness`, with its own Ed25519 key and its own state file. It implements the C2SP [tlog-witness](https://c2sp.org/tlog-witness) `add-checkpoint` call. It keeps the latest checkpoint it cosigned for each log. It cosigns a new checkpoint only with a valid consistency proof from that size, and it refuses forks and rollbacks (422 and 400) and a stale old size (409 with the size it holds). Run one process per witness key, with one state file. At start the witness takes an exclusive lock on the directory `<state>.lockdir` and holds it until it exits, so a second process on the same state refuses to start. A state path that ends in `.lockdir`, or a file where the lock directory belongs, also refuses to start. Before and after each save the witness checks that the lock path still names the directory it locked. If not, it cosigns nothing more. Older versions locked the file `<state>.lock`, and the two locks do not exclude each other: stop the old witness before you start an upgraded one. A leftover `<state>.lock` file is stale and harmless. The lock does not reach other hosts or network file systems: never run one witness key on two hosts. The cosignature is Ed25519 `cosignature/v1` with a timestamp (C2SP [tlog-cosignature](https://c2sp.org/tlog-cosignature)).

The manifest names the witnesses, so the owner signs the witness set and no one can change it without them:

```toml
[log]
witnesses = [{ name = "witness.example.org/w1", key = "witness.example.org/w1+<id>+<key>" }]
witness_quorum = 1          # cosignatures a client requires
checkpoint_max_age = "1h"   # oldest cosignature a client accepts
```

The optional `[schedule]` table tells devices when to check themselves and when to send claims automatically. It is part of the signed manifest and of its hash:

```toml
[schedule.vpn]                    # while the company VPN answers
probe = "10.0.0.1:443"            # host:port that answers only on the company VPN
probe_name = "vpn.example.org"    # optional TLS name that the probe must present
interval = "1h"                   # the longest time between claims on the VPN: 5m to 24h
check = "5m"                      # optional: how often the device checks itself on the VPN, 1m to 24h; default 5m

[schedule.always]                 # optional: on any network
interval = "24h"
```

The manifest needs at least one of the two tables. The older flat table (`mode = "vpn"` or `"always"`, `vpn_probe`, `vpn_probe_name`, `interval`) still parses and keeps its old meaning. Without `[schedule]`, devices send claims only by hand with `check`. The owner turns automatic sending on or off on the device. The client shows the table in plain words, such as `Automatic claims: on the company VPN (vpn.example.org at 10.0.0.1:443) checks every 5 minutes, sends at once on connect or when a result gets worse, and at least every hour; on any network every 24 hours, and at once when a result gets worse.` On the VPN a device checks itself every `check`, sends at once when it connects (at most once every five minutes) and when a required result gets worse, and at least every `interval`. Off the VPN it only probes, unless `[schedule.always]` asks it to check every five minutes and send every `interval` of that table. `check` is local work, not more sending, but a shorter `check` is new work on the device, so the owner must agree to it again with `schedule on` after `accept`. Every change of the manifest, the schedule included, needs the owner's `accept`; until then the job keeps the policy the owner signed. Anyone who can reach `GET /v1/manifest` can read the probe address, so choose an address that is no secret.

A device whose check finds a required control non-compliant, with its grace ended on the device, deletes its own VPN certificate and sends a claim at once. A claim that the gateway denies installs no new certificate.

Clients up to 0.4.9 reject a manifest that has a `[schedule]` table, so `join` and `accept` fail on them. Upgrade every client before the company adds `[schedule]`.

`witness_quorum` must be more than half of the listed witnesses: 1 of 1, 2 of 2 or 3, 3 of 4. Any two sets that large share a witness, and that witness cosigns only one history, so two clients cannot accept checkpoints from different histories. A manifest with 1 of 2 or 2 of 4 does not parse. Every manifest needs a `[log]` section. To run without witnesses, set `allow_split_views = true` with `witnesses = []` and `witness_quorum = 0`; the client then prints a loud warning on every `join` and `check`.

The gateway sends every new checkpoint to the witnesses in `WITNESS_URLS` before it serves it, keeps the cosignatures that a manifest witness key verifies, and serves them with the checkpoint. It sends the current checkpoint again every `WITNESS_REFRESH_SECS` (default a quarter of `checkpoint_max_age`, at most 600), so the cosignatures stay fresh while the log does not grow.

A witness detects a forking gateway only if someone other than the gateway operator runs it, for example the contractor or an auditor. To run one:

```sh
WITNESS_NAME=witness.example.org/w1 WITNESS_KEY_FILE=witness.key open-pact-witness keygen   # prints the verifier key for the manifest
WITNESS_NAME=witness.example.org/w1 WITNESS_KEY_FILE=witness.key WITNESS_STATE=state.json \
  WITNESS_LOG_KEYS="$(curl -s https://pact.example.com/v1/log/key)" open-pact-witness
```

Confirm the log key out of band, as with the invitation. `WITNESS_LOG_KEY_URL` pins the first key a URL serves; it exists for `compose.yaml` only. Losing the state file lets the gateway roll the log back, so back it up. Run one witness process per state file and give that file one name: the witness refuses a symlink or a hard-linked `WITNESS_STATE` and stops cosigning if the file gains another name. Never copy one witness key to a second state file or host. The `compose.yaml` witness uses a key from a public seed (`deploy/compose/demo-witness.key`), and `examples/manifest.toml` lists it: anyone can forge its cosignatures.

**Client.** The client pins the log key from the invitation at `join`. On first contact, it verifies the checkpoint's gateway signature and the witness cosignatures required by the signed manifest. A manifest that explicitly permits split views with no witnesses accepts a gateway-signed checkpoint alone and prints a warning. The client fetches its manifest and device entries from `POST /v1/log/mine` and verifies each inclusion proof. `enrolment.json` keeps their indexes; the gateway returns them at enrolment. Later `join` and `check` commands verify a consistency proof from the checkpoint stored on the device. If the proof fails or an entry is missing, the client prints an alarm and exits with status 2. `check` verifies the `log_checkpoint` of an accepted claim response against the checkpoint it verified before the claim. If that fails, it raises the alarm, exits with status 2 and installs neither the CA nor the certificate. `log prove [index]` verifies the inclusion proof of one entry. Without an index, it proves the entry of this device's enrolment. Each claim carries `log_checkpoint`, the size and root that the client verified last. The gateway denies a claim whose checkpoint is not a state of its log.

The gateway reads each log row from the database once and signs the checkpoint once per tree size. The checkpoint, the cosignatures and the proofs also verify with the Go packages `golang.org/x/mod/sumdb/note`, `github.com/transparency-dev/formats/note` and `github.com/transparency-dev/merkle/proof`. `log_entries` rejects `UPDATE`, `DELETE` and `TRUNCATE` with a trigger.

**Mandatory disclosures.** `disclosed_metadata` must list every field a claim always carries: `manifest_hash`, `device_pseudonym`, `device_key`, `nonce`, `time`, `client_version`, `os`, `trust_level` and `vpn_certificate_request`. `virtualized` and `log_checkpoint` are optional: the client sends them only if the manifest lists them, and the gateway denies and does not store a claim that carries an unlisted one. Other names do not parse. The example manifest replaces `client_hash` with `client_version` and adds `device_key`, `nonce` and `vpn_certificate_request`, so its hash changes and owners sign it again with `join`.

**Upgrade from v0.1.0.** Migration 0004 drops the hash-chain columns. The entries keep their order and become the leaves, and the log key stays. A client that holds a v0.1.0 `log-head.json` tells the owner to run `join` again, exits with status 1 and raises no alarm. `join` removes the old file and pins the checkpoint. `GET /v1/log` answers 410. The example manifest now lists `log_checkpoint` in `disclosed_metadata`, so its hash changes and owners sign it again at that `join`.

## Keys

On first start the gateway generates its company manifest-signing key, its log-signing key and a P-256 CA ("open-pact demo CA"), and stores them in the `gateway_secrets` table. This is for the demo only. In production these keys stay in an HSM or a cloud key vault and never reach the database.

Each row of `gateway_secrets` is encrypted with AES-256-GCM under the key-encryption key in `GATEWAY_KEK`, with the row name as associated data. `GATEWAY_KEK` is 32 random bytes in base64. The gateway refuses to start without it. Only `DEV_INSECURE_KEK=1`, which `compose.yaml` sets, replaces it with a public development key. A gateway upgraded from a version without the KEK encrypts the plaintext rows in place on its first start and logs each one. A wrong key stops the gateway; it never generates new keys over rows it cannot read. Keep a copy of the key outside the database and its backups: without it, the keys and claims cannot be read. Rotating the KEK is not supported yet.

**Claims at rest.** Each stored claim gets a deletion deadline: its receipt time plus the `claim_retention` of the manifest it was accepted under (calendar months for `mo`). A later manifest cannot extend that deadline. A shorter later `claim_retention` still deletes the claim earlier. The gateway seals each claim, with its device pseudonym and JWS, under the key of its deadline's calendar month (UTC), so claims kept for different spans never share a key. Each month key is sealed under the KEK in `claim_keys`. Only `received_at`, `delete_after` and the allow or deny flag stay readable. Every hour the gateway deletes the claims past their deadline. It then deletes the key of every ended month that no remaining claim uses. A logical dump made after that cannot decrypt those claims. A physical backup can still hold the deleted key until PostgreSQL vacuums it, and a WAL archive replays its insert until that archive expires. Backups made before the deletion hold the sealed month key too, so anyone with such a backup and the KEK can still read the claims. A deleted claim is therefore gone from backups only when every database backup made before its key was deleted has expired. Keep database backups only as long as you tell device owners, and the gateway logs this limit on every start. Each purge that deletes something appends a `retention_purge` log entry with the counts. Claims stored by earlier versions have no recorded deadline, and the gateway keeps only the current manifest's body. On the first start after the upgrade, a claim made under the current manifest gets the deadline of the current `claim_retention`. A claim made under any other manifest had a `claim_retention` the gateway cannot recover. The shortest value a manifest allows is zero, so that claim is due at once and the next purge deletes it. The upgrade never keeps a claim longer than the manifest it was accepted under allowed. On that start the gateway also seals claims that earlier versions stored in plaintext. Their old plaintext can remain in PostgreSQL dead tuples, the WAL and earlier backups until those are vacuumed or expire.

In Kubernetes, create the Secret once and name it in the chart values:

```sh
kubectl create secret generic pact-gateway-kek --from-literal=kek="$(openssl rand -base64 32)"
helm upgrade --install pact deploy/helm/open-pact \
  --set gateway.kekSecret.name=pact-gateway-kek \
  --set postgres.existingSecret=pact-postgres   # or --set postgres.password=...
```

The chart fails to render without `gateway.kekSecret.name`, and, for the bundled PostgreSQL, without `postgres.password` or `postgres.existingSecret`.

The manifest lives in the company's deployment config, not in the image. The image carries only the example manifest. To enforce your own signed manifest, pass its TOML text with `--set-file manifest=company-manifest.toml`. The chart renders it into a ConfigMap, mounts it at `/etc/open-pact/custom/manifest.toml`, sets `MANIFEST_PATH`, and restarts the gateway when the text changes. Run the witness as a separate release (`witness.enabled=true`, with its own key Secret and `witness.logKeys`) and list its URL in the gateway's `log.witnessUrls`. Both images are published from this repository; you rebuild neither. The chart sets non-root users, a read-only root filesystem and default `resources` for both; override `gateway.resources`, `gateway.securityContext` and the `witness.*` equivalents as needed.

## Tests

`scripts/smoke.sh` runs the full flow against a running gateway: an invitation with a wrong company key fingerprint (refused, nothing pinned), a remote `http://` gateway (refused), `join --yes --software-key` with the right invitation (it signs crafted claims with `device-dev.pem`), `check` denied while pending, a repeated `join`, reuse of the invitation by another device, three devices racing for one invitation, `devices approve` and `devices list`, `check`, `openssl verify` of the certificate, a replay of the client's own claim, a claim from an unenrolled device, chosen-result claims (failed check, a grace period that starts, ends after a day with the stored start moved back, and clears on a pass, undisclosed result, wrong manifest, tampered signature), `log show`, `log prove`, a claim with a foreign log checkpoint, the witness cosignature, a fork the witness refuses, the log alarm for a checkpoint without a cosignature and for one cosigned two hours ago, and the log alarm for a different root (split view), for a rollback, and the upgrade message for a v0.1.0 log head, a changed company key, and `devices revoke`. On a device that fails a 0-day-grace check, such as disk encryption off, `check` is denied and the smoke script stops there.

`scripts/check-helm.sh` checks that the chart refuses to render without `gateway.kekSecret.name` and without a database password or secret, that `manifest` renders its ConfigMap, mount and checksum, and that a database password with `@:/?#%` reaches the gateway raw as `PGPASSWORD`, never inside `DATABASE_URL`. The gateway tests that need PostgreSQL are `#[ignore]`d in a plain `cargo test`. Run them against a throwaway database:

```sh
docker run -d --rm --name pact-testdb -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:17
TEST_DATABASE_URL=postgres://postgres:test@localhost:55432/postgres cargo test --workspace -- --include-ignored
```

## Known gaps

- The invitation is a bearer secret, and its fingerprints are only as authentic as the channel that carried it. A relay that forwards the public endpoints passes the fingerprint check and can use a code it intercepts. TLS and IT approval of the device code are the defences; confirm the company key fingerprint over a second channel.
- Behind an ingress the gateway sees the ingress address, so the enrolment failure limit applies to all enrolments together and the nonce limit to all devices together. Size `NONCE_MAX_PER_WINDOW` for the whole fleet in that case. The gateway does not read `X-Forwarded-For`. The limits are in memory and per replica.
- When the gateway enforces a new manifest, an approved device stays approved. Until the owner runs `open-pact-client accept`, a required control that the signed manifest does not collect fails with its own grace, and claims keep the consent terms of the signed manifest.
- The witness has no monitoring endpoint yet, so a client cannot fetch cosignatures from it directly; it gets them through the gateway.
- Replays, bad signatures, unenrolled devices and oversharing claims are refused without being stored.
- The Secure Enclave device key proves that claims come from this Mac, but it is not bound to the client's code signature as PAPER.md section 5 describes. The client keeps the wrapped key in `device-se.key`, not in the keychain, so it needs no keychain entitlement, and any program on the same Mac that can read the file can sign with it. A Developer ID signed client with a keychain access group closes this. The Secure Enclave key protects against key theft: its private key cannot be copied off the Mac. It does not prove anything to the gateway, because the trust level in a claim is what the client asserts. Without attestation the gateway records that assertion as `asserted_trust_level`, counts every claim as `verified_trust_level` L0, and denies every claim when `min_trust_level` is L1 or L2, with the reason that the level needs attestation, which is not available.
- The VPN certificate key and the owner key are still software keys.
- The CN is the pseudonym's hex digest without the `pseudonym:` prefix, because X.509 limits a CN to 64 characters.

## Bounded integer controls

`os_patch_age_days` replaces the bucket-based patch-age control. This is a breaking manifest and claim change. Owners sign the new manifest again. Clients report whole days as a JSON integer, or `"unknown"` when they cannot establish an age within 0 to 3650 days. Windows reads the latest successfully installed OS `Package_for_RollupFix` servicing package with `Get-WindowsPackage -Online`. This requires administrator or SYSTEM access. Unrelated updates and pending packages do not count. Missing evidence and future timestamps return `"unknown"`.

```toml
[[control]]
id = "os_patch_age_days"
source = "company_policy"
rationale = "Limit the age of the last whole-system OS update."
check = "builtin:os_patch_age_days@1"
output = { integer = { min = 0, max = 3650 } }
required = { macos = { max = 30 }, windows = { max = 30 }, linux = { max = 30 } }
grace = "1d"
```

Integer outputs always allow `"unknown"`. Both bounds are inclusive signed 32-bit integers. A requirement uses `{ max = 30 }` for at most 30, or `{ min = 90 }` for at least 90. The limit must be within the output range. Numeric strings, fractions, other strings and out-of-range values are refused. Unknown values use `unknown_grace`. A smaller output range is narrowing. Lowering a maximum or raising a minimum is stricter and needs owner consent. Switching comparison direction or output kind also needs consent. Manifest hashes remain SHA-256 of the exact TOML bytes. Claims retain JCS encoding.

The screen-lock output `"none"` means no screen lock. It replaces `"off"` in this breaking change. An enumerated control may declare `"n/a"` and accept it for an OS where the control does not apply. The gateway treats `"n/a"` as a declared string value, with no special bypass. When a check returns `"n/a"`, the client sends `"unknown"` only when the manifest allows `"unknown"` and does not allow `"n/a"`.


## Additional security checks

All checks are read-only. macOS and Linux checks run as the device owner. Windows checks support a SYSTEM scheduled task or an elevated administrator. Each external command has a three-second timeout, except the single Windows PowerShell batch, which has a 60-second timeout. Command output uses the C locale. Unsupported sources return `unknown`.

| Control | macOS | Linux |
| --- | --- | --- |
| `os_auto_updates` | `AutomaticCheckEnabled`, `ConfigDataInstall` and `CriticalUpdateInstall` all enabled | Enabled and active apt or dnf timer with automatic installation configured |
| `antimalware_realtime` | XProtect present, registered and enabled | Running `clamonacc` process |
| `antimalware_active_threats` | `n/a` | `unknown` |
| `work_account` | Current account membership in `admin` | Current account membership in `sudo` or `wheel` |
| `uptime_days` | Whole days since `kern.boottime` | Whole days from `/proc/uptime` |
| `password_min_length` | Largest length rule in `pwpolicy getaccountpolicies`; `none` without a rule | `minlen` from `pwquality.conf` and its drop-in files; `none` without one |
| `preboot_auth` | FileVault on means `user_secret`, off means `none` | No encryption means `none`; an unverified LUKS unlock method means `unknown` |
| `antimalware_active` | XProtect bundle and Remediator executable present, scan service registered and enabled | Existing ClamAV service check |
| `antimalware_signature_age_days` | Whole days since the receipt for the installed XProtect definitions version | Age of the daily ClamAV CVD or CLD embedded timestamp in standard database directories |
| `antimalware_full_scan_age_days` | `n/a` | `unknown`, no reliable clamscan full-scan record |
| `web_protection` | Chrome, Edge, Brave and Firefox profiles and readable managed policies. Safari is not checked because its settings need Full Disk Access. | `unknown` |
| `log_oldest_record_days` | `n/a`, unified log retention is size-based | Age of the oldest readable system journal entry; permission warnings mean `unknown` |
| `process_audit`, `powershell_logging` | `n/a` | `n/a` |
| `remote_wipe` | Activation Lock state; remote erase requires the Mac to be online | `n/a` |
| `log_cleared` | `n/a` | `n/a` |

Windows collects the controls in one cached PowerShell batch. A missing source, command failure, timeout or unrecognized output returns `unknown`.

| Windows control | Source | Privilege |
| --- | --- | --- |
| `os_auto_updates` | Windows Update automatic updates enabled and no unexpired pause | Update settings and registry read access |
| `antimalware_realtime` | Defender `RealTimeProtectionEnabled` in Normal mode | Defender status read access |
| `antimalware_active_threats` | Count of `Get-MpThreat` results with `IsActive` | Defender threat read access |
| `work_account` | Administrators SID in token groups, including UAC deny-only groups. SYSTEM uses the active console user token | Own token, or SYSTEM for the console token |
| `uptime_days` | Whole days since `Win32_OperatingSystem.LastBootUpTime` | CIM read access |
| `password_min_length` | Minimum password length of the local account policy (`NetUserModalsGet`); 0 means `none` | Device user |
| `preboot_auth` | OS-volume BitLocker protection and numeric key-protector types; recovery passwords do not establish the startup method | SYSTEM or elevated administrator |
| `antimalware_signature_age_days` | Defender `AntivirusSignatureLastUpdated` | Defender status read access |
| `antimalware_full_scan_age_days` | Defender `FullScanEndTime`; absent date means `unknown` | Defender status read access |
| `web_protection` | Explorer SmartScreen plus Chrome, Edge, Brave, and Firefox preferences and HKLM/HKCU policies | Registry and browser-profile read access |
| `log_oldest_record_days` | Shorter age of the oldest Security and System records | SYSTEM or elevated administrator |
| `process_audit` | Native Process Creation audit-policy success flag and command-line policy | SYSTEM or elevated administrator |
| `remote_wipe` | `n/a`; Windows Find my device cannot erase without an MDM | n/a |
| `powershell_logging` | Windows PowerShell ScriptBlockLogging policy, machine before interactive users, weakest user policy wins | Registry read access |
| `log_cleared` | Latest Security event 1102 or System event 104; JSON null after both readable logs have no matching event | SYSTEM or elevated administrator |

Defender metrics require Defender in Normal mode with its antivirus and service enabled. Other antivirus providers return `unknown` for these metrics. Active threat counts describe Defender threats that are still active. Standard users get `unknown` for the controls that enforce elevation. Access failures also return `unknown`.

On Windows, `preboot_auth`, `log_oldest_record_days`, `process_audit`, and `log_cleared` need SYSTEM or an elevated administrator. The `web_protection` check also needs SYSTEM to read browser settings for other user profiles. Answer yes to the SYSTEM question in the join wizard, or run `schedule on --system` from an elevated PowerShell prompt, to run these checks as SYSTEM. The task reads Windows settings and reports their values. It does not change those settings.

`screen_lock@1` reports buckets and `screen_lock@2` whole minutes, rounded up, of the same setting; on macOS `@2` adds the screen saver idle time and the display sleep time to the password delay, while `@1` reads the password delay only (see [docs/controls.md](docs/controls.md)). Windows `screen_lock` uses a machine inactivity limit first. Otherwise it reads the effective screen-saver policy before local desktop settings. It requires a positive timer, secure mode, and an existing `.scr` file. An absent enabled flag or an empty saver program means no saver runs, so the result is `none`. As SYSTEM, it reads the HKU hives of interactive users. The weakest readable user setting decides. Missing users, unloaded hives, and unreadable evidence return `unknown`.

Windows `os_supported` uses an edition-aware lifecycle table for client, IoT Enterprise, LTSC/LTSB, and Server releases. Older systems use `ReleaseId` when `DisplayVersion` is absent. Missing lifecycle entries and unverified Windows 10 ESU status return `unknown`.

Windows browser discovery checks standard Program Files and per-user Local AppData installations. Chromium profiles use Local AppData user-data directories or a mandatory `UserDataDir` policy. Hidden profiles are included. Missing or unreadable policy directories return `unknown`. Known mandatory protection policy still decides when a profile read fails. Firefox uses Roaming AppData profiles and installation-directory `distribution/policies.json`. Machine registry policy takes precedence over user policy. Recommended Chromium policy stays below explicit user preferences. Firefox supports JSON Preferences policy and legacy per-preference DWORD policy. Firefox registry policy takes precedence over the distribution file.

As SYSTEM, the reader checks every non-special Windows user profile and its loaded HKEY_USERS policy hive. It returns `unknown` for an installed browser with an unloaded hive or unreadable settings. It does not load hives or change permissions. Custom installation locations and command-line `--user-data-dir` overrides are outside discovery. Unsupported `UserDataDir` variables return `unknown`. SmartScreen must be readable and on for Windows `web_protection=on`; an absent `SmartScreenEnabled` value is the Windows default, which is on; Windows never reports `n/a`.


`antimalware_active` now checks XProtect instead of Gatekeeper. This is a breaking mechanism change. [Apple describes XProtect as macOS antivirus technology](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web). The signature-age reader matches `CFBundleShortVersionString` with an `XProtectPlistConfigData` receipt in `InstallHistory.plist`. It uses the matching receipt date because a bundle build date or file modification date does not establish when definitions were installed.

Web protection is `on` only when every installed supported browser is on. Any known disabled browser gives `off`. Otherwise an unreadable browser gives `unknown`, and a local diagnostic names that browser. Missing preference keys use browser defaults. Safari is not checked because its settings need Full Disk Access. If no supported browser is installed, the value is `n/a`. Browser installations outside standard system and user Applications directories and profiles stored outside standard browser data directories are not discovered.

Integer outputs can declare `values = ["n/a"]`, `values = ["none"]`, or both beside `integer`. Only these two additional text values are allowed. They must be unique. An OS can require a declared text value. Numeric requirements do not accept text values. Adding a text value expands disclosure and requires consent. For example:

```toml
output = { integer = { min = 0, max = 3650 }, values = ["n/a"] }
required = { macos = "n/a", linux = { max = 7 } }
```

The fictional example sets an illustrative V3.1 baseline. `antimalware_full_scan_age_days`, `web_protection`, `work_account`, and `uptime_days` use `required = {}` to report values only. The client runs and discloses every listed control. The gateway checks disclosure bounds but applies no access requirement when the OS has no entry in `required`. A policy can require signature freshness with `required = { macos = { max = 3 } }`. Windows requires zero active threats. It requires at least 90 days of Security and System history and no retained clearing event.

The ClamAV parser uses the [documented database header](https://docs.clamav.net/manual/Signatures.html). The journal reader uses [journalctl oldest-entry selection](https://freedesktop.org/software/systemd/man/latest/journalctl.html).

## Configure the device

You edit no settings file. The company's rules are in the signed manifest. `join` prints the absolute path of a file with the whole manifest, and `accept` and `manifest show` do the same, so you can read all of it before you sign. After IT approves the device, the join wizard asks only for your own choices:

- whether to send claims automatically, only when the manifest has `[schedule]`;
- on Windows, whether the job runs as you or as SYSTEM;
- the folders that hold your repositories, only when the manifest counts repositories.

The client keeps the answers in `device.json` in the client home. It writes the file atomically and does not expect you to edit it. Change the answers later with commands:

```sh
open-pact-client schedule on
open-pact-client schedule off
open-pact-client schedule status
open-pact-client folders list
open-pact-client folders add ~/projects
open-pact-client folders remove ~/projects
```

An `open-pact.toml` from an earlier client is ignored. The first time the client reads a home that has no `device.json`, it carries over what your earlier choices were: the folders of `[managed_repos]` go into `device.json` (they were your own choice, so `folders list` shows them and the wizard still asks step 5), and on Windows an installed SYSTEM job keeps `run_as` SYSTEM. `check` and the job print once that the file is ignored and where each value went. For a SYSTEM job the notice prints the exact command to run from an elevated PowerShell prompt, `schedule on --system` with the full path of the client. The client never deletes the file. The commands `apply`, `finish` and `config example` no longer exist. `~` expands to your user home, folder paths stay on the device, and the folders feed the managed repository checks.

`check` prints each manifest control, its requirement for this OS, the device setting that feeds it, and the result.

### See what a claim sends

Run `check --dry-run` to see what `check` would send now:

```sh
open-pact-client check --dry-run
```

The command runs the same local checks and prints the claim as JSON. It adds `manifest_toml` when the gateway enforces a different manifest. It makes GET requests for the manifest, log key, checkpoint, and any needed consistency proof. It sends no nonce request or signed POST. It writes no file. The dry run never suppresses the claim. When the saved device status is pending or revoked, it prints one `Last known status` line after the claim, because `check` asks the gateway again. It cannot verify private log entries or current device status because those checks need a signed request. When the dry run prints a claim, it also prints this line: `check also asks the gateway whether this device may send; the dry run skips that signed request.` The nonce, time, and VPN certificate request appear as placeholders. The scheduled job sends the same claim. Add `--timings` to print, on the error stream, the wall time of the whole run and the CPU time (user and system) of the client process and its child processes. Unix reads them from `getrusage`. On Windows the child time counts the commands that the checks ran, such as the PowerShell batch. Run it about twenty times on each kind of device before you set a short `check` period. It needs `--dry-run`.

## Send claims automatically

The scheduled job runs the claim pipeline of `check` on its own. The company chooses the policy in `[schedule]` of the signed manifest: `[schedule.vpn]` works only while the device is on the company VPN, and `[schedule.always]` works on any network. You choose whether the job runs:

```sh
open-pact-client schedule on --dry-run
open-pact-client schedule on
open-pact-client schedule on
```

`schedule on` refuses when the manifest has no `[schedule]`. It prints the policy line. The first run prints `schedule: install`. The second prints `no changes`. A changed executable path prints `schedule: update`, and so does a job that client 0.7 installed: it wakes every five minutes, and `schedule on` rewrites it to wake every minute. `schedule status` prints the consent line, your choice, the state of the job, the last answered claim, the last check, and when the next check and claim fall due. Dry run prints the planned change and writes nothing. Keep the binary at its installed path. macOS uses a launchd LaunchAgent. Linux uses a systemd user timer and needs a running user manager. Windows uses Task Scheduler. No separate client daemon is needed.

Use the same absolute `--home` for each command. The scheduled run reads the policy from the manifest you signed every time. When the company changes the manifest and you have not yet run `accept`, the job keeps the policy you signed and writes the accept notice to `schedule.log`. To stop the job, run `open-pact-client schedule off`. The command removes the job and its state and records your no. If the entire client home is already missing, it removes the remaining job without recreating that home.

On Windows, choose SYSTEM in the wizard or run `schedule on --system` from an elevated PowerShell prompt. Without elevation, the command prints the exact command and changes nothing. Other operating systems reject `--system`. The installer copies the client into `%ProgramFiles%\open-pact\open-pact-client.exe` and refuses a directory that non-administrators can write. The SYSTEM job runs with `--system --user-home <profile>`. It reads the selected user's absolute `--home`, expands `~` in the folders of `device.json` against that profile, and refuses reparse-point files. It keeps its state under `%ProgramData%\open-pact\system\<home hash>`, with access limited to SYSTEM and Administrators. Choose a home path without `%`.

`probe` (flat form: `vpn_probe`) must be a `host:port` that connects only on the company VPN. The job sends nothing from the VPN table while it does not connect, so an address that also answers off the VPN makes the job send off the VPN. A probe can succeed just before the VPN disconnects.

A private address such as `10.0.0.1:443` can also exist on other networks, such as hotel or home routers, so a TCP connection alone can match the wrong network. With `probe_name` (flat form: `vpn_probe_name`) in the manifest, the probe connects to `probe` without a DNS lookup of the name. It needs a TLS certificate that is valid for the name and chains to a root that the client trusts for its HTTPS requests. Any HTTP status counts as an answer. The probe has five seconds in total and does not use a proxy. An empty value or an IP address for `probe_name` does not parse.

The OS wakes the job every minute (launchd `StartInterval` 60, a systemd timer of one minute, Task Scheduler every minute). A wake costs one process start and one probe. It first decides, from the saved state and the clock, whether anything is due, and when nothing is due it exits at once: no check, no repository scan, no gateway request.

On the VPN the job checks every `check` period (at least five minutes on Windows, where one check starts PowerShell) and on the first wake after the VPN connects. It sends at once on a connect, at once when a required control changes from compliant to non-compliant, and at least every `interval`. A connect claim goes at most once every five minutes: when the gateway answered a claim less than five minutes ago, a VPN that flaps does not send again. Off the VPN the job runs no check and sends nothing, except under `[schedule.always]`, which checks every five minutes and sends every its `interval`. A claim that is due always runs fresh checks first. The flat 0.7 form keeps its interval gating (it sends when the last answered attempt is older than `interval`, also at a connect), and checks every five minutes while it may send.

The probe is a TCP connection with a two-second timeout that includes name resolution. With `probe_name`, it tries the TLS probe instead. Use brackets around IPv6 addresses. A successful connection records connectivity for this check. The job probes again at the start of the send, before any gateway request (the manifest, the log, a nonce), and once more before the POST of the claim. It sends nothing more when a probe fails, so a device that left the VPN during the repository scan sends nothing, not even a log request. DNS runs in a child process that the parent kills at the deadline: two seconds for TCP, five seconds with `vpn_probe_name`. A disconnect and reconnect entirely between two probes is not observed. A send that gets no answer from the gateway (a network error) retries on the next run. If the clock moves behind the last answer time, the next connected run retries and resets that time. Without a VPN table the job does not probe and sends when `interval` has passed since the last answered attempt.

The job scans repositories at most once a day, before it takes the claim lock, and uses the stored counts in `repo-scan.json` between scans. It holds the claim lock, the lock of `check` and `accept`, only for the gateway part. When one of them runs, the job skips that run. A command you start waits up to 60 seconds for the lock and prints one line that it waits for the scheduled job. A claim that the gateway accepts or denies counts as sent. So does an answer without a verdict on the claim: the device waits for approval, IT revoked it, the manifest awaits `accept`, or the log did not verify. After any of these the job asks again only when `interval` has passed, and writes each piece of news to `schedule.log` once, when it changes.

Every check evaluates the collected results against this OS's requirements in the signed manifest. A required control that changes from compliant to non-compliant triggers an extra claim. Missing results and `unknown` count as non-compliant, regardless of grace. Controls with no requirement for this OS never trigger. The first claim that the gateway answers sets the compliance baseline. Later answers replace that baseline with the results sent.

On Windows, Security event 1102 and any new Defender detection also trigger an extra claim, even if the threat is already resolved. The task user needs `Event Log Readers` access or SYSTEM access to read the Security log. The first successful read of each event source sets its baseline. Later marker advances are saved only after the gateway answers.

The job sends at most one claim per wake and, with only a VPN table, sends nothing off VPN. A change of a check result is the one reason to send inside the interval. The job holds detected events and compliance failures while the VPN is down, even if the control recovers before reconnecting. The next detected connection sends a claim with current results. Only an answer from the gateway clears the pending event. Events before the first successful baseline read are part of that baseline.

The job cannot ask you anything. When only you can fix a problem, it writes one dated line to `schedule.log` in the client home: a changed manifest (run `accept`), a gateway denial with its reasons, a device that waits for approval or was revoked, a transparency log alarm, or an error. The log keeps one old copy: the job moves `schedule.log` to `schedule.log.1` at the start of a run when the file has reached 256 KiB. A log alarm installs no VPN certificate. Read the file after a missed VPN login. Run `check` to see the full result. `claims.jsonl` keeps every claim and response, as for `check`.

The client home holds `device.json` with your choices, an applied-settings receipt in `schedule-applied.json`, `report-schedule.lock`, `claim.lock`, and `schedule.log`. `manifest-to-sign.toml` exists only while `join` or `accept` waits for your answer. Limited jobs keep `report-state.json` there. Windows SYSTEM jobs keep their state in the protected SYSTEM directory and use a sibling `<home hash>.lock` file. State records connectivity, answered claims, compliance, and pending events. A lock prevents overlapping commands. Each client home has its own job name. Updates reset the job state.

Limited Windows operations leave orphaned protected state and the shared binary unchanged. Run `schedule off` from an elevated prompt to remove those leftovers. Elevated removal uses the existing SYSTEM cleanup path when a SYSTEM task or protected state remains. It requires elevation. A held state lock stops removal before the task changes and asks you to retry. Cleanup keeps the shared binary while another SYSTEM task uses it. Otherwise, it queues the binary for deletion at reboot. Incomplete cleanup returns an error and lists the remaining files. Retry `schedule off` from an elevated prompt after the client stops or Windows restarts. Lock files remain. `stop` prints the removal instructions. On Windows it prints the full path of the client and says that a SYSTEM job needs an elevated PowerShell prompt. On Unix, new scheduler homes use mode `0700`. State files use mode `0600` or keep stricter owner permissions.

### Windows device keys

On Windows, TPM protection requires an elevated administrator join. A non-elevated join creates a software key and reports `key_protection = os_permissions`. Existing keys stay in use.

An elevated administrator Windows join tries a non-exportable ECDSA P-256 key in the TPM through the
Microsoft Platform Crypto Provider. The private key does not leave the TPM.
The machine-scope key ACL is configured for the joining user and SYSTEM. Other users do
not receive explicit access. Hosted Windows CI did not verify signing under a standard-user
or SYSTEM task token, so scheduler use under those tokens remains unverified.
Creation requires an elevated administrator prompt. If the provider is unavailable,
the client warns and uses a software key. `--software-key` forces software on a new home.
Existing software keys stay in use. Before rotation, remove the old schedule and run
`open-pact-client --home <old-home> delete-device-key`. To rotate to TPM, use a new `--home`, join again,
and replace the old enrolment and scheduler registration.
The home stores only the TPM key name in `device-tpm.key`. Keep this marker with the home.
TPM claims request `L1`, like Secure Enclave claims. The gateway verifies them as `L0`
until hardware attestation is supported. Real TPM signing is unverified on hosted CI.
See [platform support](docs/platform-support.md#key-protection) for the test limits.
For full uninstall, remove the schedule first. Run `open-pact-client --home <home> delete-device-key` before deleting the home or binary.
Schedule removal keeps the device key. Key deletion removes the persisted CNG key, its marker, and any software device key file.
On Windows, run key deletion as the user who created the key or as SYSTEM. A different administrator has no explicit key access.
Windows CI checks creator deletion after removal of administrator membership, SYSTEM deletion, and refusal for a different administrator through the software CNG provider.
TPM hardware deletion remains unverified on hosted runners. Marker write and ACL failures stop join without software fallback.


## Log-clearing output

`log_cleared` uses `output = { timestamp = true, nullable = true, values = ["n/a"] }`.
A successful read returns the last clearing time as an RFC 3339 UTC string ending in `Z`.
JSON null means both Windows logs were readable and contain no retained clearing event.
The string `"unknown"` means the read failed. The string `"n/a"` means the check does not apply.
A TOML requirement uses `windows = "null"` to accept JSON null. It does not accept the string `"null"`.
Any timestamp fails that requirement. Claims retain actual JSON null through serialization.
These results describe retained log history. They cannot prove that a log was never cleared.
