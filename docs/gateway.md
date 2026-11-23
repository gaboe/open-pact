# Deploy and operate the gateway

This guide covers the gateway, PostgreSQL, manifest rollout, witness, and SIEM export. The repository is a proof of concept. Do not use the demo Compose secrets or the public demo witness key for a real service.

## Prepare the gateway

Use a PostgreSQL database, a stable HTTPS URL, and persistent storage. Keep PostgreSQL credentials and the key-encryption key outside the database. The gateway needs one 32-byte base64 key in `GATEWAY_KEK`. It encrypts the company signing key, log signing key, CA key, and stored claims in PostgreSQL. Keep a protected backup of the KEK outside the database backups. A wrong KEK prevents startup. KEK rotation is not supported.

Create a key with OpenSSL:

Store the output in a secret manager:

```sh
openssl rand -base64 32
```

The default Helm chart includes PostgreSQL. You can use an external database with `database.externalUrl`. Use a TLS ingress for the public URL. The chart enables ingress TLS by default.

## Deploy with Helm

Create a Kubernetes Secret for the KEK and one for the PostgreSQL password. The chart also accepts an existing PostgreSQL Secret.

```sh
kubectl create secret generic pact-gateway-kek --from-literal=kek="$(openssl rand -base64 32)"
helm upgrade --install pact deploy/helm/open-pact \
  --set image.repository=registry.example.org/open-pact/gateway \
  --set image.tag=0.2.0 \
  --set witness.image.repository=registry.example.org/open-pact/witness \
  --set witness.image.tag=0.2.0 \
  --set gateway.kekSecret.name=pact-gateway-kek \
  --set postgres.existingSecret=pact-postgres
```

Set `image.repository` and `image.tag` to the gateway image that you built or approved. Set `witness.image.repository` and `witness.image.tag` to the witness image. The chart defaults point to placeholder addresses. Set `postgres.password` instead of `postgres.existingSecret` only when your deployment system protects the value. Set `publicUrl` to the HTTPS address that clients will use. The chart writes that URL into invitations. Set `log.origin` to the public log name that you want clients to pin.

The chart refuses to render without a KEK Secret name and a password for its bundled PostgreSQL. To enforce your own manifest, provide the TOML file with `--set-file manifest=manifest.toml`. Helm puts it in a ConfigMap, mounts it at `/etc/open-pact/custom/manifest.toml`, sets `MANIFEST_PATH`, and restarts the gateway when the file changes.

Size the nonce limits for the fleet. `nonces.maxPerWindow` (chart default 3000; binary default 600) sets `NONCE_MAX_PER_WINDOW`. It counts per gateway process and per source address, so behind an ingress all devices share it: at least 2 x devices that run in one window (`nonces.windowSecs` sets `NONCE_WINDOW_SECS`, chart default 60 s) x 1.5. Count the peak runs in one window. Native IPv6 addresses in one /64 share one count. `nonces.maxOutstanding` (default 10000) sets `NONCE_MAX_OUTSTANDING`. It counts unexpired nonce rows in PostgreSQL, shared by every replica on the same database, and needs at least the unused nonces of 5 minutes. A run uses its nonces within seconds, but a burst of failing clients can fill it. At 3000 a minute, 15,000 requests fit in the 5-minute nonce life, so `maxOutstanding` can answer 503 first. A direct deployment sets these three variables itself. Docker Compose sets none of them, so it uses the binary defaults 600, 60 and 10000.

To run the local demo, use Docker Compose:

```sh
docker compose up -d --build
```

Compose uses `DEV_INSECURE_KEK=1`, a local HTTP URL, and a public demo witness seed. Use it only for a local demo. Do not expose that gateway or reuse its keys. `GATEWAY_PORT=8091 docker compose up -d` changes the host port.

## Sign and roll out a manifest

Write the manifest as TOML. Include the check IDs and output types that the client supports. Declare the required values, grace periods, `claim_retention`, `claim_recipients`, `data_controller`, and `disclosed_metadata`. The gateway signs and publishes the manifest. During `join`, the owner reviews it and signs its hash.

The gateway publishes the enforced manifest and appends its hash to the transparency log. A changed manifest has a new hash. To roll it out, set the new manifest and restart the gateway. Do not send new invitations. Do not approve devices again.

A device enrolled under an earlier manifest keeps its approval and keeps working. Updating the client is enough for it to send the manifest that its owner signed beside each claim. Accepting the new manifest is what moves the device to it. The device can hold one enrolment per manifest that its owner signed. The gateway judges a claim only under the enrolment in use: the one under the enforced manifest, or else the newest. A claim under another enrolment is denied. An accepted device keeps one enrolment. The gateway accepts that text only when its hash equals the hash stored for the device, so the operator does not keep earlier manifests in the configuration. The signed manifest decides what the claim may disclose and how long the gateway keeps it: `disclosed_metadata`, `claim_retention`, and `claim_recipients` stay those of the signed manifest. The new manifest decides the verdict. Every required control of the new manifest counts:

- A control that the signed manifest does not collect fails with its own `grace`. The grace starts at the first claim without it. Inside the grace, the claim is accepted with a warning that names the control, the time left, and `open-pact-client accept`. After the grace, the claim is denied and gets no VPN certificate.
- A control that both manifests collect is judged by the new requirement. A tightened requirement fails with that control's own `grace`, like any other failing control.

The owner runs `open-pact-client accept`. The client shows the new manifest and its changes, and the owner and the device sign a statement that names both hashes and a gateway nonce. The gateway checks the signatures, the device key, and the owner key from enrolment. It then moves the device to the new hash and appends a `manifest_accepted` entry to the log. The device keeps its state: approved, pending, and revoked devices stay so. Its grace clocks move with it. An older client's claims are denied until the owner updates the client. The updated client sends its signed manifest and gets the warning. `accept` moves the device to the new manifest. A claim without a valid signed manifest text is denied without being stored, because the gateway cannot know its retention terms. If an acceptance stops after the gateway records it, `check` names `accept` again. Running `accept` again finishes the move, and the gateway answers the same.

To let devices send claims automatically, add a `[schedule.vpn]` table, a `[schedule.always]` table, or both to the manifest. `[schedule.vpn]` needs an address that connects only on the company VPN, such as the VPN gateway, as `probe`, and an `interval`; devices check every `check` period (default `5m`) while that address answers, send at once on connect or when a result gets worse, and at least every `interval`. `[schedule.always]` needs only an `interval`; devices send on any network. The client job wakes every minute and decides from the manifest what is due, so a manifest change sets the period without a new job. [docs/client.md](client.md#what-one-wake-does) lists every rule. The older flat form (`mode`, `vpn_probe`, `interval`) still works with its 0.7 meaning. The table is part of the signed manifest, so the owner reads it before signing, and a change to it appears in the `accept` list of changes. When a new manifest adds automatic sending, changes a probe, shortens an interval, or checks more often, `accept` turns automatic sending off until the owner runs `schedule on` again. Anyone who can reach `GET /v1/manifest` can read the probe address, so choose an address that is no secret. A manifest without `[schedule]` means devices send claims only by hand. Clients up to 0.4.9 reject a manifest that has a `[schedule]` table: `join` and `accept` fail on them with an unknown field error. Upgrade every client before you add `[schedule]` to the manifest. The gateway is the only server that receives claims; devices send no separate report.

The core library can validate whether a manifest change is a narrowing under the old owner signature. The client applies only the schedule rule, which turns automatic sending off when the new manifest widens the schedule. The owner signs every changed manifest with `accept`, without a new invitation or operator approval.

Review retention before each rollout. PostgreSQL stores encrypted claims until the manifest deadline. A backup can keep a deleted claim readable while it still contains the month key and the KEK. Expire database backups and WAL archives in line with the retention that owners accepted.

## Create invitations and approve devices

Create a one-time invitation on the gateway. Use a short lifetime and a fictional note that identifies the device without personal data. The note stays in the gateway database and is sent in SIEM events when a SIEM sink is configured. It is never in the transparency log.

```sh
kubectl exec deploy/pact-gateway -- open-pact-gateway invite \
  --url https://pact.example.com --ttl 72h --note "Example laptop"
```

The command prints an `opi1:` invitation. Give it to the device owner over a trusted channel. The invitation pins the gateway URL, company key fingerprint, and log key. Confirm the company fingerprint out of band.

The owner runs `open-pact-client join 'opi1:replace-with-invitation'`. The client displays the manifest and asks the owner to sign its hash. The gateway stores the device as pending. Approve the short device code that `join` prints:

```sh
kubectl exec deploy/pact-gateway -- open-pact-gateway devices list
kubectl exec deploy/pact-gateway -- open-pact-gateway devices approve 0123456789ab
```

Use `kubectl exec deploy/pact-gateway -- open-pact-gateway devices revoke 'pseudonym:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'` to revoke an enrolled device. `AUTO_APPROVE=true` approves each new device without IT review. Keep it false unless that behavior is intended.

### Read the gateway as JSON

An app can run these commands through `kubectl exec`. Each prints one JSON document on stdout. On a database or other error it prints `{"error": "<text>"}` and exits non-zero. A command line that does not parse, such as `--ttl invalid`, prints the same error document and exits 2.

```sh
kubectl exec deploy/pact-gateway -- open-pact-gateway devices list --json
kubectl exec deploy/pact-gateway -- open-pact-gateway invite --url https://pact.example.com --ttl 72h --note "Example laptop" --json
kubectl exec deploy/pact-gateway -- open-pact-gateway status --json
```

`devices list --json` prints an array with one object per enrolment, oldest first:

```json
[{"pseudonym": "pseudonym:0123…", "code": "0123456789ab", "state": "approved", "note": "Example laptop",
  "enrolled_at": "2026-11-02T10:00:00Z", "manifest_hash": "sha256:…",
  "last_claim_at": "2026-11-03T08:15:00Z", "last_result": "accepted_with_warnings",
  "last_reasons": ["os_patch_age_days = 40, <= 30 required, access ends in 24h"]}]
```

`code` is the first 12 hex digits of the pseudonym, which `devices approve` takes. `note` is the invitation note, empty when there is none. `last_claim_at`, `last_result` and `last_reasons` are the gateway's decision on the last claim of this enrolment. `last_result` is `accepted`, `accepted_with_warnings` or `denied`. `last_reasons` holds the warnings of an accepted claim or the reasons of a denied one, and is empty for a clean accepted claim. A device that never sent a claim has `null` in `last_claim_at` and `last_result` and `[]` in `last_reasons`. The gateway writes them in the transaction that decides the claim, as plain columns of the `devices` table. A claim that carries data the manifest does not allow is not stored, and its reasons can quote that data, so its `last_reasons` is the one line "the claim disclosed more than the manifest allows". The gateway also writes `last_access_until`, the end of the certificate that the last claim got, in the same transaction. An accepted claim that got no certificate stores its own decision time, because its access ended at once. The column is null after a denial, and for an enrolment whose last claim the gateway decided before it kept this column; the next claim replaces that null. `claims list` and `claims show` read it to derive a standing.

`invite --json` prints `{"invitation": "opi1:…", "expires_at": "2026-11-05T10:00:00Z", "company_key_fingerprint": "sha256:…", "note": "Example laptop"}` and nothing on stderr.

`status --json` reads the manifest the same way `serve` does. The active database version takes precedence. Without one, the gateway reads `MANIFEST_PATH`, or the example manifest when that variable is unset. Status also reports `AUTO_APPROVE`:

```json
{"version": "0.6.0", "manifest_hash": "sha256:…", "manifest_source": "database", "manifest_version": 3, "auto_approve": false,
 "devices": {"pending": 1, "approved": 12, "revoked": 0}, "company_key_fingerprint": "sha256:…"}
```

`manifest_source` is `database`, `file` for `MANIFEST_PATH`, or `builtin` for the image's example manifest. `manifest_version` is the active database version, or `null` for either file source. `devices` counts distinct pseudonyms per state. Without `--json`, `status` prints the same facts as text.

## VPN certificate lifetime

An accepted claim gets a VPN client certificate. Its end is the earliest of these limits:

- Twice the send interval on the VPN. With both `[schedule.vpn]` and `[schedule.always]`, the shorter interval counts. The gateway uses the schedule of the manifest it enforces, never the one the device signed, so a shorter interval takes effect before the owner accepts the new manifest.
- `claim_max_age` of the enforced manifest.
- 24 hours.
- The nearest grace deadline of a failing control. A claim accepted with a warning gets a certificate that ends when the warned grace runs out.

A manifest without a schedule has no interval limit. A claim with no time left under these limits gets no certificate. The gateway fixes the end as one time from one clock reading, in whole seconds, so a certificate never ends after the grace deadline. It writes the end into the certificate, and it keeps the same end with the claim as `certificate_not_after`.

The gateway does not revoke a certificate before its end. A device that stops being compliant keeps VPN access until the certificate ends, and it gets no new certificate. A shorter `claim_max_age` shortens every certificate. How long a live tunnel stays up after its certificate ends depends on the VPN product, so check its re-authentication setting.

## Read results

IT can read what devices reported without a database client. Both commands only read. They open the stored claims with the KEK, so they need `GATEWAY_KEK` in the gateway container, and they add no HTTP route. With `--json` each prints one JSON document. On an error it prints `{"error": "<text>"}`. Usage errors, such as `--limit 0`, print the same error document and exit 2. Other errors exit 1. These commands never migrate the database. On a database older than this gateway they print an error that says to start the gateway once, and they write nothing.

```sh
kubectl exec deploy/pact-gateway -- open-pact-gateway claims list --json --device 0123456789ab --result warnings --limit 20
kubectl exec deploy/pact-gateway -- open-pact-gateway claims show 4812 --json
```

`claims list` prints the newest claims first. Every filter is optional and the filters combine:

- `--device` takes at least 8 hex digits of a device pseudonym, as `devices approve` does.
- `--result` is `accepted`, `warnings` or `denied`.
- `--since` is an RFC 3339 time. A claim received at that time is included.
- `--limit` is the number of claims to print: 100 by default, 1000 at most. The command stops reading after that many matches.

```json
{"claims": [{"id": 4812, "received_at": "2026-11-03T08:15:00Z", "device": "pseudonym:0123…",
             "device_note": "Example laptop", "manifest_hash": "sha256:…", "result": "warnings",
             "failed_controls": ["os_patch_age_days"], "access_until": "2026-11-03T10:05:00Z", "standing": "lapsed"}],
 "unreadable": 0}
```

`device_note` is the invitation note of the device, empty when it has none.

`access_until` is the end of the VPN certificate that this claim got, in RFC 3339. It is `null` for a denied claim, for a claim without a certificate, and for a claim stored before this version. It stays the claim's own end even after the device has a newer claim.

`standing` describes the device when the command runs, so every claim of one device shows the same value. It is one of these values:

- `current`: the last claim was accepted, and its certificate has not ended.
- `lapsed`: the last claim was accepted, its certificate has ended, and no newer claim renewed it.
- `unknown`: the last claim was accepted before the gateway kept the end of its certificate, so the gateway cannot tell whether that certificate still runs. The device's next claim replaces it with another value.
- `denied`: the last claim was denied.
- `silent`: the last claim is older than twice the send interval, or the device never claimed. Without a schedule in the manifest, a device with a claim is never silent.

The command derives the standing from the device's last decision and the clock. No job stores it, and no certificate is revoked for it. `failed_controls` lists the required controls that do not pass, inside their grace or not. `unreadable` counts the claims the command met that it cannot open, because retention deleted the key of their month. No filter applies to them.

`claims show <id>` prints one claim with every control of the manifest it was made under:

```json
{"id": 4812, "received_at": "2026-11-03T08:15:00Z", "device": "pseudonym:0123…", "device_note": "Example laptop",
 "manifest_hash": "sha256:…", "os": "linux", "client_version": "0.6.0", "trust_level": "L0", "result": "warnings",
 "access_until": "2026-11-03T10:05:00Z", "standing": "lapsed",
 "controls": [{"id": "os_patch_age_days", "value": 40, "required": "<= 30", "status": "fail", "grace": "1d",
               "first_failed_at": "2026-11-02T08:15:00Z", "deadline": "2026-11-03T08:15:00Z"}]}
```

`status` is `pass`, `fail`, `unknown` (the device reported `unknown`) or `not_required` (the manifest requires nothing for this OS). `grace` is the grace of a control that fails: its own, or `unknown_grace` for an `unknown` value. `first_failed_at` is the start the gateway holds now for that control, and `deadline` is that start plus `grace`. Both are `null` when the control passes or the gateway holds no start. `value` is `null` when the claim has no value for the control.

The command finds the manifest by its hash in the stored versions, or in the manifest the process started with. When it finds neither, it cannot evaluate: `result` comes from the stored decision, every control has `"required": null` and `"status": "unknown"`, and `failed_controls` of `claims list` is empty. `result` is `null` for a claim that an early version stored with no decision. The result is derived from the stored decision and the claim's own manifest, so a claim that was accepted only because of a manifest the device had not accepted yet can show `accepted`. A claim shown for an id that does not exist, or whose month key retention deleted, prints an error and exits 1.

Without `--json`, both commands print a short table.

## Run a witness

A witness keeps its own Ed25519 key and latest checkpoint. Run it under a different operator and in a separate environment from the gateway. A witness run by the gateway operator cannot show that operator a conflicting log history.

Create the key with `open-pact-witness keygen`. Store the seed in a secret and the witness state on persistent storage. Add the witness name and verifier key to the manifest's `[log]` section. Set `witness_quorum` above half the witness count. Configure the gateway's `log.witnessUrls` to send checkpoints to the witness. Deploy the witness as a separate Helm release with `gateway.enabled=false`, `witness.enabled=true`, its key Secret, persistent storage, and confirmed `witness.logKeys`.

Set `witness.image.repository` and `witness.image.tag` to the witness image that you built or approved before you install this release. The chart defaults point to a placeholder address.

Generate the witness key on a trusted host. The command writes the private seed to `witness.key` and prints the verifier key for the manifest:

```sh
WITNESS_NAME=witness.example.org/w1 WITNESS_KEY_FILE=witness.key open-pact-witness keygen
kubectl create secret generic pact-witness-key --from-file=witness.key
helm upgrade --install pact-witness deploy/helm/open-pact \
  --set gateway.enabled=false \
  --set witness.enabled=true \
  --set witness.image.repository=registry.example.org/open-pact/witness \
  --set witness.image.tag=0.2.0 \
  --set witness.name=witness.example.org/w1 \
  --set witness.keySecret.name=pact-witness-key \
  --set 'witness.logKeys[0]=pact.example.com/log+<id>+<base64-key>'
```

Replace the verifier-key placeholder with the gateway key that you confirmed out of band. Add the witness verifier key and name to the owner's manifest before the owner signs it. Set `log.witnessUrls` in the gateway release to the witness service URL.

Run one process per witness key and state file. Do not run the same key on two hosts. Back up the witness state. If it is lost, the witness can no longer prevent a gateway rollback from its last saved checkpoint.

## Export events to a SIEM

SIEM export is off by default. Choose one sink. The TLS syslog sink accepts `GATEWAY_SIEM_SYSLOG_URL=tls://siem.example.com:6514` and `GATEWAY_SIEM_CA=/path/to/ca.pem`. It requires an explicit port and a CA file. The receiver certificate must match the URL host. The file sink uses `GATEWAY_SIEM_FILE=/var/log/open-pact/events.jsonl` and requires an existing writable parent directory. Do not configure both sinks.

New Unix files use mode `0600` by default. The `GATEWAY_SIEM_FILE_MODE` setting accepts only `0600` or `0640`. Set it to `0640` before the gateway creates the file when a Wazuh reader needs group access. The process umask can remove group-read access. Add the gateway process to the Wazuh group. Grant that group read and execute access to the parent directory. For an existing file, change its group and mode yourself. For example, run `chgrp wazuh /var/log/open-pact/events.jsonl`. Then run `chmod g+r /var/log/open-pact/events.jsonl`. Keep the gateway as the only writer to this file.

For Helm, set `siem.enabled=true`, `siem.syslogUrl`, `siem.caSecret.name`, and `siem.retentionDays`. The Secret key defaults to `ca.pem`. The chart mounts the CA read-only. Restart the gateway after you change the CA Secret. The chart exposes `siem.fileMode`, but its built-in sink uses TLS. `fileMode` applies only to a separately configured file sink.

The gateway exports one event after each committed claim evaluation from an enrolled device. Events include allow and deny verdicts, including pending, approved, and revoked devices. Invalid claims and failed database commits produce no event. Events contain the pseudonym, manifest hash, OS, verdict, reasons, warnings, trust levels, and declared results. Each event also carries `access_until`, the end of the VPN certificate that the claim got, or `null` when the claim got none, and for each control with a declared result `status_<id>` and `deadline_<id>`, plus `access_ends`, the earliest end of grace. See the event schema in the README. They do not contain raw logs, keys, nonces, JWS values, certificate requests, certificates, or source addresses.

`devices approve` and `devices revoke` send one `device_state` event when they change a device, as the README describes. The CLI process needs the same `GATEWAY_SIEM_*` variables as the server. It waits at most 15 seconds and does not retry. When the send fails, the database change stands: the command prints a warning on stderr and exits 0. A command that changes nothing sends nothing. With `AUTO_APPROVE=true`, the server sends the `approved` event itself for each enrolment it approves, through its queued exporter. Each `device_state` event carries `log_index`, the index of the log entry that recorded the change. Order one device's `device_state` events by it.

TLS output uses RFC 5424 syslog with RFC 5425 octet counting. File output is one JSON object per line. The queue holds at most 1024 events. It drops the oldest event on overflow and logs a change in the drop count once per minute. Check gateway logs for drop warnings. No metrics endpoint exposes the drop count. The queue is in memory, so a restart loses queued events. Retries can create duplicate events. A successful TLS write does not confirm SIEM ingestion.

The sample Wazuh files are in [`deploy/wazuh`](../deploy/wazuh/README.md). For TLS syslog, install the rsyslog GnuTLS module. Place the receiver CA, certificate, and private key at the paths in [`rsyslog.conf`](../deploy/wazuh/rsyslog.conf). The sample authenticates the receiver to the gateway. It does not require a client certificate from the gateway. Restrict port 6514 to the gateway. Validate the receiver config with `rsyslogd -N1`. Give the JSON output file to a Wazuh agent with [`agent-localfile.xml`](../deploy/wazuh/agent-localfile.xml). For a direct file sink, set `GATEWAY_SIEM_FILE` on the gateway host. Grant the Wazuh agent group read access to the file. Do not send both sinks to the same file.

Install [`rules.xml`](../deploy/wazuh/rules.xml) in the Wazuh manager's local rules directory. Reserve rule IDs 100500 through 100507 or change them to avoid conflicts. The optional [`decoder.xml`](../deploy/wazuh/decoder.xml) shows a JSON decoder for a custom decoder chain. The rules use numeric control values. They do not match bucketed strings such as `gt_30d`. Test the rules with `/var/ossec/bin/wazuh-logtest` on the target manager. Test the receiver with `rsyslogd -N1`. The samples have not been tested against a live manager.

Set SIEM retention at least as short as `claim_retention`. `GATEWAY_SIEM_RETENTION_DAYS` logs a warning when the configured SIEM retention exceeds the manifest value. The gateway cannot enforce retention at the SIEM.

## Back up and upgrade

Back up PostgreSQL, the KEK, the gateway deployment configuration, the manifest, and each witness state file. Restrict backup access as you restrict access to the live data. A PostgreSQL backup without the KEK cannot decrypt gateway secrets or claims. A backup with the KEK can expose claims until the backup expires.

Read the release notes before an upgrade. Back up the database, KEK, and witness state. Keep the KEK unchanged. The gateway migrates existing key rows to encrypted form when it first starts with a KEK. A wrong KEK stops startup. Do not start two witness processes with the same key and state. When upgrading an old witness that used a `.lock` file, stop it before starting the new version.

Upgrade the Helm release with the same release name and values file. Keep the KEK and database Secret names in that file:

```sh
helm upgrade --install pact deploy/helm/open-pact -f gateway-values.yaml
```

The chart restarts the gateway when the manifest changes. Confirm that the gateway is ready. Check the transparency checkpoint and SIEM delivery logs.

## Read log entries

Log entries are private. The public `/v1/log/entries` and `/v1/log/proof/inclusion` routes return 404. An approved device uses `POST /v1/log/mine` to get its signed manifest and its own device entries with inclusion proofs. The log key, signed checkpoint and consistency proofs remain public. Witnesses receive checkpoints and consistency proofs by push; they do not download entries.

Public consistency proofs expose leaf hashes for log changes. An outsider who polls checkpoints can count and time changes. The outsider can recognize manifest and retention-purge entries, then identify the remaining changes as device events. Salted commitments stop the outsider from linking a device event to a device. Entry contents remain private. Witnesses verify checkpoint consistency, and each approved device verifies its own entries.

Operators can read JSON lines directly from the database through `kubectl exec <gateway-pod> -- open-pact-gateway log entries --from 0 --limit 256`. Both flags are optional. Their defaults are 0 and 256. This command requires database access; it does not expose an HTTP route.

## Troubleshoot common failures

| Symptom | Check |
| --- | --- |
| Gateway will not start without a KEK | Set `GATEWAY_KEK` from the protected Secret. Do not enable `DEV_INSECURE_KEK` outside the local demo. |
| Gateway rejects the KEK | Restore the exact KEK that encrypted the database rows. The gateway does not replace unreadable keys. |
| Helm render fails | Set `gateway.kekSecret.name` and either `postgres.password` or `postgres.existingSecret`. |
| Client invitation uses the wrong URL | Set Helm `publicUrl` to the public HTTPS URL. Create a new invitation. |
| Device claim is denied while pending | Approve its device code with `open-pact-gateway devices approve`. |
| Device approval no longer applies | Enrol the device against the current manifest hash. Approve the device. |
| Witness rejects a checkpoint | Check the manifest witness key, quorum, witness state, and gateway `log.witnessUrls`. Keep one process per witness state. |
| SIEM export is disabled | Check gateway logs for invalid sink configuration. Configure one sink. Verify the CA or file path. |
| SIEM drop count increases | Restore receiver access. Inspect queue overflow. The in-memory queue cannot recover dropped events after restart. |
| Wazuh cannot read file events | Set `GATEWAY_SIEM_FILE_MODE=0640` before the gateway creates the file. Grant the Wazuh group access to the parent directory. Add the gateway process to that group. Add the Wazuh agent to that group. |

## Change the manifest without a redeploy

The gateway keeps manifest versions in PostgreSQL. An active database version takes precedence over the Helm manifest or MANIFEST_PATH. Running gateways load the active version within 10 seconds. Devices that signed an earlier manifest use the existing accept flow.

Use these four commands through kubectl. Replace the deployment name and version with your values. The set command reads the exact TOML text from stdin. It validates the manifest before it stores a version. The activate command restores a stored version.

```sh
kubectl exec -i deployment/open-pact-gateway -- open-pact-gateway manifest set --note "Policy update" --json < manifest.toml
kubectl exec deployment/open-pact-gateway -- open-pact-gateway manifest history --json
kubectl exec deployment/open-pact-gateway -- open-pact-gateway manifest get --version 1 > manifest-backup.toml
kubectl exec deployment/open-pact-gateway -- open-pact-gateway manifest activate 1 --json
```

Omit --version to get the active manifest. Save a local backup with manifest get before each change. The history includes the version, hash, creation time, note and active state. The set and activate replies include the version, manifest_hash and previous_hash. Use status --json to read manifest_source and manifest_version. The source is database, file or builtin. The version is null for a file or the example manifest.
