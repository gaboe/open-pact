# Deploy and operate the gateway

This guide covers the gateway, PostgreSQL, manifest rollout, witness, and SIEM export. The repository is a proof of concept. Do not use the demo Compose secrets or the public demo witness key for a real service.

## Prepare the gateway

Use a PostgreSQL database, a stable HTTPS URL, and persistent storage. Keep PostgreSQL credentials and the key-encryption key outside the database. The gateway needs one 32-byte base64 key in `GATEWAY_KEK`. It encrypts the company signing key, log signing key, CA key, and stored claims in PostgreSQL. Keep a protected backup of the KEK outside the database backups. A wrong KEK prevents startup. KEK rotation is not supported.

Create a key with OpenSSL and store it in a secret manager:

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

To run the local demo, use Docker Compose:

```sh
docker compose up -d --build
```

Compose uses `DEV_INSECURE_KEK=1`, a local HTTP URL, and a public demo witness seed. Use it only for a local demo. Do not expose that gateway or reuse its keys. `GATEWAY_PORT=8091 docker compose up -d` changes the host port.

## Sign and roll out a manifest

Write the manifest as TOML. Include the check IDs and output types that the client supports. Declare the required values, grace periods, `claim_retention`, `claim_recipients`, `data_controller`, and `disclosed_metadata`. The gateway signs and publishes the manifest. During `join`, the owner reviews it and signs its hash.

The gateway publishes the enforced manifest and appends its hash to the transparency log. A changed manifest has a new hash. Enrol the device again with a new invitation, and approve it again. Approval applies to one manifest hash.

The core library can validate whether a manifest change is a narrowing under the old owner signature. The current client and gateway do not apply that capability when they check an enrolled device. Every changed manifest needs a new join, a new owner signature, and operator approval. The owner signs the new manifest hash during the join.

Review retention before each rollout. PostgreSQL stores encrypted claims until the manifest deadline. A backup can keep a deleted claim readable while it still contains the month key and the KEK. Expire database backups and WAL archives in line with the retention that owners accepted.

## Create invitations and approve devices

Create a one-time invitation on the gateway. Use a short lifetime and a fictional note that identifies the device without personal data.

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

The gateway exports one event after each committed claim evaluation from an enrolled device. Events include allow and deny verdicts, including pending, approved, and revoked devices. Invalid claims and failed database commits produce no event. Events contain the pseudonym, manifest hash, OS, verdict, reasons, warnings, trust levels, and declared results. They do not contain raw logs, keys, nonces, JWS values, certificate requests, certificates, or source addresses.

TLS output uses RFC 5424 syslog with RFC 5425 octet counting. File output is one JSON object per line. The queue holds at most 1024 events. It drops the oldest event on overflow and logs a change in the drop count once per minute. Check gateway logs for drop warnings. No metrics endpoint exposes the drop count. The queue is in memory, so a restart loses queued events. Retries can create duplicate events. A successful TLS write does not confirm SIEM ingestion.

The sample Wazuh files are in [`deploy/wazuh`](../deploy/wazuh/README.md). For TLS syslog, install the rsyslog GnuTLS module. Place the receiver CA, certificate, and private key at the paths in [`rsyslog.conf`](../deploy/wazuh/rsyslog.conf). The sample authenticates the receiver to the gateway. It does not require a client certificate from the gateway. Restrict port 6514 to the gateway. Validate the receiver config with `rsyslogd -N1`. Give the JSON output file to a Wazuh agent with [`agent-localfile.xml`](../deploy/wazuh/agent-localfile.xml). For a direct file sink, set `GATEWAY_SIEM_FILE` on the gateway host and grant the Wazuh agent group read access. Do not send both sinks to the same file.

Install [`rules.xml`](../deploy/wazuh/rules.xml) in the Wazuh manager's local rules directory. Reserve rule IDs 100500 through 100505 or change them to avoid conflicts. The optional [`decoder.xml`](../deploy/wazuh/decoder.xml) shows a JSON decoder for a custom decoder chain. The rules use numeric control values. They do not match bucketed strings such as `gt_30d`. Test the rules with `/var/ossec/bin/wazuh-logtest` on the target manager. Test the receiver with `rsyslogd -N1`. The samples have not been tested against a live manager.

Set SIEM retention at least as short as `claim_retention`. `GATEWAY_SIEM_RETENTION_DAYS` logs a warning when the configured SIEM retention exceeds the manifest value. The gateway cannot enforce retention at the SIEM.

## Back up and upgrade

Back up PostgreSQL, the KEK, the gateway deployment configuration, the manifest, and each witness state file. Restrict backup access as you restrict access to the live data. A PostgreSQL backup without the KEK cannot decrypt gateway secrets or claims. A backup with the KEK can expose claims until the backup expires.

Before an upgrade, check the release notes and back up the database, KEK, and witness state. Keep the KEK unchanged. The gateway migrates existing key rows to encrypted form when it first starts with a KEK. A wrong KEK stops startup. Do not start two witness processes with the same key and state. When upgrading an old witness that used a `.lock` file, stop it before starting the new version.

Upgrade the Helm release with the same release name and values file. Keep the KEK and database Secret names in that file:

```sh
helm upgrade --install pact deploy/helm/open-pact -f gateway-values.yaml
```

The chart restarts the gateway when the manifest changes. Confirm that the gateway is ready, then check the transparency checkpoint and SIEM delivery logs.

## Troubleshoot common failures

| Symptom | Check |
| --- | --- |
| Gateway will not start without a KEK | Set `GATEWAY_KEK` from the protected Secret. Do not enable `DEV_INSECURE_KEK` outside the local demo. |
| Gateway rejects the KEK | Restore the exact KEK that encrypted the database rows. The gateway does not replace unreadable keys. |
| Helm render fails | Set `gateway.kekSecret.name` and either `postgres.password` or `postgres.existingSecret`. |
| Client invitation uses the wrong URL | Set Helm `publicUrl` to the public HTTPS URL, then create a new invitation. |
| Device claim is denied while pending | Approve its device code with `open-pact-gateway devices approve`. |
| Device approval no longer applies | Enrol and approve the device against the current manifest hash. |
| Witness rejects a checkpoint | Check the manifest witness key, quorum, witness state, and gateway `log.witnessUrls`. Keep one process per witness state. |
| SIEM export is disabled | Check gateway logs for invalid sink configuration. Configure one sink and verify the CA or file path. |
| SIEM drop count increases | Restore receiver access. Inspect queue overflow. The in-memory queue cannot recover dropped events after restart. |
| Wazuh cannot read file events | Set `GATEWAY_SIEM_FILE_MODE=0640` before the gateway creates the file. Grant the Wazuh group access to the parent directory. Add the gateway process to that group. Add the Wazuh agent to that group. |
