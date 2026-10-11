# open-pact

Verifiable security checks on personally owned devices, without blanket monitoring. The owner signs the company's manifest once. Each time the device connects, the client sends one small signed claim to the company gateway, and a compliant device gets a short-lived VPN client certificate. Read [PAPER.md](PAPER.md) for the design.

Status: proof of concept, not for production. On a Mac, `join` creates the device key in the Secure Enclave, and the client reports trust level L1; elsewhere, or with `join --software-key`, all keys are development software keys (trust level L0). The gateway has no attestation, so it counts every claim as L0 whatever the client reports. The gateway enforces [examples/manifest.toml](examples/manifest.toml), or the file in `MANIFEST_PATH`.

## Layout

- `crates/open-pact-core` manifest, signatures, narrowing, claims (RFC 8785 + JWS), evaluation, the Merkle transparency log and signed checkpoints
- `crates/open-pact-client` CLI: `join <invitation>`, `check`, `log head`, `log prove`, `log show`, `stop`
- `crates/open-pact-gateway` HTTP gateway, small CA and transparency log, backed by PostgreSQL; admin commands `invite` and `devices`
- `deploy/helm/open-pact` Helm chart (values use placeholders)

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
| `device-se.key` | device key on a Mac: a Secure Enclave key wrapped for this Mac only; signs the enrolment statement and claims, its public key's hash is the pseudonym |
| `device-dev.pem` | device key as a software file, instead of `device-se.key` |
| `vpn-key.pem` | VPN certificate key; only its certificate request leaves the device |
| `manifest.toml`, `enrolment.json` | the signed manifest, gateway URL and the salt that opens the enrolment commitment |
| `vpn-cert.pem`, `ca.pem` | the last VPN client certificate and the gateway CA |
| `company-key.txt`, `log-key.txt` | the company key fingerprint and the log key, pinned from the invitation at `join` |
| `log-checkpoint.txt` | the last verified, gateway-signed log checkpoint |
| `claims.jsonl` | every claim sent and every response, byte for byte |

Nothing runs in the background. To uninstall, delete the binary and the directory.

## Verify a release

The gateway image is reproducible: a pinned toolchain and builder, a static musl binary, `FROM scratch`, and timestamps fixed to the commit time. CI builds each release twice on separate runners and fails when the digests differ. The witness image (`ghcr.io/<owner>/open-pact-witness`, the Dockerfile `witness` target) is built and checked the same way. To check a release yourself, run `scripts/verify-release.sh v0.0.1 ghcr.io/<owner>/open-pact-gateway@sha256:<digest>`, or add `--target witness` and the witness image reference. It rebuilds the tag from the public source, prints the digest, and exits nonzero on a mismatch. It needs Docker with buildx and takes several minutes. The gateway makes no outbound TLS calls, so the image carries no CA bundle (do not use `sslmode=verify-full` for PostgreSQL).

## Gateway API

| Request | Response |
| --- | --- |
| `GET /v1/manifest` | `{toml, company}`: the enforced manifest and the company's signature over its hash |
| `POST /v1/enroll {signed_manifest, device_key, invitation_code, owner_signature, device_signature}` | `{status: "enrolled", device, state, salt, log_index, manifest_log_index, log_checkpoint}`. See [Enrolment](#enrolment). `state` is `pending` until IT approves. |
| `POST /v1/nonce` | `{nonce}`, single use, valid 5 minutes; 429 after `NONCE_MAX_PER_WINDOW` (default 600) nonces in `NONCE_WINDOW_SECS` (default 60) from one address, IPv6 per /64; 503 while `NONCE_MAX_OUTSTANDING` (default 10000) unexpired nonces exist. Expired nonces are deleted every minute |
| `POST /v1/claim {jws}` | `{status: "accepted", warnings, certificate_pem, ca_pem, log_checkpoint}`, or 403 `{status: "denied", reasons}` |
| `GET /v1/log/key` | the log verifier key, `<origin>+<key id>+<base64 key>` |
| `GET /v1/log/checkpoint` | the signed checkpoint note, with stored witness cosignatures |
| `GET /v1/log/entries?from=&to=` | `{entries}`, `from` inclusive, `to` exclusive, at most 256 entries; without `to`, one page |
| `GET /v1/log/proof/inclusion?index=&size=` | `{index, size, proof}`, hashes in lowercase hex |
| `GET /v1/log/proof/consistency?from=&to=` | `{from, to, proof}` |
| `GET /v1/log` | 410: the v0.1.0 hash-chain endpoint is gone |
| `GET /` | aggregate summary page, no per-device detail |

A claim is accepted only if the device is enrolled for the enforced manifest and approved, the `client` field is exactly `open-pact-client <major>.<minor>.<patch>`, the nonce is unused, the claim time is within `claim_max_age` and not more than 5 minutes ahead, and the results meet the manifest. The client posts `{"jws": ..., "csr_pem": ...}`. The certificate request travels beside the JWS, and the signed claim carries only `csr_sha256`, the SHA-256 of the request's DER. The request must carry a P-256 public key and nothing else: canonical PEM with no text around it, an empty subject, and no attributes or extensions. If the request matches `csr_sha256`, the gateway issues a client certificate for its public key: CN = the pseudonym's 64 hex digits, extended key usage `clientAuth`, key usage `digitalSignature` and an authority key identifier, valid 24 hours or `claim_max_age` if shorter. The gateway stores the signed claim and the certificate's SHA-256, never the request. Each version component in `client` is a `u32` without leading zeros, so the field stays short.

**Grace.** The gateway stores, per device, manifest and control, the time it first saw a required control fail or report `unknown`. A passing value clears it; a missing result denies at once and keeps it. While the failure is younger than the control's `grace` (or `unknown_grace` for `unknown`), the claim is accepted with a warning such as `firewall = off, on required, access ends in 23h`. After that it is denied with `firewall = off, on required, grace 1d ended`. `grace = "0d"` denies the first failed claim. Changing between a failed value and `unknown` keeps the first time. Only a claim that passes the client, manifest, time, trust level and disclosure checks from an enrolled device changes the stored times.

## Enrolment

IT creates a one-time invitation on the gateway. In Kubernetes, run it with `kubectl exec`:

```sh
open-pact-gateway invite --ttl 72h --note "laptop for the new contractor"
```

It prints the `opi1:` string on stdout and a readable form on stderr. The string is base64url JSON with the gateway URL (`--url`, default `PUBLIC_URL`), the company key fingerprint, the log key, and a code of 256 random bits. The gateway stores only the SHA-256 of the code, its expiry (at most 30 days) and the note. The note never reaches the log.

The owner runs `open-pact-client join 'opi1:...'`. Before it shows the manifest or sends anything, the client checks that the gateway serves the company key and the log key that the invitation names, and verifies the signed checkpoint. Then it pins both keys. The owner key and the device key both sign one statement over the manifest hash, the invitation hash and both public keys. The gateway checks both signatures, its own company key and the enforced manifest. Then it consumes the invitation and stores the device as `pending`, in one transaction. Running `join` again with the same invitation from the same device changes nothing. A device enrolled before invitations existed stays approved, but the client has no pinned keys; the owner joins again with a new invitation, which binds to the device and keeps its state.

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

**Checkpoints.** The gateway signs a checkpoint, the C2SP [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) body `<origin>\n<size>\n<base64 root>\n`, in C2SP [signed-note](https://c2sp.org/signed-note) format. The key name is the origin, set by `LOG_ORIGIN` (default `pact.example.com/log`). The log key is ECDSA P-256, signed-note type `0x02` as transparency-dev/formats implements it: a DER signature over SHA-256, and a key ID from the DER public key. Most C2SP tools use Ed25519. P-256 keeps the log key in the same hardware as the other keys.

**Witnesses.** A witness is a separate service, `open-pact-witness`, with its own Ed25519 key and its own state file. It implements the C2SP [tlog-witness](https://c2sp.org/tlog-witness) `add-checkpoint` call. It keeps the latest checkpoint it cosigned for each log. It cosigns a new checkpoint only with a valid consistency proof from that size, and it refuses forks and rollbacks (422 and 400) and a stale old size (409 with the size it holds). Run one process per witness key, with one state file. At start the witness takes an exclusive lock on `<state>.lock` and holds it until it exits, so a second process on the same state refuses to start. The lock does not reach other hosts or network file systems: never run one witness key on two hosts. The cosignature is Ed25519 `cosignature/v1` with a timestamp (C2SP [tlog-cosignature](https://c2sp.org/tlog-cosignature)).

The manifest names the witnesses, so the owner signs the witness set and no one can change it without them:

```toml
[log]
witnesses = [{ name = "witness.example.org/w1", key = "witness.example.org/w1+<id>+<key>" }]
witness_quorum = 1          # cosignatures a client requires
checkpoint_max_age = "1h"   # oldest cosignature a client accepts
```

`witness_quorum` must be more than half of the listed witnesses: 1 of 1, 2 of 2 or 3, 3 of 4. Any two sets that large share a witness, and that witness cosigns only one history, so two clients cannot accept checkpoints from different histories. A manifest with 1 of 2 or 2 of 4 does not parse. Every manifest needs a `[log]` section. To run without witnesses, set `allow_split_views = true` with `witnesses = []` and `witness_quorum = 0`; the client then prints a loud warning on every `join` and `check`.

The gateway sends every new checkpoint to the witnesses in `WITNESS_URLS` before it serves it, keeps the cosignatures that a manifest witness key verifies, and serves them with the checkpoint. It sends the current checkpoint again every `WITNESS_REFRESH_SECS` (default a quarter of `checkpoint_max_age`, at most 600), so the cosignatures stay fresh while the log does not grow.

A witness detects a forking gateway only if someone other than the gateway operator runs it, for example the contractor or an auditor. To run one:

```sh
WITNESS_NAME=witness.example.org/w1 WITNESS_KEY_FILE=witness.key open-pact-witness keygen   # prints the verifier key for the manifest
WITNESS_NAME=witness.example.org/w1 WITNESS_KEY_FILE=witness.key WITNESS_STATE=state.json \
  WITNESS_LOG_KEYS="$(curl -s https://pact.example.com/v1/log/key)" open-pact-witness
```

Confirm the log key out of band, as with the invitation. `WITNESS_LOG_KEY_URL` pins the first key a URL serves; it exists for `compose.yaml` only. Losing the state file lets the gateway roll the log back, so back it up. The `compose.yaml` witness uses a key from a public seed (`deploy/compose/demo-witness.key`), and `examples/manifest.toml` lists it: anyone can forge its cosignatures.

**Client.** The client pins the log key from the invitation at `join`. On every `join` and `check` it fetches the checkpoint, verifies the signature and verifies a consistency proof from the checkpoint it stored. On first contact it downloads all entries and recomputes the root instead. It then fetches the entry for the manifest hash the owner signed and the entry with this device's commitment `sha256(salt || pseudonym)`, and verifies an inclusion proof for each. `enrolment.json` keeps their indexes; the gateway returns them at enrolment. Before that it requires `witness_quorum` valid cosignatures from the manifest's witnesses, each no older than `checkpoint_max_age`, so a checkpoint the witnesses did not see, or an old one replayed, raises the alarm. With `allow_split_views = true` it warns that split views go undetected. If a check fails or an entry is missing, the client prints an alarm and exits with status 2. `log prove [index]` verifies the inclusion proof of one entry. Without an index, it proves the entry of this device's enrolment. Each claim carries `log_checkpoint`, the size and root that the client verified last. The gateway denies a claim whose checkpoint is not a state of its log.

The gateway reads each log row from the database once and signs the checkpoint once per tree size. The checkpoint, the cosignatures and the proofs also verify with the Go packages `golang.org/x/mod/sumdb/note`, `github.com/transparency-dev/formats/note` and `github.com/transparency-dev/merkle/proof`. `log_entries` rejects `UPDATE`, `DELETE` and `TRUNCATE` with a trigger.

**Mandatory disclosures.** `disclosed_metadata` must list every field a claim always carries: `manifest_hash`, `device_pseudonym`, `device_key`, `nonce`, `time`, `client_version`, `os`, `trust_level` and `vpn_certificate_request`. `virtualized` and `log_checkpoint` are optional: the client sends them only if the manifest lists them, and the gateway denies and does not store a claim that carries an unlisted one. Other names do not parse. The example manifest replaces `client_hash` with `client_version` and adds `device_key`, `nonce` and `vpn_certificate_request`, so its hash changes and owners sign it again with `join`.

**Upgrade from v0.1.0.** Migration 0004 drops the hash-chain columns. The entries keep their order and become the leaves, and the log key stays. A client that holds a v0.1.0 `log-head.json` tells the owner to run `join` again, exits with status 1 and raises no alarm. `join` removes the old file and pins the checkpoint. `GET /v1/log` answers 410. The example manifest now lists `log_checkpoint` in `disclosed_metadata`, so its hash changes and owners sign it again at that `join`.

## Keys

On first start the gateway generates its company manifest-signing key, its log-signing key and a P-256 CA ("open-pact demo CA"), and stores them in the `gateway_secrets` table. This is for the demo only. In production these keys stay in an HSM or a cloud key vault and never reach the database.

Each row of `gateway_secrets` is encrypted with AES-256-GCM under the key-encryption key in `GATEWAY_KEK`, with the row name as associated data. `GATEWAY_KEK` is 32 random bytes in base64. The gateway refuses to start without it. Only `DEV_INSECURE_KEK=1`, which `compose.yaml` sets, replaces it with a public development key. A gateway upgraded from a version without the KEK encrypts the plaintext rows in place on its first start and logs each one. A wrong key stops the gateway; it never generates new keys over rows it cannot read. Keep a copy of the key outside the database and its backups: without it, the keys and claims cannot be read. Rotating the KEK is not supported yet.

**Claims at rest.** The gateway seals each stored claim, with its device pseudonym and JWS, under the key of its calendar month (UTC). Each month key is sealed under the KEK in `claim_keys`. Only `received_at` and the allow or deny flag stay readable, for the summary page. Every hour the gateway deletes claims older than the manifest's `claim_retention` (calendar months for `mo`). It then deletes the key of every month that ended before that cutoff, so copies of those claims in backups can no longer be decrypted. Each purge that deletes something appends a `retention_purge` log entry with the counts. On the first start after the upgrade, the gateway seals claims that earlier versions stored in plaintext. Their old plaintext can remain in PostgreSQL dead tuples, the WAL and earlier backups until those are vacuumed or expire.

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

`scripts/check-helm.sh` checks that the chart refuses to render without `gateway.kekSecret.name` and without a database password or secret, and that `manifest` renders its ConfigMap, mount and checksum. The gateway tests that need PostgreSQL are `#[ignore]`d in a plain `cargo test`. Run them against a throwaway database:

```sh
docker run -d --rm --name pact-testdb -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:17
TEST_DATABASE_URL=postgres://postgres:test@localhost:55432/postgres cargo test --workspace -- --include-ignored
```

## Known gaps

- The invitation is a bearer secret, and its fingerprints are only as authentic as the channel that carried it. A relay that forwards the public endpoints passes the fingerprint check and can use a code it intercepts. TLS and IT approval of the device code are the defences; confirm the company key fingerprint over a second channel.
- Behind an ingress the gateway sees the ingress address, so the enrolment failure limit applies to all enrolments together and the nonce limit to all devices together. Size `NONCE_MAX_PER_WINDOW` for the whole fleet in that case. The gateway does not read `X-Forwarded-For`. The limits are in memory and per replica.
- Approval belongs to one manifest hash. When the gateway enforces a new manifest, the owner needs a new invitation and IT approves again.
- The witness has no monitoring endpoint yet, so a client cannot fetch cosignatures from it directly; it gets them through the gateway.
- The summary page counts stored claims only. Replays, bad signatures, unenrolled devices and oversharing claims are refused without being stored.
- The Secure Enclave device key proves that claims come from this Mac, but it is not bound to the client's code signature as PAPER.md section 5 describes. The client keeps the wrapped key in `device-se.key`, not in the keychain, so it needs no keychain entitlement, and any program on the same Mac that can read the file can sign with it. A Developer ID signed client with a keychain access group closes this. The Secure Enclave key protects against key theft: its private key cannot be copied off the Mac. It does not prove anything to the gateway, because the trust level in a claim is what the client asserts. Without attestation the gateway records that assertion as `asserted_trust_level`, counts every claim as `verified_trust_level` L0, and denies every claim when `min_trust_level` is L1 or L2, with the reason that the level needs attestation, which is not available.
- The VPN certificate key and the owner key are still software keys.
- The CN is the pseudonym's hex digest without the `pseudonym:` prefix, because X.509 limits a CN to 64 characters.
