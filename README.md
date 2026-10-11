# open-pact

Verifiable security checks on personally owned devices, without blanket monitoring. The owner signs the company's manifest once. Each time the device connects, the client sends one small signed claim to the company gateway, and a compliant device gets a short-lived VPN client certificate. Read [PAPER.md](PAPER.md) for the design.

Status: proof of concept, not for production. All keys are development software keys (trust level L0). The gateway enforces [examples/manifest.toml](examples/manifest.toml), or the file in `MANIFEST_PATH`.

## Layout

- `crates/open-pact-core` manifest, signatures, narrowing, claims (RFC 8785 + JWS), evaluation, the Merkle transparency log and signed checkpoints
- `crates/open-pact-client` CLI: `join`, `check`, `log head`, `log prove`, `log show`, `stop`
- `crates/open-pact-gateway` HTTP gateway, small CA and transparency log, backed by PostgreSQL
- `deploy/helm/open-pact` Helm chart (values use placeholders)

## Run

```sh
docker compose up -d --build
scripts/smoke.sh http://localhost:8080
scripts/demo.sh http://localhost:8080      # PAUSE=1 waits for Enter between steps
open http://localhost:8080
docker compose down -v
```

Run the client by hand:

```sh
cargo run -p open-pact-client -- join --gateway http://localhost:8080
cargo run -p open-pact-client -- check
cargo run -p open-pact-client -- log head
```

The client keeps its files in `~/.config/open-pact/`, or in the directory given with `--home`:

| File | Content |
| --- | --- |
| `owner-dev.pem` | owner key; signs the manifest hash |
| `device-dev.pem` | device key; signs claims, its hash is the pseudonym |
| `vpn-key.pem` | VPN certificate key; only its certificate request leaves the device |
| `manifest.toml`, `enrolment.json` | the signed manifest, gateway URL and the salt that opens the enrolment commitment |
| `vpn-cert.pem`, `ca.pem` | the last VPN client certificate and the gateway CA |
| `log-key.txt` | the gateway's log key, pinned at the first `join` |
| `log-checkpoint.txt` | the last verified, gateway-signed log checkpoint |
| `claims.jsonl` | every claim sent and every response, byte for byte |

Nothing runs in the background. To uninstall, delete the binary and the directory.

## Gateway API

| Request | Response |
| --- | --- |
| `GET /v1/manifest` | `{toml, company}`: the enforced manifest and the company's signature over its hash |
| `POST /v1/enroll {signed_manifest, device_key}` | `{status: "enrolled", device, salt, log_index, manifest_log_index, log_checkpoint}`. The gateway checks both signatures, that `company.key` is its own key and that the hash is the enforced manifest. Enrolling the same device key again changes nothing; a different owner key gets 409. |
| `POST /v1/nonce` | `{nonce}`, single use, valid 5 minutes |
| `POST /v1/claim {jws}` | `{status: "accepted", warnings, certificate_pem, ca_pem, log_checkpoint}`, or 403 `{status: "denied", reasons}` |
| `GET /v1/log/key` | the log verifier key, `<origin>+<key id>+<base64 key>` |
| `GET /v1/log/checkpoint` | the signed checkpoint note, with stored witness cosignatures |
| `GET /v1/log/entries?from=&to=` | `{entries}`, `from` inclusive, `to` exclusive, at most 256 entries; without `to`, one page |
| `GET /v1/log/proof/inclusion?index=&size=` | `{index, size, proof}`, hashes in lowercase hex |
| `GET /v1/log/proof/consistency?from=&to=` | `{from, to, proof}` |
| `POST /v1/log/witness` | body: a checkpoint note with witness cosignature lines; stores the valid ones |
| `GET /v1/log` | 410: the v0.1.0 hash-chain endpoint is gone |
| `GET /` | aggregate summary page, no per-device detail |

A claim is accepted only if the device is enrolled for the enforced manifest, the nonce is unused, the claim time is within `claim_max_age` and not more than 5 minutes ahead, and the results meet the manifest. If the claim carries `csr_pem`, the gateway issues a client certificate for the request's public key: CN = the pseudonym's 64 hex digits, extended key usage `clientAuth`, valid 24 hours or `claim_max_age` if shorter.

## Transparency log

The log is a Merkle tree with RFC 9162 (Certificate Transparency 2.0) hashing. A leaf is the RFC 8785 canonical JSON of `{kind, data}`. The leaf hash is `sha256(0x00 || leaf)` and an inner node is `sha256(0x01 || left || right)`. The index is not part of the leaf, because the position in the tree fixes it.

- `manifest_published` `{manifest}` is appended once per new manifest hash at gateway start.
- `device_enrolled` `{commitment}` holds `sha256(salt || pseudonym)`, not the pseudonym. The owner keeps the 256-bit salt and can prove the entry is theirs.

**Checkpoints.** The gateway signs a checkpoint, the C2SP [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) body `<origin>\n<size>\n<base64 root>\n`, in C2SP [signed-note](https://c2sp.org/signed-note) format. The key name is the origin, set by `LOG_ORIGIN` (default `pact.example.com/log`). The log key is ECDSA P-256, signed-note type `0x02` as transparency-dev/formats implements it: a DER signature over SHA-256, and a key ID from the DER public key. Most C2SP tools use Ed25519. P-256 keeps the log key in the same hardware as the other keys.

**Witnesses.** A witness checks that a new checkpoint extends the last one it saw, then cosigns it with Ed25519 `cosignature/v1` (C2SP [tlog-cosignature](https://c2sp.org/tlog-cosignature)). `POST /v1/log/witness` takes the checkpoint note with the witness's cosignature lines appended, as a C2SP [tlog-witness](https://c2sp.org/tlog-witness) response carries them. The gateway keeps cosignatures from the keys in `WITNESS_KEYS` (comma-separated verifier keys) and serves them with the checkpoint of the same size and root. The `dev_witness` example is a demo witness with a fixed, public key, and `compose.yaml` trusts it:

```sh
curl -s localhost:8080/v1/log/checkpoint | cargo run -q -p open-pact-core --example dev_witness -- cosign \
  | curl -s --data-binary @- localhost:8080/v1/log/witness
```

**Client.** The client pins the log key at the first `join`. On every `join` and `check` it fetches the checkpoint, verifies the signature and verifies a consistency proof from the checkpoint it stored. On first contact it downloads all entries and recomputes the root instead. It then fetches the entry for the manifest hash the owner signed and the entry with this device's commitment `sha256(salt || pseudonym)`, and verifies an inclusion proof for each. `enrolment.json` keeps their indexes; the gateway returns them at enrolment. If a check fails or an entry is missing, the client prints an alarm and exits with status 2. `log prove [index]` verifies the inclusion proof of one entry. Without an index, it proves the entry of this device's enrolment. Each claim carries `log_checkpoint`, the size and root that the client verified last.

The gateway reads each log row from the database once and signs the checkpoint once per tree size. The checkpoint, the cosignatures and the proofs also verify with the Go packages `golang.org/x/mod/sumdb/note`, `github.com/transparency-dev/formats/note` and `github.com/transparency-dev/merkle/proof`. `log_entries` rejects `UPDATE`, `DELETE` and `TRUNCATE` with a trigger.

**Upgrade from v0.1.0.** Migration 0004 drops the hash-chain columns. The entries keep their order and become the leaves, and the log key stays. A client that holds a v0.1.0 `log-head.json` tells the owner to run `join` again, exits with status 1 and raises no alarm. `join` removes the old file and pins the checkpoint. `GET /v1/log` answers 410. The example manifest now lists `log_checkpoint` in `disclosed_metadata`, so its hash changes and owners sign it again at that `join`.

## Keys

On first start the gateway generates its company manifest-signing key, its log-signing key and a P-256 CA ("open-pact demo CA"), and stores them in the `gateway_secrets` table. This is for the demo only. In production these keys stay in an HSM or a cloud key vault and never reach the database.

## Tests

`scripts/smoke.sh` runs the full flow against a running gateway: `join --yes`, a repeated `join`, `check`, `openssl verify` of the certificate, a replay of the client's own claim, a claim from an unenrolled device, chosen-result claims (failed check, undisclosed result, wrong manifest, tampered signature), `log show`, `log prove`, a witness cosignature, and the log alarm for a different root (split view), for a rollback, and the upgrade message for a v0.1.0 log head. On a device that fails a 0-day-grace check, such as disk encryption off, `check` is denied and the smoke script stops there.

## Known gaps

- Anyone who can reach the gateway and holds the company-signed manifest can enrol a device. PAPER.md section 4.6 adds a one-time invitation code and IT approval; neither exists yet.
- `join` prints the company key fingerprint but compares it with nothing, and the client trusts the log key it sees first. A fake gateway at join time wins both. The invitation fingerprint from PAPER.md section 4.6 closes this.
- The client prints witness cosignatures with the checkpoint but does not verify them, because it has no list of witness keys yet. The demo witness signs any checkpoint it is given; a real witness first checks a consistency proof from the last checkpoint it cosigned.
- The summary page counts stored claims only. Replays, bad signatures, unenrolled devices and oversharing claims are refused without being stored.
- The CN is the pseudonym's hex digest without the `pseudonym:` prefix, because X.509 limits a CN to 64 characters.
