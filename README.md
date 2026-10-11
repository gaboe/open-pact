# open-pact

Verifiable security checks on personally owned devices, without blanket monitoring. The owner signs the company's manifest once. Each time the device connects, the client sends one small signed claim to the company gateway, and a compliant device gets a short-lived VPN client certificate. Read [PAPER.md](PAPER.md) for the design.

Status: proof of concept, not for production. All keys are development software keys (trust level L0). The gateway enforces [examples/manifest.toml](examples/manifest.toml), or the file in `MANIFEST_PATH`.

## Layout

- `crates/open-pact-core` manifest, signatures, narrowing, claims (RFC 8785 + JWS), evaluation and the transparency log chain
- `crates/open-pact-client` CLI: `join`, `check`, `log head`, `log show`, `stop`
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
| `log-head.json` | the last verified, gateway-signed transparency log head |
| `claims.jsonl` | every claim sent and every response, byte for byte |

Nothing runs in the background. To uninstall, delete the binary and the directory.

## Gateway API

| Request | Response |
| --- | --- |
| `GET /v1/manifest` | `{toml, company}`: the enforced manifest and the company's signature over its hash |
| `POST /v1/enroll {signed_manifest, device_key}` | `{status: "enrolled", device, salt, log_head}`. The gateway checks both signatures, that `company.key` is its own key and that the hash is the enforced manifest. Enrolling the same device key again changes nothing; a different owner key gets 409. |
| `POST /v1/nonce` | `{nonce}`, single use, valid 5 minutes |
| `POST /v1/claim {jws}` | `{status: "accepted", warnings, certificate_pem, ca_pem, log_head}`, or 403 `{status: "denied", reasons}` |
| `GET /v1/log?from=N` | `{entries, head}` |
| `GET /` | aggregate summary page, no per-device detail |

A claim is accepted only if the device is enrolled for the enforced manifest, the nonce is unused, the claim time is within `claim_max_age` and not more than 5 minutes ahead, and the results meet the manifest. If the claim carries `csr_pem`, the gateway issues a client certificate for the request's public key: CN = the pseudonym's 64 hex digits, extended key usage `clientAuth`, valid 24 hours or `claim_max_age` if shorter.

## Transparency log

Entry `n` is `{index, kind, data, prev_hash, hash}` with `hash = sha256(prev_hash || JCS({index, kind, data}))`. Entry 0 has 32 zero bytes as `prev_hash`. Hashes are lowercase hex in JSON and raw bytes in the hash input. The head is `{index, hash, signature, key}`, where `signature` is ES256 by the gateway's log key over the string `"{index}:{hash}"`.

- `manifest_published` `{manifest}` is appended once per new manifest hash at gateway start.
- `device_enrolled` `{commitment}` holds `sha256(salt || pseudonym)`, not the pseudonym. The owner keeps the salt and can prove the entry is theirs.

The client pins the log key at `join`. On every `check` it downloads new entries, verifies the chain against its stored head and stores the new head. If the history does not match, it prints an alarm and exits with status 2. `log_entries` rejects `UPDATE`, `DELETE` and `TRUNCATE` with a trigger.

## Keys

On first start the gateway generates its company manifest-signing key, its log-signing key and a P-256 CA ("open-pact demo CA"), and stores them in the `gateway_secrets` table. This is for the demo only. In production these keys stay in an HSM or a cloud key vault and never reach the database.

## Tests

`scripts/smoke.sh` runs the full flow against a running gateway: `join --yes`, a repeated `join`, `check`, `openssl verify` of the certificate, a replay of the client's own claim, a claim from an unenrolled device, chosen-result claims (failed check, undisclosed result, wrong manifest, tampered signature), `log show` and the log alarm. On a device that fails a 0-day-grace check, such as disk encryption off, `check` is denied and the smoke script stops there.

## Known gaps

- Anyone who can reach the gateway and holds the company-signed manifest can enrol a device. PAPER.md section 4.6 adds a one-time invitation code and IT approval; neither exists yet.
- `join` prints the company key fingerprint but compares it with nothing, and the client trusts the log key it sees first. A fake gateway at join time wins both. The invitation fingerprint from PAPER.md section 4.6 closes this.
- The summary page counts stored claims only. Replays, bad signatures, unenrolled devices and oversharing claims are refused without being stored.
- The CN is the pseudonym's hex digest without the `pseudonym:` prefix, because X.509 limits a CN to 64 characters.
