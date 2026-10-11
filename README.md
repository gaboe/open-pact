# open-pact

Verifiable security checks on personally owned devices, without blanket monitoring. The client sends a small signed claim to a company gateway when the owner connects. Read [PAPER.md](PAPER.md) for the design.

Status: proof of concept, not for production. Claims are signed as ES256 JWS with a development software key (`~/.config/open-pact/device-dev.pem`, trust level L0). The gateway enforces [examples/manifest.toml](examples/manifest.toml), or the file in `MANIFEST_PATH`.

## Layout

- `crates/open-pact-core` manifest, signatures, narrowing, claims (RFC 8785 + JWS) and evaluation
- `crates/open-pact-client` CLI, runs the manifest's built-in checks (macOS: disk encryption, firewall, screen lock, OS support)
- `crates/open-pact-gateway` HTTP gateway backed by PostgreSQL
- `deploy/helm/open-pact` Helm chart (values use placeholders)

## Run

```sh
docker compose up -d --build
scripts/smoke.sh http://localhost:8080
open http://localhost:8080
docker compose down -v
```

Run the client by hand:

```sh
cargo run -p open-pact-client -- --gateway http://localhost:8080 check
```

The smoke script checks `/healthz` and runs the client. Then it signs claims with chosen results and expects: a compliant claim accepted, its replay denied, a failed check denied with its reason, an undisclosed result denied, a wrong manifest hash denied, and a tampered signature denied.
