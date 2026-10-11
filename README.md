# open-pact

Verifiable security checks on personally owned devices, without blanket monitoring. The client sends a small signed claim to a company gateway when the owner connects. Read [PAPER.md](PAPER.md) for the design.

Status: proof of concept, software device key, not for production. Claims are not signed yet and the manifest is a placeholder.

## Layout

- `crates/open-pact-core` shared types
- `crates/open-pact-client` CLI, runs one check (`disk_encryption`)
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

The smoke script checks `/healthz`, runs the client, then replays a used nonce and expects a denial.
