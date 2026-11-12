# Client dependencies

Every direct dependency of `open-pact-client` and `open-pact-core` is listed here with the reason it stays. The server crates (`open-pact-gateway`, `open-pact-witness`) are not in the client graph: `cargo tree -p open-pact-client` shows no `sqlx`, `axum` or other server crate.

Rule for a change: a new direct dependency needs a line in this file. A security-critical crate (`ring`, `rustls`, `rcgen`, `x509-parser`, `p256`, `ed25519-dalek`, `sha2`) is never replaced with hand-written code.

## open-pact-core

| Crate | Why |
| --- | --- |
| `serde`, `serde_json` | Manifest, claim and report data types. |
| `serde_jcs` | RFC 8785 canonical JSON, the bytes that signatures cover. |
| `toml` | Parses the signed manifest body. |
| `p256` | ECDSA P-256 signatures on manifests and claims. |
| `ed25519-dalek` | Witness checkpoint signatures (tree head notes). |
| `sha2` | SHA-256 and SHA-512 digests for hashes and log entries. |
| `base64`, `hex` | Wire encodings of keys, signatures and hashes. |
| `chrono` | Validity windows and timestamps. Features: `serde`, `clock`, `std` only. |
| `thiserror` | Error enums for manifest, invitation and narrowing checks. |

## open-pact-client

| Crate | Why |
| --- | --- |
| `open-pact-core` | Manifest verification, evaluation and claim signing. |
| `serde`, `serde_json`, `toml` | Local config, reports, local log and the example manifest. |
| `tokio` | Runtime, `process` (run OS probes), `signal` (Ctrl-C), `time`, `net` (loopback probe), `sync` (oneshot). `sync` is now listed explicitly instead of coming in through `reqwest`. |
| `reqwest` | HTTPS client for the gateway. `rustls-tls` only, no default features, redirects off. |
| `clap` | Command line. Features: `derive` plus defaults; colour and "did you mean" suggestions stay on for owners. |
| `chrono` | Timestamps in reports and local log. Features: `clock` only. |
| `anyhow` | Error context in the binary. |
| `uuid` | Random report ids and temporary file names (`v4`). |
| `base64`, `hex`, `sha2` | Encode and hash report payloads, log entries and Linux package index files. |
| `rcgen` | Builds the device certificate signing request. Features: `crypto`, `ring`, `pem`. The unused `x509-parser` feature is off. |
| `x509-parser` | Reads and verifies the certificate the gateway returns (`verify` feature). |
| `libc` (unix) | `geteuid`, `setpriority`, `confstr` for the trusted `PATH`. |
| `core-foundation`, `security-framework`, `security-framework-sys` (macOS) | Keychain device key and certificate access. |
| `windows-sys` (Windows) | CNG key storage (device key), security descriptors and process token access. Only the three used feature groups. |

Dev-only (not in the release graph): `p256`, `ed25519-dalek`, `tempfile`.

## Removed

- `url` from `open-pact-core`: unused in the crate. `reqwest` still pulls `url` in transitively.
- `rcgen` feature `x509-parser`: no call site used it.

## Duplicate versions

`cargo tree -d -e normal` shows these. None can move with a semver-compatible bump.

| Crate | Versions | Cause |
| --- | --- | --- |
| `base64` | 0.22, 0.23 | `reqwest` uses 0.22. Downgrading ours would trade a major version for one crate. |
| `sha2`, `digest`, `block-buffer`, `cpufeatures`, `crypto-common`, `signature` | 0.10 and 0.11 lines | `ed25519-dalek` 2.2 is on the RustCrypto 0.10 line, `p256` 0.14 on the 0.11 line. |
| `getrandom` | 0.2, 0.4 | `ring` on 0.2, `uuid` and the RustCrypto 0.11 line on 0.4. |
| `syn` | 2, 3 | Proc-macro crates only. Build time, not binary size. |

## Normal dependency count per release target

Command: `cargo tree -p open-pact-client -e normal --target <t> --prefix none | sort -u | wc -l`

| Target | Before | After |
| --- | --- | --- |
| x86_64-apple-darwin | 251 | 250 |
| aarch64-apple-darwin | 250 | 249 |
| x86_64-unknown-linux-musl | 245 | 244 |
| x86_64-pc-windows-msvc | 247 | 246 |
