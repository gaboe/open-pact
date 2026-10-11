FROM --platform=linux/amd64 rust:1.99.0-alpine@sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627 AS build
WORKDIR /src
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates crates
ENV CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_STRIP=symbols \
    RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/usr/local/rustup=/rustup -C link-arg=-Wl,--build-id=none"
RUN cargo build --locked --release --target x86_64-unknown-linux-musl -p open-pact-gateway
# A separate build, so the witness's dependencies cannot change the gateway binary.
RUN cargo build --locked --release --target x86_64-unknown-linux-musl -p open-pact-witness \
    && mkdir -p /witness-state

# The witness runs as its own service with its own key: docker build --target witness .
FROM --platform=linux/amd64 scratch AS witness
COPY --from=build --chmod=0555 /src/target/x86_64-unknown-linux-musl/release/open-pact-witness /usr/local/bin/open-pact-witness
COPY --from=build --chown=10001:10001 /witness-state /var/lib/open-pact-witness
ENV PATH=/usr/local/bin \
    WITNESS_STATE=/var/lib/open-pact-witness/state.json
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/open-pact-witness"]

FROM --platform=linux/amd64 scratch
COPY --from=build --chmod=0555 /src/target/x86_64-unknown-linux-musl/release/open-pact-gateway /usr/local/bin/open-pact-gateway
COPY examples/manifest.toml /etc/open-pact/manifest.toml
ENV PATH=/usr/local/bin \
    MANIFEST_PATH=/etc/open-pact/manifest.toml
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/open-pact-gateway"]
