FROM --platform=linux/amd64 rust:1.99.0-alpine@sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627 AS build
WORKDIR /src
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates crates
ENV CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_STRIP=symbols \
    RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/usr/local/rustup=/rustup -C link-arg=-Wl,--build-id=none"
RUN cargo build --locked --release --target x86_64-unknown-linux-musl -p open-pact-gateway

FROM --platform=linux/amd64 scratch
COPY --from=build --chmod=0555 /src/target/x86_64-unknown-linux-musl/release/open-pact-gateway /open-pact-gateway
COPY examples/manifest.toml /etc/open-pact/manifest.toml
ENV MANIFEST_PATH=/etc/open-pact/manifest.toml
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/open-pact-gateway"]
