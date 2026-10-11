FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --release -p open-pact-gateway

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 gateway
COPY --from=build /src/target/release/open-pact-gateway /usr/local/bin/open-pact-gateway
USER 10001
EXPOSE 8080
ENTRYPOINT ["open-pact-gateway"]
