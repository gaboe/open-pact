FROM rust:1-slim-bookworm AS tools
RUN rustup component add rustfmt clippy

FROM tools AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock PAPER.md ./
COPY crates crates
COPY examples examples
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && \
    cargo test --workspace && cargo test -p open-pact-client --no-run 2>/tmp/client-test.log && \
    binary=$(sed -n 's/.*Executable unittests src\/main.rs (\(.*\)).*/\1/p' /tmp/client-test.log) && \
    test -n "$binary" && cp "$binary" /open-pact-checks && \
    cargo build -p open-pact-client && cp target/debug/open-pact-client /open-pact-client

FROM ubuntu:24.04 AS ubuntu
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus dbus-user-session util-linux cryptsetup-bin \
    unattended-upgrades clamav clamav-daemon procps sudo python3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /open-pact-checks /usr/local/bin/open-pact-checks
COPY --from=build /open-pact-client /usr/local/bin/open-pact-client
COPY tests/linux-docker/scenarios.py /scenarios.py
CMD ["python3", "/scenarios.py"]

FROM fedora:43 AS fedora
RUN dnf install -y systemd dbus-daemon util-linux cryptsetup dnf5-plugin-automatic clamav clamd procps-ng sudo python3 && dnf clean all
COPY --from=build /open-pact-checks /usr/local/bin/open-pact-checks
COPY --from=build /open-pact-client /usr/local/bin/open-pact-client
COPY tests/linux-docker/scenarios.py /scenarios.py
CMD ["python3", "/scenarios.py"]
