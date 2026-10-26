#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
platform=${PLATFORM:-linux/arm64}
if [[ -z ${PLATFORM:-} && $(uname -m) != arm64 && $(uname -m) != aarch64 ]]; then
    platform=linux/amd64
fi
for distro in ${DISTROS:-ubuntu fedora}; do
    image="open-pact-linux-v31-$distro"
    docker build --platform "$platform" --target "$distro" -f tests/linux-docker/Dockerfile -t "$image" .
    docker run --rm --platform "$platform" "$image"
    if [[ "$distro" == ubuntu && ${SYSTEMD:-1} == 1 ]]; then
        python3 tests/linux-docker/systemd.py "$image" "$platform"
        python3 tests/linux-docker/failed-start.py "$image" "$platform"
    fi
done
