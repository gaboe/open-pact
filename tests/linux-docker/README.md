# Linux v3.1 container checks

Run `tests/linux-docker/run.sh` from the repository checkout. Docker builds and tests the workspace on Linux. It then runs Ubuntu and Fedora scenarios. `DISTROS=ubuntu` selects Ubuntu only. `PLATFORM=linux/amd64` or `PLATFORM=linux/arm64` selects the container architecture. Cross-architecture execution needs Docker emulation.

The build runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`. It also builds `open-pact-client` and copies the client's ignored check printer into the runtime images. The printer calls the same registry as `check` without a manifest, join, gateway, or VPN.

The scenarios read real APT and DNF configuration, numeric user groups, and real LUKS2 file metadata. A sparse file is enough for `luksFormat` and `luksDump`. No loop device or privileged container is required. Block topology is injected through an `lsblk` fixture because a container cannot replace its host root filesystem. Hardware token paths use fixtures because the container has no enrolled TPM2 or FIDO2 device.

A `systemctl` fixture supplies timer state after the initial no-manager case. The tests do not claim a working systemd timer from this fixture. The named `clamonacc` process is a copied `sleep` executable. It proves process lookup, not fanotify protection. Journal fixtures prove marker parsing, warning handling, and dispatch. They do not prove a real on-access detection. Browser fixtures supply standard package and profile paths. They do not launch a browser.

All runtime containers use `--rm`. Build cache and test images remain available for another run. No existing Docker container is changed.

The Ubuntu run also attempts a privileged systemd container with a private cgroup namespace. When the Docker host supports it, the test installs and removes the client's real user timer, runs its service with a closed local VPN probe, and injects two fictional detections through the native journal API. The detection marker must advance. A host that cannot start the systemd manager prints the observed reason as `SKIP`. Set `SYSTEMD=0` to omit this optional scenario.
