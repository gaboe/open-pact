#!/usr/bin/env python3
"""Check that a release tag names the version of both Cargo workspaces.

    check-release-version.py v1.2.3 [repository-root]
    check-release-version.py --msi 1.2.3-rc.1 <upgrade-code>

The tag, the root [workspace.package] version and the desktop/Cargo.toml
[workspace.package] version must be the same. Prints the version on success.

--msi prints the Windows Installer ProductVersion and ProductCode of a version,
separated by a space. ProductVersion orders the releases. ProductCode comes from
the version, so a rebuild of the same version keeps it.
"""

from __future__ import annotations

import re
import sys
import tomllib
import uuid
from pathlib import Path

SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.([1-9][0-9]*))?")
MAX_MAJOR_MINOR = 255
MAX_PATCH = 654
MAX_RC = 98
STABLE_BUILD = 99


def msi_version(version: str) -> str:
    """Map a release version to a ProductVersion that Windows Installer orders.

    Windows Installer compares only major.minor.build. The patch and the
    prerelease share the build field: rc.N is patch * 100 + N and a stable
    release is patch * 100 + 99, so every rc.N sorts below its stable release.
    """
    match = SEMVER.fullmatch(version)
    if match is None:
        raise SystemExit(f"The version {version} is not X.Y.Z or X.Y.Z-rc.N.")
    major, minor, patch = (int(match.group(number)) for number in (1, 2, 3))
    if major > MAX_MAJOR_MINOR or minor > MAX_MAJOR_MINOR:
        raise SystemExit(f"The version {version} has a major or minor number above {MAX_MAJOR_MINOR}.")
    if patch > MAX_PATCH:
        raise SystemExit(f"The version {version} has a patch number above {MAX_PATCH}.")
    build = STABLE_BUILD
    if match.group(4) is not None:
        build = int(match.group(4))
        if build > MAX_RC:
            raise SystemExit(f"The version {version} has an rc number above {MAX_RC}.")
    return f"{major}.{minor}.{patch * 100 + build}"


def msi_product_code(upgrade_code: str, version: str) -> str:
    """Name the ProductCode after the version, so a rebuild of that version keeps it."""
    return "{" + str(uuid.uuid5(uuid.UUID(upgrade_code), version)).upper() + "}"


def workspace_version(manifest: Path) -> str:
    with manifest.open("rb") as handle:
        data = tomllib.load(handle)
    try:
        return data["workspace"]["package"]["version"]
    except KeyError:
        raise SystemExit(f"{manifest}: no [workspace.package] version") from None


def check(tag: str, root: Path) -> str:
    if not tag.startswith("v"):
        raise SystemExit(f"The tag {tag} does not start with v.")
    expected = tag[1:]
    msi_version(expected)
    for manifest in (root / "Cargo.toml", root / "desktop" / "Cargo.toml"):
        version = workspace_version(manifest)
        if version != expected:
            raise SystemExit(
                f"The tag {tag} does not match the version {version} in {manifest.relative_to(root)}."
            )
    return expected


def main() -> None:
    args = sys.argv[1:]
    if len(args) == 3 and args[0] == "--msi":
        version = args[1]
        print(msi_version(version), msi_product_code(args[2], version))
        return
    if len(args) not in (1, 2):
        raise SystemExit(f"usage: {sys.argv[0]} <tag> [repository-root] | --msi <version> <upgrade-code>")
    root = Path(args[1]) if len(args) == 2 else Path(__file__).resolve().parents[2]
    print(check(args[0], root))


if __name__ == "__main__":
    main()
