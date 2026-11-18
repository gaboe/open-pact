#!/usr/bin/env python3
"""Check that a release tag names the version of both Cargo workspaces.

    check-release-version.py v1.2.3 [repository-root]

The tag, the root [workspace.package] version and the desktop/Cargo.toml
[workspace.package] version must be the same. Prints the version on success.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


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
    for manifest in (root / "Cargo.toml", root / "desktop" / "Cargo.toml"):
        version = workspace_version(manifest)
        if version != expected:
            raise SystemExit(
                f"The tag {tag} does not match the version {version} in {manifest.relative_to(root)}."
            )
    return expected


def main() -> None:
    if len(sys.argv) not in (2, 3):
        raise SystemExit(f"usage: {sys.argv[0]} <tag> [repository-root]")
    root = Path(sys.argv[2]) if len(sys.argv) == 3 else Path(__file__).resolve().parents[2]
    print(check(sys.argv[1], root))


if __name__ == "__main__":
    main()
