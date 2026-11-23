#!/usr/bin/env python3
"""Generate Homebrew and Scoop metadata from release checksums."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path


RELEASE_FILES = {
    "mac_arm64": "open-pact-client-aarch64-apple-darwin",
    "mac_x86_64": "open-pact-client-x86_64-apple-darwin",
    "windows_x86_64": "open-pact-client-x86_64-pc-windows-msvc.exe",
}

MSI_FILE = "open-pact-client-x86_64-pc-windows-msvc.msi"
WINGET_ID = "gaboe.open-pact"
WINGET_TEST_ID = "gaboe.open-pact.test"
ROOT = Path(__file__).resolve().parents[2]
RELEASE_URL = "https://github.com/gaboe/open-pact/releases/download"


def _load_version_gate():
    spec = importlib.util.spec_from_file_location(
        "check_release_version", Path(__file__).resolve().parent / "check-release-version.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


version_gate = _load_version_gate()


def desktop_zip(version: str) -> str:
    return f"open-pact-desktop-{version}-windows-x64.zip"


def read_checksums(path: Path, required_files: set[str] | None = None) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if not match:
            raise ValueError(f"{path}:{number}: expected '<sha256><two spaces><filename>'")
        digest, filename = match.groups()
        if filename in checksums:
            raise ValueError(f"{path}:{number}: duplicate checksum for {filename}")
        checksums[filename] = digest
    if required_files is None:
        required_files = set(RELEASE_FILES.values())
    missing = sorted(required_files - checksums.keys())
    if missing:
        raise ValueError(f"{path}: missing checksums for {', '.join(missing)}")
    return checksums


def formula(version: str, hashes: dict[str, str], placeholder: bool) -> str:
    if placeholder:
        note = "# PLACEHOLDER HASHES: replace these values from the published SHA256SUMS.\n"
        arm_hash = intel_hash = "PLACEHOLDER"
    else:
        note = "# Generated from the published SHA256SUMS.\n"
        arm_hash = hashes[RELEASE_FILES["mac_arm64"]]
        intel_hash = hashes[RELEASE_FILES["mac_x86_64"]]
    return f'''# typed: strict
# frozen_string_literal: true

# Open Pact client formula.
class OpenPact < Formula
  desc "Verifiable security checks for personally owned devices"
  homepage "https://github.com/gaboe/open-pact"
  license "MIT"
  depends_on :macos

  on_macos do
    on_arm do
      url "https://github.com/gaboe/open-pact/releases/download/v{version}/{RELEASE_FILES['mac_arm64']}"
      sha256 "{arm_hash}"
    end

    on_intel do
      url "https://github.com/gaboe/open-pact/releases/download/v{version}/{RELEASE_FILES['mac_x86_64']}"
      sha256 "{intel_hash}"
    end
  end

  {note.rstrip()}
  def install
    if Hardware::CPU.arm?
      bin.install "{RELEASE_FILES['mac_arm64']}" => "open-pact-client"
    else
      bin.install "{RELEASE_FILES['mac_x86_64']}" => "open-pact-client"
    end
  end

  test do
    assert_match "open-pact-client {version}", shell_output("#{{bin}}/open-pact-client --version")
  end
end
'''


def scoop_manifest(version: str, digest: str, placeholder: bool, url: str | None) -> str:
    note = (
        "PLACEHOLDER HASH: replace with the published SHA256SUMS value."
        if placeholder
        else "Open Pact client."
    )
    download_url = url or (
        f"https://github.com/gaboe/open-pact/releases/download/v{version}/"
        f"{RELEASE_FILES['windows_x86_64']}"
    )
    return f'''{{
  "version": "{version}",
  "description": "{note}",
  "homepage": "https://github.com/gaboe/open-pact",
  "license": "MIT",
  "architecture": {{
    "64bit": {{
      "url": "{download_url}",
      "hash": "{digest}"
    }}
  }},
  "bin": [["{RELEASE_FILES['windows_x86_64']}", "open-pact-client"]],
  "checkver": {{
    "github": "https://github.com/gaboe/open-pact"
  }},
  "autoupdate": {{
    "architecture": {{
      "64bit": {{
        "url": "https://github.com/gaboe/open-pact/releases/download/v$version/{RELEASE_FILES['windows_x86_64']}"
      }}
    }},
    "hash": {{
      "url": "https://github.com/gaboe/open-pact/releases/download/v$version/SHA256SUMS",
      "regex": "(?m)^(?<sha256>[0-9a-f]{{64}})  {RELEASE_FILES['windows_x86_64'].replace('.', '[.]')}$"
    }}
  }}
}}
'''


def desktop_scoop_manifest(version: str, digest: str) -> str:
    """The Scoop manifest of the desktop apps.

    It has no "bin" entry: the app installs and owns its copy of the client, so a second
    open-pact-client shim would collide with the shim of the open-pact package.
    """
    repo = "https://github.com/gaboe/open-pact"
    manifest = {
        "version": version,
        "description": "Desktop apps for open-pact: join a company and check this device, and edit deployment manifests",
        "homepage": repo,
        "license": "MIT",
        "architecture": {
            "64bit": {
                "url": f"{repo}/releases/download/v{version}/{desktop_zip(version)}",
                "hash": digest,
            }
        },
        "shortcuts": [
            ["open-pact.exe", "open-pact"],
            ["open-pact-admin.exe", "open-pact admin"],
        ],
        "checkver": {"github": repo},
        "autoupdate": {
            "architecture": {
                "64bit": {
                    "url": f"{repo}/releases/download/v$version/{desktop_zip('$version')}",
                }
            },
            "hash": {
                "url": f"{repo}/releases/download/v$version/SHA256SUMS",
                "regex": "$sha256\\s+$basename",
            },
        },
    }
    return json.dumps(manifest, indent=2) + "\n"


def upgrade_code() -> str:
    """The MSI UpgradeCode, read from the .wxs the same way build-msi.ps1 reads it."""
    wxs = (ROOT / "packaging" / "windows" / "open-pact-client.wxs").read_text(encoding="utf-8")
    match = re.search(r'UpgradeCode="(\{[0-9A-F-]{36}\})"', wxs)
    if match is None:
        raise ValueError("packaging/windows/open-pact-client.wxs has no UpgradeCode")
    return match.group(1)


def winget_manifests(version: str, msi_hash: str, identifier: str) -> dict[str, str]:
    """The three winget manifests (schema 1.10.0) of the machine MSI for one version."""
    upgrade = upgrade_code()
    product_code = version_gate.msi_product_code(upgrade, version)
    display_version = version_gate.msi_version(version)
    url = f"{RELEASE_URL}/v{version}/{MSI_FILE}"
    head = f'PackageIdentifier: {identifier}\nPackageVersion: "{version}"\n'
    return {
        f"{identifier}.yaml": f"""# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.10.0.schema.json
{head}DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.10.0
""",
        f"{identifier}.installer.yaml": f"""# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.10.0.schema.json
{head}Installers:
  - Architecture: x64
    InstallerType: wix
    Scope: machine
    InstallerUrl: "{url}"
    InstallerSha256: "{msi_hash}"
    ProductCode: "{product_code}"
    AppsAndFeaturesEntries:
      - ProductCode: "{product_code}"
        UpgradeCode: "{upgrade}"
        DisplayVersion: "{display_version}"
ManifestType: installer
ManifestVersion: 1.10.0
""",
        f"{identifier}.locale.en-US.yaml": f"""# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.1.10.0.schema.json
{head}PackageLocale: en-US
Publisher: gaboe
PublisherUrl: https://github.com/gaboe
PackageName: open-pact client
PackageUrl: https://github.com/gaboe/open-pact
License: MIT
ShortDescription: "Verifiable security checks for personally owned devices"
ManifestType: defaultLocale
ManifestVersion: 1.10.0
""",
    }


def write_winget(directory: Path, version: str, msi_hash: str, test: bool) -> list[Path]:
    identifier = WINGET_TEST_ID if test else WINGET_ID
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, text in winget_manifests(version, msi_hash, identifier).items():
        path = directory / name
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="release version without the v prefix")
    parser.add_argument("checksums", type=Path, help="release SHA256SUMS file")
    parser.add_argument("--homebrew-dir", type=Path)
    parser.add_argument("--scoop-dir", type=Path)
    parser.add_argument("--scoop-url", help="override the Scoop download URL")
    parser.add_argument("--scoop-only", action="store_true", help="write only the Scoop manifest")
    parser.add_argument(
        "--desktop",
        action="store_true",
        help="also write open-pact-desktop.json; the checksums must list the Windows desktop zip",
    )
    parser.add_argument(
        "--placeholder-hashes",
        action="store_true",
        help="write clearly marked seed metadata before the release exists",
    )
    parser.add_argument(
        "--winget-dir",
        type=Path,
        help="also write the winget manifests here; the checksums must list the machine MSI",
    )
    parser.add_argument(
        "--winget-only", action="store_true", help="write only the winget manifests"
    )
    parser.add_argument(
        "--winget-test",
        action="store_true",
        help="write gaboe.open-pact.test manifests for any version, for the VM tests only",
    )
    args = parser.parse_args()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", args.version):
        parser.error("version must be a semantic version without a v prefix")
    stable = "-" not in args.version
    if args.winget_test and args.winget_dir is None:
        parser.error("--winget-test needs --winget-dir")
    if args.winget_only and args.winget_dir is None:
        parser.error("--winget-only needs --winget-dir")
    if args.winget_only and (args.scoop_only or args.desktop or args.placeholder_hashes):
        parser.error("--winget-only writes only the winget manifests")
    if args.winget_dir is not None and args.placeholder_hashes:
        parser.error("winget manifests need the real checksums, not placeholders")
    if args.winget_dir is not None and not args.winget_test and not stable:
        parser.error("winget manifests are for stable releases; use --winget-test for a prerelease")
    if not args.winget_only and args.scoop_dir is None:
        parser.error("--scoop-dir is required unless --winget-only is set")
    if not (args.scoop_only or args.winget_only) and args.homebrew_dir is None:
        parser.error("--homebrew-dir is required unless --scoop-only or --winget-only is set")
    if args.winget_only:
        required_files = {MSI_FILE}
    else:
        required_files = (
            {RELEASE_FILES["windows_x86_64"]} if args.scoop_only else set(RELEASE_FILES.values())
        )
    if args.desktop:
        required_files.add(desktop_zip(args.version))
    if args.winget_dir is not None:
        required_files.add(MSI_FILE)
    checksums = read_checksums(args.checksums, required_files)
    winget_paths: list[Path] = []
    if args.winget_dir is not None:
        winget_paths = write_winget(
            args.winget_dir, args.version, checksums[MSI_FILE], args.winget_test
        )
    if args.winget_only:
        for path in winget_paths:
            print(path)
        return
    if args.homebrew_dir is not None:
        args.homebrew_dir.mkdir(parents=True, exist_ok=True)
    args.scoop_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.scoop_dir / "open-pact.json"
    if not args.scoop_only:
        formula_path = args.homebrew_dir / "open-pact.rb"
        formula_path.write_text(
            formula(args.version, checksums, args.placeholder_hashes), encoding="utf-8"
        )
    manifest_path.write_text(
        scoop_manifest(
            args.version,
            "PLACEHOLDER"
            if args.placeholder_hashes
            else checksums[RELEASE_FILES["windows_x86_64"]],
            args.placeholder_hashes,
            args.scoop_url,
        ),
        encoding="utf-8",
    )
    if args.desktop:
        desktop_path = args.scoop_dir / "open-pact-desktop.json"
        desktop_path.write_text(
            desktop_scoop_manifest(
                args.version,
                "PLACEHOLDER"
                if args.placeholder_hashes
                else checksums[desktop_zip(args.version)],
            ),
            encoding="utf-8",
        )
    if not args.scoop_only:
        print(formula_path)
    print(manifest_path)
    if args.desktop:
        print(desktop_path)
    for path in winget_paths:
        print(path)


if __name__ == "__main__":
    main()
