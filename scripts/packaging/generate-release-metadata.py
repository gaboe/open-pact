#!/usr/bin/env python3
"""Generate Homebrew and Scoop metadata from release checksums."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


RELEASE_FILES = {
    "mac_arm64": "open-pact-client-aarch64-apple-darwin",
    "mac_x86_64": "open-pact-client-x86_64-apple-darwin",
    "windows_x86_64": "open-pact-client-x86_64-pc-windows-msvc.exe",
}


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
  license "Apache-2.0"
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
  "license": "Apache-2.0",
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="release version without the v prefix")
    parser.add_argument("checksums", type=Path, help="release SHA256SUMS file")
    parser.add_argument("--homebrew-dir", type=Path)
    parser.add_argument("--scoop-dir", type=Path, required=True)
    parser.add_argument("--scoop-url", help="override the Scoop download URL")
    parser.add_argument("--scoop-only", action="store_true", help="write only the Scoop manifest")
    parser.add_argument(
        "--placeholder-hashes",
        action="store_true",
        help="write clearly marked seed metadata before the release exists",
    )
    args = parser.parse_args()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", args.version):
        parser.error("version must be a semantic version without a v prefix")
    if not args.scoop_only and args.homebrew_dir is None:
        parser.error("--homebrew-dir is required unless --scoop-only is set")
    required_files = {RELEASE_FILES["windows_x86_64"]} if args.scoop_only else None
    checksums = read_checksums(args.checksums, required_files)
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
    if not args.scoop_only:
        print(formula_path)
    print(manifest_path)


if __name__ == "__main__":
    main()
