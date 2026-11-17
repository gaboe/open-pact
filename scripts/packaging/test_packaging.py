"""Tests for the release packaging scripts. Run with:

    uv run python -m unittest discover -s scripts/packaging -p 'test_*.py'
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load("generate_release_metadata", "generate-release-metadata.py")
gate = load("check_release_version", "check-release-version.py")

VERSION = "1.2.3"
SUMS = {
    "open-pact-client-aarch64-apple-darwin": "a" * 64,
    "open-pact-client-x86_64-apple-darwin": "b" * 64,
    "open-pact-client-x86_64-unknown-linux-musl": "c" * 64,
    "open-pact-client-x86_64-pc-windows-msvc.exe": "d" * 64,
    "open-pact-desktop-1.2.3-macos.zip": "e" * 64,
    "open-pact-desktop-1.2.3-windows-x64.zip": "f" * 64,
    "NOTICE": "0" * 64,
}


def write_sums(directory: Path, sums: dict[str, str]) -> Path:
    path = directory / "SHA256SUMS"
    path.write_text("".join(f"{digest}  {name}\n" for name, digest in sums.items()))
    return path


def run_generator(*args: str) -> str:
    out = io.StringIO()
    argv = sys.argv
    sys.argv = ["generate-release-metadata.py", *args]
    try:
        with contextlib.redirect_stdout(out):
            generator.main()
    finally:
        sys.argv = argv
    return out.getvalue()


class GeneratorTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def generate(self, sums: dict[str, str], *extra: str) -> Path:
        checksums = write_sums(self.dir, sums)
        run_generator(
            VERSION,
            str(checksums),
            "--homebrew-dir",
            str(self.dir / "Formula"),
            "--scoop-dir",
            str(self.dir / "bucket"),
            *extra,
        )
        return self.dir / "bucket"

    def test_desktop_manifest_has_no_bin_and_the_zip_hash(self):
        bucket = self.generate(SUMS, "--desktop")
        manifest = json.loads((bucket / "open-pact-desktop.json").read_text())
        self.assertNotIn("bin", manifest)
        self.assertEqual(manifest["version"], VERSION)
        self.assertEqual(
            manifest["architecture"]["64bit"],
            {
                "url": "https://github.com/gaboe/open-pact/releases/download/v1.2.3/open-pact-desktop-1.2.3-windows-x64.zip",
                "hash": "f" * 64,
            },
        )
        self.assertEqual(
            [name for _, name in manifest["shortcuts"]], ["open-pact", "open-pact admin"]
        )
        autoupdate = manifest["autoupdate"]
        self.assertIn(
            "v$version/open-pact-desktop-$version-windows-x64.zip",
            autoupdate["architecture"]["64bit"]["url"],
        )
        self.assertTrue(autoupdate["hash"]["url"].endswith("/v$version/SHA256SUMS"))

    def test_the_cli_manifest_keeps_its_shim_and_no_desktop_file_without_the_flag(self):
        bucket = self.generate(SUMS)
        cli = json.loads((bucket / "open-pact.json").read_text())
        self.assertEqual(
            cli["bin"], [["open-pact-client-x86_64-pc-windows-msvc.exe", "open-pact-client"]]
        )
        self.assertFalse((bucket / "open-pact-desktop.json").exists())

    def test_the_desktop_flag_needs_the_windows_zip_checksum(self):
        sums = {k: v for k, v in SUMS.items() if "windows-x64" not in k}
        checksums = write_sums(self.dir, sums)
        with self.assertRaisesRegex(ValueError, "open-pact-desktop-1.2.3-windows-x64.zip"):
            run_generator(
                VERSION,
                str(checksums),
                "--homebrew-dir",
                str(self.dir / "Formula"),
                "--scoop-dir",
                str(self.dir / "bucket"),
                "--desktop",
            )

    def test_extra_checksum_lines_do_not_break_the_cli_files(self):
        bucket = self.generate(SUMS)
        self.assertTrue((bucket / "open-pact.json").exists())
        self.assertTrue((self.dir / "Formula" / "open-pact.rb").exists())


class VersionGateTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        (self.root / "desktop").mkdir()

    def manifests(self, root_version: str, desktop_version: str):
        for path, version in (
            (self.root / "Cargo.toml", root_version),
            (self.root / "desktop" / "Cargo.toml", desktop_version),
        ):
            path.write_text(f'[workspace]\nmembers = []\n\n[workspace.package]\nversion = "{version}"\n')

    def test_matching_versions_pass(self):
        self.manifests("1.2.3", "1.2.3")
        self.assertEqual(gate.check("v1.2.3", self.root), "1.2.3")

    def test_a_prerelease_tag_needs_the_prerelease_version(self):
        self.manifests("1.2.3-rc.1", "1.2.3-rc.1")
        self.assertEqual(gate.check("v1.2.3-rc.1", self.root), "1.2.3-rc.1")
        with self.assertRaises(SystemExit):
            gate.check("v1.2.3", self.root)

    def test_a_stale_desktop_version_fails_and_names_the_file(self):
        self.manifests("1.2.3", "0.1.0")
        with self.assertRaisesRegex(SystemExit, "desktop/Cargo.toml"):
            gate.check("v1.2.3", self.root)

    def test_a_stale_root_version_fails(self):
        self.manifests("1.2.2", "1.2.3")
        with self.assertRaisesRegex(SystemExit, "Cargo.toml"):
            gate.check("v1.2.3", self.root)

    def test_a_tag_without_v_fails(self):
        self.manifests("1.2.3", "1.2.3")
        with self.assertRaises(SystemExit):
            gate.check("1.2.3", self.root)

    def test_the_repository_versions_agree_with_each_other(self):
        root = HERE.parents[1]
        version = gate.workspace_version(root / "Cargo.toml")
        self.assertEqual(gate.check(f"v{version}", root), version)


if __name__ == "__main__":
    unittest.main()
