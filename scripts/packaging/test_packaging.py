"""Tests for the release packaging scripts. Run with:

    uv run python -m unittest discover -s scripts/packaging -p 'test_*.py'
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
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


class MsiVersionTest(unittest.TestCase):
    def test_each_row_of_the_scheme(self):
        cases = {
            "0.9.0-rc.1": "0.9.1",
            "0.9.0-rc.2": "0.9.2",
            "0.9.0": "0.9.99",
            "0.9.1-rc.1": "0.9.101",
            "0.9.1": "0.9.199",
            "0.0.1": "0.0.199",
            "0.0.2-rc.1": "0.0.201",
            "0.0.2": "0.0.299",
            "0.0.3": "0.0.399",
        }
        for version, product in cases.items():
            with self.subTest(version=version):
                self.assertEqual(gate.msi_version(version), product)

    def test_the_releases_sort_in_release_order(self):
        releases = []
        for patch in range(4):
            releases += [f"1.2.{patch}-rc.{number}" for number in range(1, 99)]
            releases.append(f"1.2.{patch}")
        keys = [tuple(int(part) for part in gate.msi_version(version).split(".")) for version in releases]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(set(keys)), len(keys))

    def test_the_largest_values_fit_the_build_field(self):
        self.assertEqual(gate.msi_version("255.255.654"), "255.255.65499")
        self.assertEqual(gate.msi_version("255.255.654-rc.98"), "255.255.65498")

    def test_values_outside_the_scheme_are_refused(self):
        for version in (
            "256.0.0", "0.256.0", "0.0.655", "0.0.654-rc.99", "0.0.0-rc.0",
            "0.0.1-beta.1", "1.2", "01.2.3", "1.2.3-rc.01",
        ):
            with self.subTest(version=version), self.assertRaises(SystemExit):
                gate.msi_version(version)


class MsiProductCodeTest(unittest.TestCase):
    UPGRADE = "{E1B7C572-13D3-4628-AFF3-453C870603F6}"

    def test_the_product_code_follows_the_version(self):
        code = gate.msi_product_code(self.UPGRADE, "0.9.0")
        self.assertEqual(code, gate.msi_product_code(self.UPGRADE, "0.9.0"))
        self.assertNotEqual(code, gate.msi_product_code(self.UPGRADE, "0.9.0-rc.1"))
        self.assertRegex(code, r"^\{[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\}$")

    def test_the_command_prints_the_product_version_and_code(self):
        out = subprocess.run(
            [sys.executable, str(HERE / "check-release-version.py"), "--msi", "0.9.0-rc.1", self.UPGRADE],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        version, code = out.split()
        self.assertEqual(version, "0.9.1")
        self.assertEqual(code, gate.msi_product_code(self.UPGRADE, "0.9.0-rc.1"))


class TagSchemeTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        for path, version in ((self.root / "Cargo.toml", "1.2.3-beta.1"), (self.root / "desktop" / "Cargo.toml", "1.2.3-beta.1")):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f'[workspace]\nmembers = []\n\n[workspace.package]\nversion = "{version}"\n')

    def test_a_tag_the_msi_scheme_cannot_order_fails_before_any_build(self):
        with self.assertRaises(SystemExit):
            gate.check("v1.2.3-beta.1", self.root)


class WixSourceTest(unittest.TestCase):
    WIX = HERE.parents[1] / "packaging" / "windows"
    NS = "{http://wixtoolset.org/schemas/v4/wxs}"

    def test_both_sources_are_well_formed_and_share_one_upgrade_code(self):
        codes = set()
        for path in (self.WIX / "open-pact-client.wxs", self.WIX / "tests" / "fail-late.wxs"):
            package = ET.parse(path).getroot().find(self.NS + "Package")
            codes.add(package.get("UpgradeCode"))
        self.assertEqual(len(codes), 1)
        self.assertRegex(codes.pop(), r"^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$")

    def test_the_release_source_has_one_file_and_no_custom_action(self):
        text = (self.WIX / "open-pact-client.wxs").read_text()
        self.assertEqual(text.count("<File "), 1)
        for forbidden in ("CustomAction", "Binary", "InstallExecuteSequence"):
            self.assertNotIn(forbidden, text)
        self.assertIn('Name="PATH"', text)

    def test_the_fail_late_fixture_is_the_release_source_plus_its_failing_action(self):
        release = (self.WIX / "open-pact-client.wxs").read_text().splitlines()
        fixture = (self.WIX / "tests" / "fail-late.wxs").read_text().splitlines()
        self.assertEqual([line for line in release if line not in fixture], [])
        added = [line for line in fixture if line not in release]
        self.assertTrue(any('Id="FailLate"' in line for line in added))
        self.assertTrue(all(line.strip().startswith(("<", "Execute", "Impersonate")) or line.strip() == "" for line in added))


if __name__ == "__main__":
    unittest.main()
