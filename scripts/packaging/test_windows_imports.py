"""Tests for the Windows import check. Run with:

    uv run python -m unittest discover -s scripts/packaging -p 'test_*.py'
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import struct
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


imports = load("check_windows_imports", "check-windows-imports.py")

SECTION_RVA = 0x1000
SECTION_AT = 0x200


def pe_image(dlls=(), delayed=()) -> bytes:
    """A PE32+ image whose one section holds the import and delay-load tables."""
    import_size = 20 * (len(dlls) + 1)
    delay_size = 32 * (len(delayed) + 1)
    names = bytearray()

    def name_rva(dll: str) -> int:
        rva = SECTION_RVA + import_size + delay_size + len(names)
        names.extend(dll.encode() + b"\0")
        return rva

    table = bytearray()
    for dll in dlls:
        table += struct.pack("<5I", 0, 0, 0, name_rva(dll), 0)
    table += bytes(20)
    delay_at = len(table)
    for dll in delayed:
        table += struct.pack("<8I", 1, name_rva(dll), 0, 0, 0, 0, 0, 0)
    table += bytes(32)
    content = bytes(table + names)
    assert len(content) <= 0x200

    header = bytearray(SECTION_AT)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 0x44, 0x8664, 1, 0, 0, 0, 240, 0x22)
    optional = 0x58
    struct.pack_into("<H", header, optional, 0x20B)
    struct.pack_into("<I", header, optional + 108, 16)
    directories = optional + 112
    struct.pack_into("<II", header, directories + 8 * 1, SECTION_RVA, import_size)
    struct.pack_into("<II", header, directories + 8 * 13, SECTION_RVA + delay_at, delay_size)
    section = optional + 240
    header[section : section + 8] = b".idata\0\0"
    struct.pack_into("<4I", header, section + 8, len(content), SECTION_RVA, 0x200, SECTION_AT)
    return bytes(header) + content.ljust(0x200, b"\0")


class ImportedDllsTest(unittest.TestCase):
    def test_reads_the_import_table(self):
        image = pe_image(dlls=["KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"])
        self.assertEqual(
            imports.imported_dlls(image), ["KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"]
        )

    def test_reads_the_delay_load_table(self):
        image = pe_image(dlls=["KERNEL32.dll"], delayed=["MSVCP140.dll"])
        self.assertEqual(imports.imported_dlls(image), ["KERNEL32.dll", "MSVCP140.dll"])

    def test_an_image_without_imports_has_none(self):
        self.assertEqual(imports.imported_dlls(pe_image()), [])

    def test_a_file_that_is_not_a_pe_image_is_refused(self):
        with self.assertRaises(ValueError):
            imports.imported_dlls(b"MZ" + bytes(200))


class MainTest(unittest.TestCase):
    def check(self, image: bytes):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "open-pact-client.exe"
            path.write_bytes(image)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = imports.main(["check", str(path)])
            return code, out.getvalue(), err.getvalue()

    def test_a_static_crt_image_passes(self):
        code, out, _ = self.check(pe_image(dlls=["KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"]))
        self.assertEqual(code, 0)
        self.assertIn("none from the Visual C++ runtime", out)

    def test_a_vcruntime_import_fails_and_names_the_dll(self):
        code, _, err = self.check(pe_image(dlls=["KERNEL32.dll", "VCRUNTIME140.dll"]))
        self.assertEqual(code, 1)
        self.assertIn("VCRUNTIME140.dll", err)

    def test_every_forbidden_family_fails_in_any_case(self):
        for dll in ["msvcp140.dll", "VCOMP140.DLL", "vcruntime140_1.dll"]:
            with self.subTest(dll=dll):
                self.assertEqual(self.check(pe_image(dlls=[dll]))[0], 1)

    def test_a_delayed_visual_cpp_import_fails(self):
        self.assertEqual(self.check(pe_image(dlls=["KERNEL32.dll"], delayed=["MSVCP140.dll"]))[0], 1)

    def test_a_missing_path_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(imports.main(["check"]), 2)


if __name__ == "__main__":
    unittest.main()
