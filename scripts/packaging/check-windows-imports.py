#!/usr/bin/env python3
"""Fail when a Windows image imports a Visual C++ runtime DLL.

The client links the C runtime into the executable, so it runs on a Windows
machine without the Visual C++ redistributable. A VCRUNTIME, MSVCP or VCOMP
import means the static link flag is missing.

    python scripts/packaging/check-windows-imports.py open-pact-client.exe
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

FORBIDDEN = re.compile(r"VCRUNTIME|MSVCP|VCOMP", re.IGNORECASE)
IMPORT_DIRECTORY = 1
DELAY_IMPORT_DIRECTORY = 13


def imported_dlls(image: bytes) -> list[str]:
    """The DLL names in the import table and the delay-load table of a PE32+ image."""
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe : pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    section_count = struct.unpack_from("<H", image, pe + 6)[0]
    optional_size = struct.unpack_from("<H", image, pe + 20)[0]
    optional = pe + 24
    if struct.unpack_from("<H", image, optional)[0] != 0x20B:
        raise ValueError("only PE32+ images are checked")
    sections = []
    table = optional + optional_size
    for index in range(section_count):
        at = table + 40 * index
        virtual_size, address, raw_size, raw_at = struct.unpack_from("<4I", image, at + 8)
        sections.append((address, max(virtual_size, raw_size), raw_at))

    def offset(rva: int) -> int:
        for address, size, raw_at in sections:
            if address <= rva < address + size:
                return rva - address + raw_at
        raise ValueError(f"RVA {rva:#x} is outside every section")

    def name(rva: int) -> str:
        start = offset(rva)
        return image[start : image.index(b"\0", start)].decode("ascii", "replace")

    names = []
    for directory, size, name_field in (
        (IMPORT_DIRECTORY, 20, 12),
        (DELAY_IMPORT_DIRECTORY, 32, 4),
    ):
        rva, _ = struct.unpack_from("<II", image, optional + 112 + 8 * directory)
        if rva == 0:
            continue
        at = offset(rva)
        while any(image[at : at + size]):
            names.append(name(struct.unpack_from("<I", image, at + name_field)[0]))
            at += size
    return names


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check-windows-imports.py <image.exe>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    found = imported_dlls(path.read_bytes())
    forbidden = [dll for dll in found if FORBIDDEN.search(dll)]
    if forbidden:
        print(f"{path}: imports {', '.join(forbidden)}; link the C runtime statically", file=sys.stderr)
        return 1
    print(f"{path}: imports {len(found)} DLLs, none from the Visual C++ runtime")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
