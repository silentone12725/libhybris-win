#!/usr/bin/env python3
"""Write a deterministic, minimal ELF64 ET_DYN image for loader tests.

The fixture contains one page-aligned PT_LOAD with no file payload and one
page of memory.  It is intentionally not an Android rootfs or a usable shared
library; it exercises ELF header/program-header parsing and mapping bounds.
"""

import struct
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT")
    output = Path(sys.argv[1])
    # ELF64 header: little endian, ET_DYN, x86-64, one 56-byte program header.
    header = struct.pack(
        "16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8),
        3, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0,
    )
    # PT_LOAD, file offset 0, virtual address 0, one zero-filled page.
    program = struct.pack(
        "IIQQQQQQ", 1, 6, 0, 0, 0, 4096, 4096, 4096
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(header + program)


if __name__ == "__main__":
    main()
