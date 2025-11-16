"""Helper functions for creating mock PE files in tests."""

import struct


def create_mock_dos_header(pe_offset: int = 0x80) -> bytearray:
    """Create a minimal DOS header pointing to PE signature."""
    data = bytearray(0x40)
    data[0:2] = b"MZ"  # DOS signature
    data[0x3C:0x40] = struct.pack("<I", pe_offset)
    return data


def create_mock_pe_file(
    pe_offset: int = 0x80,
    timestamp: int = 0x12345678,
    has_debug_dir: bool = False,
) -> bytearray:
    """Create a minimal valid PE file for testing."""
    # DOS header
    data = bytearray(pe_offset + 0x200)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", pe_offset)

    # PE signature
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    # COFF header
    coff_offset = pe_offset + 4
    data[coff_offset : coff_offset + 2] = struct.pack("<H", 0x8664)  # Machine (x64)
    data[coff_offset + 2 : coff_offset + 4] = struct.pack("<H", 1)  # NumberOfSections
    data[coff_offset + 4 : coff_offset + 8] = struct.pack("<I", timestamp)  # TimeDateStamp

    # Optional header size
    data[coff_offset + 16 : coff_offset + 18] = struct.pack("<H", 240)  # SizeOfOptionalHeader

    # Optional header (PE32+)
    opt_offset = coff_offset + 20
    data[opt_offset : opt_offset + 2] = struct.pack("<H", 0x20B)  # Magic (PE32+)

    return data
