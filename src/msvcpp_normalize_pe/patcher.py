"""Core PE file patching logic."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

# PE file format constants
_DOS_HEADER_MIN_SIZE = 0x40
_PE_OFFSET_LOCATION = 0x3C
_COFF_HEADER_SIZE = 20
_DEBUG_DIRECTORY_INDEX = 6
_DEBUG_ENTRY_SIZE = 28

# Debug directory type constants
_DEBUG_TYPE_CODEVIEW = 2
_DEBUG_TYPE_REPRO = 16

# PE32/PE32+ magic numbers
_PE32_MAGIC = 0x10B  # 32-bit
_PE32_PLUS_MAGIC = 0x20B  # 64-bit

# CODEVIEW signature
_RSDS_SIGNATURE = 0x53445352  # 'RSDS' in little-endian

# GUID size in bytes
_GUID_SIZE = 16


@dataclass
class PatchResult:
    """Result of patching operation."""

    success: bool
    patches_applied: int
    errors: list[str] = field(default_factory=list)
    file_path: Path | None = None


@dataclass
class DebugDirectory:
    """Debug directory location information."""

    file_offset: int
    num_entries: int
    size: int


def validate_pe_file(path: Path) -> bool:
    """Validate that a file is a valid PE executable.

    Args:
        path: Path to file to validate

    Returns:
        True if valid PE file, False otherwise

    """
    if not path.exists():
        return False

    if path.stat().st_size < _DOS_HEADER_MIN_SIZE:
        return False

    with path.open("rb") as f:
        data = f.read(0x100)

    # Check DOS header signature
    if data[0:2] != b"MZ":
        return False

    # Get PE offset
    pe_offset = struct.unpack("<I", data[_PE_OFFSET_LOCATION:_DOS_HEADER_MIN_SIZE])[0]

    if pe_offset + 4 > len(data):
        # Need to read more
        with path.open("rb") as f:
            data = f.read(pe_offset + 4)

    if len(data) < pe_offset + 4:
        return False

    # Check PE signature
    pe_sig = data[pe_offset : pe_offset + 4]
    return pe_sig == b"PE\x00\x00"


def _find_pe_offset(data: bytes | bytearray) -> int:
    """Find PE signature offset from DOS header."""
    if len(data) < _DOS_HEADER_MIN_SIZE:
        msg = "File too small for DOS header"
        raise ValueError(msg)
    pe_offset: int = struct.unpack(
        "<I",
        data[_PE_OFFSET_LOCATION:_DOS_HEADER_MIN_SIZE],
    )[0]
    return pe_offset


def _verify_pe_signature(data: bytes | bytearray, pe_offset: int) -> None:
    """Verify PE signature at given offset."""
    if len(data) < pe_offset + 4:
        msg = f"File too small for PE signature at offset {pe_offset}"
        raise ValueError(msg)

    pe_sig = data[pe_offset : pe_offset + 4]
    if pe_sig != b"PE\x00\x00":
        msg = f"Invalid PE signature: {pe_sig.hex()}"
        raise ValueError(msg)


def _patch_coff_header(
    data: bytearray,
    pe_offset: int,
    timestamp: int,
    *,
    verbose: bool = False,
) -> int:
    """Patch COFF header timestamp."""
    coff_offset = pe_offset + 4
    timestamp_offset = coff_offset + 4

    if len(data) < timestamp_offset + 4:
        msg = "File too small for COFF header"
        raise ValueError(msg)

    original_timestamp = struct.unpack("<I", data[timestamp_offset : timestamp_offset + 4])[0]
    data[timestamp_offset : timestamp_offset + 4] = struct.pack("<I", timestamp)

    if verbose:
        print(f"  [1/?] COFF header: 0x{original_timestamp:08x} -> 0x{timestamp:08x}")

    return 1


def _find_debug_directory(
    data: bytes | bytearray,
    pe_offset: int,
) -> DebugDirectory | None:
    """Find debug directory location in PE file."""
    coff_offset = pe_offset + 4

    # Get number of sections and optional header size
    if len(data) < coff_offset + _COFF_HEADER_SIZE:
        return None

    num_sections = struct.unpack("<H", data[coff_offset + 2 : coff_offset + 4])[0]
    opt_header_size = struct.unpack("<H", data[coff_offset + 16 : coff_offset + 18])[0]
    opt_header_offset = coff_offset + _COFF_HEADER_SIZE

    if len(data) < opt_header_offset + 2:
        return None

    # Check PE32 (32-bit) or PE32+ (64-bit) magic
    magic = struct.unpack("<H", data[opt_header_offset : opt_header_offset + 2])[0]

    if magic == _PE32_MAGIC:  # PE32 (32-bit)
        # Data directories start at opt_header_offset + 96 for PE32
        data_dir_offset = opt_header_offset + 96
    elif magic == _PE32_PLUS_MAGIC:  # PE32+ (64-bit)
        # Data directories start at opt_header_offset + 112 for PE32+
        data_dir_offset = opt_header_offset + 112
    else:
        return None

    # Debug directory is entry #6
    if len(data) < data_dir_offset + _DEBUG_DIRECTORY_INDEX * 8 + 8:
        return None

    debug_entry_offset = data_dir_offset + _DEBUG_DIRECTORY_INDEX * 8
    debug_dir_rva = struct.unpack("<I", data[debug_entry_offset : debug_entry_offset + 4])[0]
    debug_dir_size = struct.unpack(
        "<I",
        data[debug_entry_offset + 4 : debug_entry_offset + 8],
    )[0]

    if debug_dir_rva == 0 or debug_dir_size == 0:
        return None

    # Convert RVA to file offset using section table
    section_table_offset = opt_header_offset + opt_header_size

    for i in range(num_sections):
        section_offset = section_table_offset + i * 40
        if len(data) < section_offset + 24:
            break

        virtual_addr = struct.unpack("<I", data[section_offset + 12 : section_offset + 16])[0]
        virtual_size = struct.unpack("<I", data[section_offset + 8 : section_offset + 12])[0]
        raw_ptr = struct.unpack("<I", data[section_offset + 20 : section_offset + 24])[0]

        if virtual_addr <= debug_dir_rva < virtual_addr + virtual_size:
            file_offset = raw_ptr + (debug_dir_rva - virtual_addr)
            num_entries = debug_dir_size // _DEBUG_ENTRY_SIZE
            return DebugDirectory(file_offset, num_entries, debug_dir_size)

    return None


def _patch_debug_entries(
    data: bytearray,
    debug_dir: DebugDirectory,
    timestamp: int,
    *,
    verbose: bool = False,
) -> int:
    """Patch all debug directory entry timestamps."""
    patches = 0

    debug_type_names = {
        1: "COFF",
        2: "CODEVIEW",
        3: "FPO",
        4: "MISC",
        5: "EXCEPTION",
        6: "FIXUP",
        7: "OMAP_TO_SRC",
        8: "OMAP_FROM_SRC",
        9: "BORLAND",
        10: "RESERVED10",
        11: "CLSID",
        12: "VC_FEATURE",
        13: "POGO",
        14: "ILTCG",
        15: "MPX",
        16: "REPRO",
    }

    for j in range(debug_dir.num_entries):
        entry_offset = debug_dir.file_offset + j * _DEBUG_ENTRY_SIZE
        ts_offset = entry_offset + 4

        if len(data) < ts_offset + 4:
            continue

        entry_type = struct.unpack("<I", data[entry_offset + 12 : entry_offset + 16])[0]
        type_name = debug_type_names.get(entry_type, f"TYPE_{entry_type}")

        # Patch timestamp
        orig_ts = struct.unpack("<I", data[ts_offset : ts_offset + 4])[0]
        data[ts_offset : ts_offset + 4] = struct.pack("<I", timestamp)
        patches += 1

        if verbose:
            print(
                f"  [{patches}/?] Debug {type_name} timestamp: "
                f"0x{orig_ts:08x} -> 0x{timestamp:08x}",
            )

        # CODEVIEW: Patch GUID and Age
        if entry_type == _DEBUG_TYPE_CODEVIEW:
            patches = _patch_codeview_entry(data, entry_offset, patches, verbose=verbose)

        # REPRO: Patch hash
        if entry_type == _DEBUG_TYPE_REPRO:
            patches = _patch_repro_entry(data, entry_offset, patches, verbose=verbose)

    return patches


def _patch_codeview_entry(
    data: bytearray,
    entry_offset: int,
    patches: int,
    *,
    verbose: bool,
) -> int:
    """Patch CODEVIEW debug entry GUID and Age."""
    ptr_to_data = struct.unpack("<I", data[entry_offset + 24 : entry_offset + 28])[0]
    if ptr_to_data > 0 and len(data) >= ptr_to_data + 24:
        cv_sig = struct.unpack("<I", data[ptr_to_data : ptr_to_data + 4])[0]
        if cv_sig == _RSDS_SIGNATURE:  # 'RSDS'
            guid_offset = ptr_to_data + 4
            age_offset = ptr_to_data + 20

            orig_guid = data[guid_offset : guid_offset + _GUID_SIZE].hex()
            data[guid_offset : guid_offset + _GUID_SIZE] = bytes(_GUID_SIZE)
            patches += 1

            if verbose:
                print(f"  [{patches}/?] Debug CODEVIEW GUID: {orig_guid} -> {'00' * _GUID_SIZE}")

            orig_age = struct.unpack("<I", data[age_offset : age_offset + 4])[0]
            data[age_offset : age_offset + 4] = struct.pack("<I", 1)
            patches += 1

            if verbose:
                print(f"  [{patches}/?] Debug CODEVIEW Age: {orig_age} -> 1")

    return patches


def _patch_repro_entry(
    data: bytearray,
    entry_offset: int,
    patches: int,
    *,
    verbose: bool,
) -> int:
    """Patch REPRO debug entry hash."""
    size_of_data = struct.unpack("<I", data[entry_offset + 16 : entry_offset + 20])[0]
    ptr_to_data = struct.unpack("<I", data[entry_offset + 24 : entry_offset + 28])[0]
    if ptr_to_data > 0 and len(data) >= ptr_to_data + size_of_data:
        orig_hash = data[ptr_to_data : ptr_to_data + size_of_data].hex()[:32]
        data[ptr_to_data : ptr_to_data + size_of_data] = bytes(size_of_data)
        patches += 1

        if verbose:
            print(
                f"  [{patches}/?] Debug REPRO hash: {orig_hash}... -> {'00' * size_of_data}",
            )

    return patches


def patch_pe_file(
    pe_path: Path,
    timestamp: int = 1,
    *,
    verbose: bool = False,
) -> PatchResult:
    """Patch PE file to normalize timestamps and GUIDs for reproducibility.

    Args:
        pe_path: Path to PE file (.exe or .dll)
        timestamp: Fixed timestamp value to write (default: 1)
        verbose: Print detailed patching information

    Returns:
        PatchResult with success status and number of patches applied

    """
    pe_path = Path(pe_path)
    result = PatchResult(success=False, patches_applied=0, file_path=pe_path)

    # Validate file exists
    if not pe_path.exists():
        msg = f"File not found: {pe_path}"
        result.errors.append(msg)
        return result

    # Read entire file
    try:
        with pe_path.open("rb") as f:
            data = bytearray(f.read())
    except Exception as e:
        msg = f"Failed to read file: {e}"
        result.errors.append(msg)
        return result

    # Find and verify PE signature
    try:
        pe_offset = _find_pe_offset(data)
        _verify_pe_signature(data, pe_offset)
    except ValueError as e:
        result.errors.append(str(e))
        return result

    # Patch COFF header
    try:
        patches = _patch_coff_header(data, pe_offset, timestamp, verbose=verbose)
        result.patches_applied += patches
    except Exception as e:
        msg = f"Failed to patch COFF header: {e}"
        result.errors.append(msg)
        return result

    # Patch debug directory entries
    debug_dir = _find_debug_directory(data, pe_offset)
    if debug_dir:
        try:
            patches = _patch_debug_entries(data, debug_dir, timestamp, verbose=verbose)
            result.patches_applied += patches
        except Exception as e:
            msg = f"Failed to patch debug entries: {e}"
            result.errors.append(msg)
            # Don't return - COFF header was patched successfully

    # Write back
    try:
        with pe_path.open("wb") as f:
            f.write(data)
    except Exception as e:
        msg = f"Failed to write file: {e}"
        result.errors.append(msg)
        return result

    result.success = True
    if verbose:
        print(f"  Total: {result.patches_applied} patch(es) applied to {pe_path.name}")

    return result
