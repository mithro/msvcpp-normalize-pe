#!/usr/bin/env python3
"""
msvcpp-normalize-pe - Normalize PE files for reproducible MSVC++ builds.

This script normalizes non-deterministic fields in Windows PE executables
to enable byte-for-byte reproducible MSVC builds. Patches:
- COFF header timestamp
- Debug Directory entry timestamps (CODEVIEW, VC_FEATURE, POGO, REPRO)
- CODEVIEW GUID and Age fields
- REPRO hash

Usage:
    python patch_pe_timestamp.py <pe_file> [timestamp_value]

    timestamp_value: Unix timestamp to use (default: 1)
"""

import struct
import sys
from pathlib import Path


def patch_pe_timestamp(pe_path, timestamp_value=1):
    """
    Patch the TimeDateStamp in a PE file's COFF header and Debug Directory.

    Args:
        pe_path: Path to PE file (.exe or .dll)
        timestamp_value: Fixed timestamp value to write (default: 1)

    Returns:
        True if patched successfully, False otherwise
    """
    pe_path = Path(pe_path)

    if not pe_path.exists():
        print(f"ERROR: File not found: {pe_path}", file=sys.stderr)
        return False

    # Read the entire file
    with open(pe_path, 'rb') as f:
        data = bytearray(f.read())

    # Find PE signature offset (at offset 0x3c)
    if len(data) < 0x40:
        print(f"ERROR: File too small to be a valid PE: {pe_path}", file=sys.stderr)
        return False

    pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]

    # Verify PE signature
    if len(data) < pe_offset + 4:
        print(f"ERROR: Invalid PE offset: {pe_offset}", file=sys.stderr)
        return False

    pe_sig = data[pe_offset:pe_offset+4]
    if pe_sig != b'PE\x00\x00':
        print(f"ERROR: Not a valid PE file (signature: {pe_sig.hex()})", file=sys.stderr)
        return False

    # COFF Header starts at pe_offset + 4
    coff_offset = pe_offset + 4
    num_sections = struct.unpack('<H', data[coff_offset+2:coff_offset+4])[0]

    # TimeDateStamp is at COFF_offset + 4
    timestamp_offset = coff_offset + 4

    if len(data) < timestamp_offset + 4:
        print(f"ERROR: File too small for COFF header", file=sys.stderr)
        return False

    # Read and patch COFF header timestamp
    original_timestamp = struct.unpack('<I', data[timestamp_offset:timestamp_offset+4])[0]
    data[timestamp_offset:timestamp_offset+4] = struct.pack('<I', timestamp_value)

    patches_applied = 1
    print(f"  [1/1] COFF header: 0x{original_timestamp:08x} -> 0x{timestamp_value:08x}")

    # Now patch Debug Directory timestamps
    # Get optional header size to find section table
    opt_header_size = struct.unpack('<H', data[coff_offset+16:coff_offset+18])[0]
    opt_header_offset = coff_offset + 20

    if len(data) < opt_header_offset + 2:
        print(f"  Warning: No optional header, skipping debug directory")
    else:
        magic = struct.unpack('<H', data[opt_header_offset:opt_header_offset+2])[0]

        if magic == 0x20b:  # PE32+ (64-bit)
            # Data directories start at opt_header_offset + 112
            data_dir_offset = opt_header_offset + 112

            # Debug directory is entry #6
            if len(data) >= data_dir_offset + 6*8 + 8:
                debug_dir_rva = struct.unpack('<I', data[data_dir_offset + 6*8:data_dir_offset + 6*8 + 4])[0]
                debug_dir_size = struct.unpack('<I', data[data_dir_offset + 6*8 + 4:data_dir_offset + 6*8 + 8])[0]

                if debug_dir_rva > 0 and debug_dir_size > 0:
                    # Convert RVA to file offset using section table
                    section_table_offset = opt_header_offset + opt_header_size
                    debug_file_offset = None

                    for i in range(num_sections):
                        section_offset = section_table_offset + i * 40
                        if len(data) < section_offset + 24:
                            break

                        virtual_addr = struct.unpack('<I', data[section_offset+12:section_offset+16])[0]
                        virtual_size = struct.unpack('<I', data[section_offset+8:section_offset+12])[0]
                        raw_ptr = struct.unpack('<I', data[section_offset+20:section_offset+24])[0]

                        if virtual_addr <= debug_dir_rva < virtual_addr + virtual_size:
                            debug_file_offset = raw_ptr + (debug_dir_rva - virtual_addr)
                            break

                    if debug_file_offset and len(data) >= debug_file_offset + debug_dir_size:
                        # Each debug directory entry is 28 bytes
                        num_entries = debug_dir_size // 28

                        debug_type_names = {
                            1: "COFF", 2: "CODEVIEW", 3: "FPO", 4: "MISC",
                            5: "EXCEPTION", 6: "FIXUP", 7: "OMAP_TO_SRC",
                            8: "OMAP_FROM_SRC", 9: "BORLAND", 10: "RESERVED10",
                            11: "CLSID", 12: "VC_FEATURE", 13: "POGO",
                            14: "ILTCG", 15: "MPX", 16: "REPRO"
                        }

                        for j in range(num_entries):
                            entry_offset = debug_file_offset + j * 28
                            # Timestamp is at offset +4 within each entry
                            ts_offset = entry_offset + 4

                            if len(data) >= ts_offset + 4:
                                entry_type = struct.unpack('<I', data[entry_offset+12:entry_offset+16])[0]
                                type_name = debug_type_names.get(entry_type, f"TYPE_{entry_type}")

                                orig_ts = struct.unpack('<I', data[ts_offset:ts_offset+4])[0]
                                data[ts_offset:ts_offset+4] = struct.pack('<I', timestamp_value)
                                patches_applied += 1

                                print(f"  [{patches_applied}/?] Debug {type_name} timestamp: 0x{orig_ts:08x} -> 0x{timestamp_value:08x}")

                                # For CODEVIEW entries, also patch the GUID and Age
                                if entry_type == 2:  # CODEVIEW
                                    ptr_to_data = struct.unpack('<I', data[entry_offset+24:entry_offset+28])[0]
                                    if ptr_to_data > 0 and len(data) >= ptr_to_data + 24:
                                        cv_sig = struct.unpack('<I', data[ptr_to_data:ptr_to_data+4])[0]
                                        if cv_sig == 0x53445352:  # 'RSDS'
                                            guid_offset = ptr_to_data + 4
                                            age_offset = ptr_to_data + 20

                                            orig_guid = data[guid_offset:guid_offset+16].hex()
                                            orig_age = struct.unpack('<I', data[age_offset:age_offset+4])[0]

                                            # Use a deterministic GUID: all zeros
                                            fixed_guid = bytes(16)
                                            data[guid_offset:guid_offset+16] = fixed_guid
                                            patches_applied += 1
                                            print(f"  [{patches_applied}/?] Debug CODEVIEW GUID: {orig_guid} -> {'00'*16}")

                                            # Use a deterministic Age: 1
                                            data[age_offset:age_offset+4] = struct.pack('<I', 1)
                                            patches_applied += 1
                                            print(f"  [{patches_applied}/?] Debug CODEVIEW Age: {orig_age} -> 1")

                                # For REPRO entries, patch the hash (which contains GUID)
                                if entry_type == 16:  # REPRO
                                    size_of_data = struct.unpack('<I', data[entry_offset+16:entry_offset+20])[0]
                                    ptr_to_data = struct.unpack('<I', data[entry_offset+24:entry_offset+28])[0]
                                    if ptr_to_data > 0 and len(data) >= ptr_to_data + size_of_data:
                                        orig_hash = data[ptr_to_data:ptr_to_data+size_of_data].hex()[:32]  # First 16 bytes
                                        # Patch entire REPRO hash to zeros
                                        data[ptr_to_data:ptr_to_data+size_of_data] = bytes(size_of_data)
                                        patches_applied += 1
                                        print(f"  [{patches_applied}/?] Debug REPRO hash: {orig_hash}... -> {'00'*size_of_data}")

    # Write back
    with open(pe_path, 'wb') as f:
        f.write(data)

    print(f"  Total: {patches_applied} timestamp(s) patched in {pe_path.name}")
    return True


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nExamples:", file=sys.stderr)
        print("  python patch_pe_timestamp.py program.exe", file=sys.stderr)
        print("  python patch_pe_timestamp.py program.exe 1234567890", file=sys.stderr)
        sys.exit(1)

    pe_file = sys.argv[1]
    timestamp_value = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    success = patch_pe_timestamp(pe_file, timestamp_value)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
