# msvc-pe-patcher - Normalize PE Files for Reproducible MSVC++ Builds

[![Documentation](https://readthedocs.org/projects/msvc-pe-patcher/badge/?version=latest)](https://msvc-pe-patcher.readthedocs.io/en/latest/)
[![PyPI](https://img.shields.io/pypi/v/msvc-pe-patcher.svg)](https://pypi.org/project/msvc-pe-patcher/)
[![Python Version](https://img.shields.io/pypi/pyversions/msvc-pe-patcher.svg)](https://pypi.org/project/msvc-pe-patcher/)
[![Tests](https://github.com/mithro/msvc-pe-patcher/workflows/Test%20%26%20Lint/badge.svg)](https://github.com/mithro/msvc-pe-patcher/actions)

A Python tool to patch Windows PE (Portable Executable) files to make MSVC builds reproducible by normalizing timestamps, GUIDs, and other non-deterministic debug metadata.

## The Problem

When compiling Windows executables with Microsoft Visual C++ (MSVC), even with the `/Brepro` flag enabled, builds are **not fully reproducible**. The same source code compiled twice produces different binaries due to non-deterministic debug information:

- **COFF Header TimeDateStamp**: Build timestamp in PE header
- **Debug Directory Timestamps**: 4 separate timestamps in debug entries (CODEVIEW, VC_FEATURE, POGO, REPRO)
- **CODEVIEW GUID**: Random GUID linking .exe to .pdb file
- **CODEVIEW Age**: Incremental counter that varies between builds
- **REPRO Hash**: Composite hash containing the GUID and timestamps

This makes **binary verification in CI impossible** - you can't verify that committed binaries match the source code because every rebuild produces different bytes, even though the executable code is identical.

## The Solution

This tool patches all non-deterministic fields in PE files to fixed, deterministic values:

- **All timestamps** → `0x00000001` (January 1, 1970 + 1 second)
- **CODEVIEW GUID** → `00000000-0000-0000-0000-000000000000`
- **CODEVIEW Age** → `1`
- **REPRO Hash** → All zeros

After patching, **identical source code produces byte-for-byte identical binaries**, enabling reproducible builds and CI verification.

## What Gets Patched

### Fields Patched (8 total)

1. **PE COFF Header TimeDateStamp** (offset varies, typically 0xC0-0x100)
2. **Debug CODEVIEW Entry Timestamp**
3. **Debug CODEVIEW GUID** (16 bytes)
4. **Debug CODEVIEW Age** (4 bytes)
5. **Debug VC_FEATURE Entry Timestamp**
6. **Debug POGO Entry Timestamp**
7. **Debug REPRO Entry Timestamp**
8. **Debug REPRO Hash** (36 bytes)

### What Doesn't Change

- **All executable code** (.text section)
- **All program data** (.data, .rdata sections)
- **Import/Export tables**
- **Section headers**
- **Relocations**

The binary behaves **identically at runtime** - only metadata used for debugging is normalized.

## Installation

### From PyPI (Recommended)

```bash
pip install msvc-pe-patcher
```

### From Source

```bash
git clone https://github.com/mithro/msvc-pe-patcher.git
cd msvc-pe-patcher
pip install .
```

### Using uv

```bash
uv pip install msvc-pe-patcher
```

## Usage

### Command Line

After installation, the `msvc-pe-patcher` command is available:

```bash
# Basic usage
msvc-pe-patcher program.exe

# Custom timestamp
msvc-pe-patcher program.exe 1234567890

# Verbose output
msvc-pe-patcher --verbose program.exe

# See all options
msvc-pe-patcher --help
```

### Python API

You can also use msvc-pe-patcher as a library in your Python code:

```python
from pathlib import Path
from msvc_pe_patcher import patch_pe_file

result = patch_pe_file(Path("program.exe"), timestamp=1, verbose=True)
if result.success:
    print(f"Patched {result.patches_applied} fields")
else:
    print(f"Errors: {result.errors}")
```

### Example Output

```
[1/1] COFF header: 0x829692a8 -> 0x00000001
  [2/?] Debug CODEVIEW timestamp: 0x829692a8 -> 0x00000001
  [3/?] Debug CODEVIEW GUID: e97b6ac706ea9b2dd577392d2bf08df7 -> 00000000000000000000000000000000
  [4/?] Debug CODEVIEW Age: 7 -> 1
  [5/?] Debug VC_FEATURE timestamp: 0x829692a8 -> 0x00000001
  [6/?] Debug POGO timestamp: 0x829692a8 -> 0x00000001
  [7/?] Debug REPRO timestamp: 0x829692a8 -> 0x00000001
  [8/?] Debug REPRO hash: 20000000e97b6ac7... -> 000000000000000000...
  Total: 8 timestamp(s) patched in program.exe
```

## Integration with Build Systems

### Makefile Integration (Native MSVC)

```makefile
# Native MSVC builds
ifeq ($(USE_NATIVE_MSVC),1)
  program.exe: program.cpp
	cl.exe /O2 /Zi program.cpp /link /DEBUG:FULL /Brepro
	msvc-pe-patcher program.exe 1
endif
```

### CI/CD Verification Workflow

```yaml
name: Verify Binary Reproducibility

jobs:
  verify:
    runs-on: windows-latest
    steps:
      - name: Build from source
        run: |
          cl.exe /O2 program.cpp /link /DEBUG:FULL /Brepro
          msvc-pe-patcher program.exe 1

      - name: Compare with committed binary
        run: |
          fc /b program.exe committed/program.exe
```

## Requirements

- **Python 3.8+** (type hints, dataclasses)
- **Target files**: Windows PE executables (.exe) or DLLs (.dll)
- **Architecture**: Works with both 32-bit (PE32) and 64-bit (PE32+) binaries

No runtime dependencies - uses only Python standard library (`struct`, `sys`, `pathlib`, `dataclasses`).

## Limitations and Known Issues

### What This Tool Fixes

- ✅ Makes **PE executables** reproducible (timestamps, GUIDs)
- ✅ Works with **native MSVC** (cl.exe + link.exe)
- ✅ Preserves **debugging capability** (PDB files still work)

### What This Tool Cannot Fix

- ❌ **PDB files remain non-deterministic** (~11% of PDB content varies)
  - PDB files contain thousands of small differences (padding, internal offsets, GUIDs)
  - Microsoft's PDB format has fundamental non-determinism issues
  - Industry solution: Use clang-cl + lld-link instead of native MSVC

- ❌ **Does not work with stripped binaries** (no debug directory to patch)

### Alternative: Use clang-cl + lld-link

For **fully reproducible builds** including PDB files, use LLVM's Windows toolchain:

```bash
clang-cl /O2 /std:c++17 program.cpp /link /DEBUG:FULL /Brepro /TIMESTAMP:1
```

The `/TIMESTAMP:` flag is **only supported by lld-link**, not native MSVC link.exe.

## Technical Details

### PE File Structure

The tool parses the PE file structure to locate and patch:

1. **DOS Header** (offset 0x3C) → PE signature offset
2. **PE Signature** (offset varies) → Verify "PE\0\0"
3. **COFF Header** (after PE sig) → TimeDateStamp at +4
4. **Optional Header** (after COFF) → Contains Data Directories
5. **Data Directory #6** → Debug Directory (RVA + Size)
6. **Debug Directory Entries** → 28-byte structures with timestamps
7. **CODEVIEW RSDS Structure** → GUID at +4, Age at +20
8. **REPRO Hash** → Full hash data

### Why /Brepro Isn't Enough

MSVC's `/Brepro` flag:
- ✅ Removes **some** non-determinism
- ✅ Uses hash-based timestamps instead of wall clock time
- ❌ Still produces **different hashes** for each build
- ❌ GUID remains random
- ❌ Age field increments

This is because `/Brepro` computes a hash of build inputs, but includes random/variable data in that hash.

## Comparison with Alternatives

### vs. ducible

[ducible](https://github.com/jasonwhite/ducible) is an older tool with similar goals:
- ❌ **Unmaintained** (last update 2018)
- ❌ Only patches COFF header timestamp
- ❌ Does not patch Debug Directory timestamps
- ❌ Does not patch GUIDs or Age fields

### vs. clang-cl + lld-link

Using LLVM's toolchain:
- ✅ **Fully reproducible** (including PDB files)
- ✅ Supports `/TIMESTAMP:` flag
- ❌ Not always possible (may need native MSVC for compatibility)

This tool fills the gap when you **must use native MSVC** but still want reproducible .exe files.

## Research and References

The non-determinism of MSVC builds with debug symbols is well-documented:

- **Microsoft PDB Repository Issue #9**: PDB non-determinism issues (GUIDs, padding, uninitialized buffers)
- **Chromium Project**: Uses clang-cl + lld-link specifically for reproducible builds
- **Bazel Team**: Marked `/experimental:deterministic` as "not planned" because "PDBs are not deterministic"
- **Reproducible Builds Mailing List** (Dec 2024): "there is no way to really solve this issue" with MSVC
- **Stack Overflow** (Nov 2024): "No complete solution currently exists for achieving fully reproducible MSVC builds with debug symbols"

## License

Apache License 2.0 - See LICENSE file

## Contributing

Contributions welcome! Please test thoroughly with your build system before submitting PRs.

## Credits

Developed as part of the [ghidra-optimized-stdvector-decompiler](https://github.com/mithro/ghidra-optimized-stdvector-decompiler) project to enable CI verification of demo binaries compiled with multiple MSVC versions.
