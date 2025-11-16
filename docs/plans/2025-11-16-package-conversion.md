# Package Conversion Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Convert `patch_pe_timestamp.py` into a professional PyPI-ready package with comprehensive testing, CI/CD, and documentation.

**Architecture:** Modern uv-first package with src/ layout, zero runtime dependencies, comprehensive testing (unit/integration/property/snapshot), GitHub Actions CI/CD, and ReadTheDocs documentation.

**Tech Stack:** Python 3.8+, uv (package manager), ruff (linting), mypy (type checking), pytest (testing), hypothesis (property testing), Sphinx (docs)

---

## Task 1: Create Project Structure

**Files:**
- Create: `src/msvc_pe_patcher/__init__.py`
- Create: `src/msvc_pe_patcher/__main__.py`
- Create: `src/msvc_pe_patcher/patcher.py`
- Create: `src/msvc_pe_patcher/cli.py`
- Create: `tests/unit/.gitkeep`
- Create: `tests/integration/.gitkeep`
- Create: `tests/property/.gitkeep`
- Create: `tests/snapshots/.gitkeep`
- Create: `tests/fixtures/.gitkeep`

**Step 1: Create directory structure**

```bash
mkdir -p src/msvc_pe_patcher
mkdir -p tests/{unit,integration,property,snapshots,fixtures}
```

**Step 2: Create placeholder files**

```bash
touch src/msvc_pe_patcher/__init__.py
touch src/msvc_pe_patcher/__main__.py
touch src/msvc_pe_patcher/patcher.py
touch src/msvc_pe_patcher/cli.py
touch tests/unit/.gitkeep
touch tests/integration/.gitkeep
touch tests/property/.gitkeep
touch tests/snapshots/.gitkeep
touch tests/fixtures/.gitkeep
```

**Step 3: Verify structure**

Run: `find src tests -type f | sort`
Expected: All files listed in correct hierarchy

**Step 4: Commit**

```bash
git add src/ tests/
git commit -m "feat: create package directory structure"
```

---

## Task 2: Create pyproject.toml Configuration

**Files:**
- Create: `pyproject.toml`

**Step 1: Write pyproject.toml**

Create file with complete configuration:

```toml
[project]
name = "msvc-pe-patcher"
version = "1.0.0"
description = "Normalize PE files for reproducible MSVC++ builds"
readme = "README.md"
requires-python = ">=3.8"
license = {text = "Apache-2.0"}
authors = [
    {name = "Tim Ansell", email = "me@mith.ro"}
]
keywords = ["msvc", "reproducible-builds", "pe", "windows", "compiler", "deterministic"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Topic :: Software Development :: Build Tools",
    "Topic :: Software Development :: Compilers",
    "License :: OSI Approved :: Apache Software License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
]
dependencies = []

[project.scripts]
msvc-pe-patcher = "msvc_pe_patcher.cli:main"

[project.urls]
Homepage = "https://github.com/mithro/msvc-pe-patcher"
Documentation = "https://msvc-pe-patcher.readthedocs.io"
Repository = "https://github.com/mithro/msvc-pe-patcher"
Issues = "https://github.com/mithro/msvc-pe-patcher/issues"
Changelog = "https://github.com/mithro/msvc-pe-patcher/releases"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.uv]
dev-dependencies = [
    "pytest>=8.0",
    "pytest-cov>=4.1",
    "hypothesis>=6.92",
    "ruff>=0.1.0",
    "mypy>=1.8",
]

[tool.ruff]
line-length = 100
target-version = "py38"

[tool.ruff.lint]
select = [
    "E",    # pycodestyle errors
    "F",    # pyflakes
    "I",    # isort
    "N",    # pep8-naming
    "UP",   # pyupgrade
    "B",    # flake8-bugbear
    "A",    # flake8-builtins
    "C4",   # flake8-comprehensions
    "PIE",  # flake8-pie
    "RET",  # flake8-return
    "SIM",  # flake8-simplify
]

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101"]

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = [
    "--cov=msvc_pe_patcher",
    "--cov-report=term-missing",
    "--cov-report=xml",
    "--strict-markers",
    "-v",
]

[tool.mypy]
python_version = "3.8"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_any_generics = true

[tool.coverage.run]
branch = true
source = ["src"]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise AssertionError",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
    "if TYPE_CHECKING:",
]
```

**Step 2: Initialize uv**

Run: `uv sync --all-extras --dev`
Expected: Dependencies installed successfully

**Step 3: Verify configuration**

Run: `uv run ruff --version`
Expected: Ruff version displayed

**Step 4: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "feat: add pyproject.toml with uv configuration"
```

---

## Task 3: Create Package __init__.py

**Files:**
- Modify: `src/msvc_pe_patcher/__init__.py`

**Step 1: Write package metadata**

```python
"""msvc-pe-patcher: Normalize PE files for reproducible MSVC++ builds."""

__version__ = "1.0.0"
__author__ = "Tim Ansell"
__email__ = "me@mith.ro"

from msvc_pe_patcher.patcher import PatchResult, patch_pe_file, validate_pe_file

__all__ = ["patch_pe_file", "validate_pe_file", "PatchResult", "__version__"]
```

**Step 2: Verify imports work**

Run: `uv run python -c "import msvc_pe_patcher; print(msvc_pe_patcher.__version__)"`
Expected: Will fail until we create patcher.py (expected at this stage)

**Step 3: Commit**

```bash
git add src/msvc_pe_patcher/__init__.py
git commit -m "feat: add package __init__.py with metadata"
```

---

## Task 4: Refactor Core Logic into patcher.py

**Files:**
- Create: `src/msvc_pe_patcher/patcher.py`
- Reference: `patch_pe_timestamp.py` (original script)

**Step 1: Create data classes and types**

```python
"""Core PE file patching logic."""

import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class PatchResult:
    """Result of patching operation."""

    success: bool
    patches_applied: int
    errors: List[str] = field(default_factory=list)
    file_path: Optional[Path] = None


@dataclass
class DebugDirectory:
    """Debug directory location information."""

    file_offset: int
    num_entries: int
    size: int
```

**Step 2: Add PE validation function**

```python
def validate_pe_file(path: Path) -> bool:
    """
    Validate that a file is a valid PE executable.

    Args:
        path: Path to file to validate

    Returns:
        True if valid PE file, False otherwise
    """
    if not path.exists():
        return False

    if path.stat().st_size < 0x40:
        return False

    with open(path, "rb") as f:
        data = f.read(0x100)

    # Check DOS header signature
    if data[0:2] != b"MZ":
        return False

    # Get PE offset
    pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]

    if pe_offset + 4 > len(data):
        # Need to read more
        with open(path, "rb") as f:
            data = f.read(pe_offset + 4)

    if len(data) < pe_offset + 4:
        return False

    # Check PE signature
    pe_sig = data[pe_offset : pe_offset + 4]
    return pe_sig == b"PE\x00\x00"
```

**Step 3: Add helper functions (from original script)**

Copy and refactor the internal functions from `patch_pe_timestamp.py`:
- `_find_pe_offset`
- `_patch_coff_header`
- `_find_debug_directory`
- `_patch_debug_entries`

Add type hints and proper error handling:

```python
def _find_pe_offset(data: bytes) -> int:
    """Find PE signature offset from DOS header."""
    if len(data) < 0x40:
        raise ValueError("File too small for DOS header")
    return struct.unpack("<I", data[0x3C:0x40])[0]


def _verify_pe_signature(data: bytes, pe_offset: int) -> None:
    """Verify PE signature at given offset."""
    if len(data) < pe_offset + 4:
        raise ValueError(f"File too small for PE signature at offset {pe_offset}")

    pe_sig = data[pe_offset : pe_offset + 4]
    if pe_sig != b"PE\x00\x00":
        raise ValueError(f"Invalid PE signature: {pe_sig.hex()}")


def _patch_coff_header(
    data: bytearray, pe_offset: int, timestamp: int, verbose: bool = False
) -> int:
    """Patch COFF header timestamp."""
    coff_offset = pe_offset + 4
    timestamp_offset = coff_offset + 4

    if len(data) < timestamp_offset + 4:
        raise ValueError("File too small for COFF header")

    original_timestamp = struct.unpack("<I", data[timestamp_offset : timestamp_offset + 4])[0]
    data[timestamp_offset : timestamp_offset + 4] = struct.pack("<I", timestamp)

    if verbose:
        print(f"  [1/?] COFF header: 0x{original_timestamp:08x} -> 0x{timestamp:08x}")

    return 1


def _find_debug_directory(data: bytes, pe_offset: int) -> Optional[DebugDirectory]:
    """Find debug directory location in PE file."""
    coff_offset = pe_offset + 4

    # Get number of sections and optional header size
    if len(data) < coff_offset + 20:
        return None

    num_sections = struct.unpack("<H", data[coff_offset + 2 : coff_offset + 4])[0]
    opt_header_size = struct.unpack("<H", data[coff_offset + 16 : coff_offset + 18])[0]
    opt_header_offset = coff_offset + 20

    if len(data) < opt_header_offset + 2:
        return None

    # Check PE32+ (64-bit) magic
    magic = struct.unpack("<H", data[opt_header_offset : opt_header_offset + 2])[0]

    if magic != 0x20B:  # PE32+
        return None

    # Data directories start at opt_header_offset + 112 for PE32+
    data_dir_offset = opt_header_offset + 112

    # Debug directory is entry #6
    if len(data) < data_dir_offset + 6 * 8 + 8:
        return None

    debug_dir_rva = struct.unpack("<I", data[data_dir_offset + 6 * 8 : data_dir_offset + 6 * 8 + 4])[0]
    debug_dir_size = struct.unpack("<I", data[data_dir_offset + 6 * 8 + 4 : data_dir_offset + 6 * 8 + 8])[0]

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
            num_entries = debug_dir_size // 28
            return DebugDirectory(file_offset, num_entries, debug_dir_size)

    return None


def _patch_debug_entries(
    data: bytearray, debug_dir: DebugDirectory, timestamp: int, verbose: bool = False
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
        entry_offset = debug_dir.file_offset + j * 28
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
            print(f"  [{patches + 1}/?] Debug {type_name} timestamp: 0x{orig_ts:08x} -> 0x{timestamp:08x}")

        # CODEVIEW: Patch GUID and Age
        if entry_type == 2:
            ptr_to_data = struct.unpack("<I", data[entry_offset + 24 : entry_offset + 28])[0]
            if ptr_to_data > 0 and len(data) >= ptr_to_data + 24:
                cv_sig = struct.unpack("<I", data[ptr_to_data : ptr_to_data + 4])[0]
                if cv_sig == 0x53445352:  # 'RSDS'
                    guid_offset = ptr_to_data + 4
                    age_offset = ptr_to_data + 20

                    orig_guid = data[guid_offset : guid_offset + 16].hex()
                    data[guid_offset : guid_offset + 16] = bytes(16)
                    patches += 1

                    if verbose:
                        print(f"  [{patches + 1}/?] Debug CODEVIEW GUID: {orig_guid} -> {'00' * 16}")

                    orig_age = struct.unpack("<I", data[age_offset : age_offset + 4])[0]
                    data[age_offset : age_offset + 4] = struct.pack("<I", 1)
                    patches += 1

                    if verbose:
                        print(f"  [{patches + 1}/?] Debug CODEVIEW Age: {orig_age} -> 1")

        # REPRO: Patch hash
        if entry_type == 16:
            size_of_data = struct.unpack("<I", data[entry_offset + 16 : entry_offset + 20])[0]
            ptr_to_data = struct.unpack("<I", data[entry_offset + 24 : entry_offset + 28])[0]
            if ptr_to_data > 0 and len(data) >= ptr_to_data + size_of_data:
                orig_hash = data[ptr_to_data : ptr_to_data + size_of_data].hex()[:32]
                data[ptr_to_data : ptr_to_data + size_of_data] = bytes(size_of_data)
                patches += 1

                if verbose:
                    print(f"  [{patches + 1}/?] Debug REPRO hash: {orig_hash}... -> {'00' * size_of_data}")

    return patches
```

**Step 4: Add main patch_pe_file function**

```python
def patch_pe_file(pe_path: Path, timestamp: int = 1, verbose: bool = False) -> PatchResult:
    """
    Patch PE file to normalize timestamps and GUIDs for reproducibility.

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
        result.errors.append(f"File not found: {pe_path}")
        return result

    # Read entire file
    try:
        with open(pe_path, "rb") as f:
            data = bytearray(f.read())
    except Exception as e:
        result.errors.append(f"Failed to read file: {e}")
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
        patches = _patch_coff_header(data, pe_offset, timestamp, verbose)
        result.patches_applied += patches
    except Exception as e:
        result.errors.append(f"Failed to patch COFF header: {e}")
        return result

    # Patch debug directory entries
    debug_dir = _find_debug_directory(data, pe_offset)
    if debug_dir:
        try:
            patches = _patch_debug_entries(data, debug_dir, timestamp, verbose)
            result.patches_applied += patches
        except Exception as e:
            result.errors.append(f"Failed to patch debug entries: {e}")
            # Don't return - COFF header was patched successfully

    # Write back
    try:
        with open(pe_path, "wb") as f:
            f.write(data)
    except Exception as e:
        result.errors.append(f"Failed to write file: {e}")
        return result

    result.success = True
    if verbose:
        print(f"  Total: {result.patches_applied} patch(es) applied to {pe_path.name}")

    return result
```

**Step 5: Verify module imports**

Run: `uv run python -c "from msvc_pe_patcher.patcher import patch_pe_file; print('OK')"`
Expected: "OK"

**Step 6: Commit**

```bash
git add src/msvc_pe_patcher/patcher.py
git commit -m "feat: create core patcher module with type-safe API"
```

---

## Task 5: Create CLI Module

**Files:**
- Create: `src/msvc_pe_patcher/cli.py`

**Step 1: Write CLI implementation**

```python
"""Command-line interface for msvc-pe-patcher."""

import argparse
import sys
from pathlib import Path

from msvc_pe_patcher import __version__
from msvc_pe_patcher.patcher import patch_pe_file


def main() -> int:
    """Entry point for msvc-pe-patcher command."""
    parser = argparse.ArgumentParser(
        prog="msvc-pe-patcher",
        description="Normalize PE files for reproducible MSVC++ builds",
        epilog="""
Examples:
  msvc-pe-patcher program.exe
  msvc-pe-patcher program.exe 1234567890
  msvc-pe-patcher --timestamp 1 program.exe
  msvc-pe-patcher --verbose program.exe
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("pe_file", help="PE file to patch (.exe or .dll)")

    parser.add_argument(
        "timestamp",
        nargs="?",
        type=int,
        default=None,
        help="Timestamp value (default: 1)",
    )

    parser.add_argument(
        "--timestamp",
        dest="timestamp_flag",
        type=int,
        metavar="VALUE",
        help="Timestamp value (explicit flag form)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed patching information",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress output except errors",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Reconcile positional vs flag timestamp
    timestamp = args.timestamp_flag or args.timestamp or 1

    # Validate conflicts
    if args.verbose and args.quiet:
        print("ERROR: Cannot use --verbose and --quiet together", file=sys.stderr)
        return 1

    # Patch the file
    pe_path = Path(args.pe_file)
    result = patch_pe_file(pe_path, timestamp, verbose=args.verbose and not args.quiet)

    # Handle errors
    if not result.success:
        for error in result.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    # Success message (unless quiet)
    if not args.quiet and not args.verbose:
        print(f"Patched {result.patches_applied} field(s) in {pe_path.name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

**Step 2: Create __main__.py**

File: `src/msvc_pe_patcher/__main__.py`

```python
"""Allow running as python -m msvc_pe_patcher."""

import sys

from msvc_pe_patcher.cli import main

if __name__ == "__main__":
    sys.exit(main())
```

**Step 3: Test CLI help**

Run: `uv run python -m msvc_pe_patcher --help`
Expected: Help text displayed

**Step 4: Commit**

```bash
git add src/msvc_pe_patcher/cli.py src/msvc_pe_patcher/__main__.py
git commit -m "feat: add CLI with hybrid argument support"
```

---

## Task 6: Write Unit Tests for Core Logic

**Files:**
- Create: `tests/unit/test_patcher.py`
- Create: `tests/unit/test_helpers.py`

**Step 1: Create test helpers**

File: `tests/unit/test_helpers.py`

```python
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
```

**Step 2: Write unit tests**

File: `tests/unit/test_patcher.py`

```python
"""Unit tests for core patcher module."""

import struct
from pathlib import Path

import pytest

from msvc_pe_patcher.patcher import (
    PatchResult,
    _find_pe_offset,
    _patch_coff_header,
    _verify_pe_signature,
    patch_pe_file,
    validate_pe_file,
)
from tests.unit.test_helpers import create_mock_dos_header, create_mock_pe_file


class TestFindPEOffset:
    """Tests for _find_pe_offset function."""

    def test_valid_dos_header(self) -> None:
        """Test PE offset detection with valid DOS header."""
        data = create_mock_dos_header(pe_offset=0x100)
        assert _find_pe_offset(data) == 0x100

    def test_different_offsets(self) -> None:
        """Test various PE offset values."""
        for offset in [0x80, 0x100, 0x200, 0xF0]:
            data = create_mock_dos_header(pe_offset=offset)
            assert _find_pe_offset(data) == offset

    def test_file_too_small(self) -> None:
        """Test error handling for truncated DOS header."""
        data = bytearray(0x30)  # Too small
        with pytest.raises(ValueError, match="File too small"):
            _find_pe_offset(data)


class TestVerifyPESignature:
    """Tests for _verify_pe_signature function."""

    def test_valid_signature(self) -> None:
        """Test valid PE signature verification."""
        data = create_mock_pe_file()
        _verify_pe_signature(data, pe_offset=0x80)  # Should not raise

    def test_invalid_signature(self) -> None:
        """Test invalid PE signature detection."""
        data = bytearray(0x100)
        data[0x80 : 0x84] = b"XXXX"  # Invalid signature
        with pytest.raises(ValueError, match="Invalid PE signature"):
            _verify_pe_signature(data, pe_offset=0x80)

    def test_file_too_small(self) -> None:
        """Test error when file truncated before PE signature."""
        data = bytearray(0x80)
        with pytest.raises(ValueError, match="File too small"):
            _verify_pe_signature(data, pe_offset=0x80)


class TestPatchCOFFHeader:
    """Tests for _patch_coff_header function."""

    def test_successful_patch(self) -> None:
        """Test COFF header timestamp patching."""
        data = create_mock_pe_file(timestamp=0x12345678)
        pe_offset = 0x80
        coff_offset = pe_offset + 4
        ts_offset = coff_offset + 4

        patches = _patch_coff_header(data, pe_offset, timestamp=42)

        assert patches == 1
        assert struct.unpack("<I", data[ts_offset : ts_offset + 4])[0] == 42

    def test_preserves_other_fields(self) -> None:
        """Test that patching doesn't corrupt adjacent fields."""
        data = create_mock_pe_file()
        pe_offset = 0x80
        coff_offset = pe_offset + 4

        # Store original machine type
        orig_machine = struct.unpack("<H", data[coff_offset : coff_offset + 2])[0]

        _patch_coff_header(data, pe_offset, timestamp=1)

        # Verify machine type unchanged
        new_machine = struct.unpack("<H", data[coff_offset : coff_offset + 2])[0]
        assert new_machine == orig_machine


class TestValidatePEFile:
    """Tests for validate_pe_file function."""

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        """Test validation fails for nonexistent file."""
        assert validate_pe_file(tmp_path / "nonexistent.exe") is False

    def test_valid_pe_file(self, tmp_path: Path) -> None:
        """Test validation succeeds for valid PE file."""
        pe_file = tmp_path / "test.exe"
        pe_file.write_bytes(create_mock_pe_file())
        assert validate_pe_file(pe_file) is True

    def test_file_too_small(self, tmp_path: Path) -> None:
        """Test validation fails for tiny file."""
        pe_file = tmp_path / "tiny.exe"
        pe_file.write_bytes(b"MZ")
        assert validate_pe_file(pe_file) is False

    def test_invalid_dos_signature(self, tmp_path: Path) -> None:
        """Test validation fails without DOS signature."""
        pe_file = tmp_path / "invalid.exe"
        pe_file.write_bytes(b"XX" + b"\x00" * 100)
        assert validate_pe_file(pe_file) is False


class TestPatchPEFile:
    """Tests for main patch_pe_file function."""

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        """Test patching nonexistent file returns error."""
        result = patch_pe_file(tmp_path / "missing.exe")
        assert result.success is False
        assert len(result.errors) > 0
        assert "not found" in result.errors[0].lower()

    def test_successful_patch(self, tmp_path: Path) -> None:
        """Test successful patching of valid PE file."""
        pe_file = tmp_path / "test.exe"
        pe_file.write_bytes(create_mock_pe_file(timestamp=0x12345678))

        result = patch_pe_file(pe_file, timestamp=1)

        assert result.success is True
        assert result.patches_applied >= 1
        assert len(result.errors) == 0

        # Verify timestamp was patched
        data = pe_file.read_bytes()
        ts_offset = 0x80 + 4 + 4
        assert struct.unpack("<I", data[ts_offset : ts_offset + 4])[0] == 1

    def test_custom_timestamp(self, tmp_path: Path) -> None:
        """Test patching with custom timestamp value."""
        pe_file = tmp_path / "test.exe"
        pe_file.write_bytes(create_mock_pe_file())

        result = patch_pe_file(pe_file, timestamp=0xABCDEF00)

        assert result.success is True

        data = pe_file.read_bytes()
        ts_offset = 0x80 + 4 + 4
        assert struct.unpack("<I", data[ts_offset : ts_offset + 4])[0] == 0xABCDEF00

    def test_invalid_pe_file(self, tmp_path: Path) -> None:
        """Test patching invalid PE file returns error."""
        pe_file = tmp_path / "invalid.exe"
        pe_file.write_bytes(b"Not a PE file")

        result = patch_pe_file(pe_file)

        assert result.success is False
        assert len(result.errors) > 0
```

**Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_patcher.py -v`
Expected: Some tests may fail due to missing imports

**Step 4: Fix any import issues**

Ensure `tests/__init__.py` exists (can be empty) and imports work.

**Step 5: Run tests again**

Run: `uv run pytest tests/unit/ -v`
Expected: All tests pass

**Step 6: Commit**

```bash
git add tests/unit/
git commit -m "test: add comprehensive unit tests for patcher module"
```

---

## Task 7: Write Integration Tests with Real PE Files

**Files:**
- Create: `tests/fixtures/README.md`
- Create: `tests/integration/test_real_pe_files.py`

**Step 1: Document test fixtures**

File: `tests/fixtures/README.md`

```markdown
# Test Fixtures

This directory contains sample PE files for integration testing.

## Generating Test Fixtures

Since we cannot commit binary PE files to the repository, you need to generate
test fixtures before running integration tests.

### On Windows with MSVC

```bash
# Simple C program
echo 'int main() { return 0; }' > test.c

# Compile with MSVC 2019+ with debug info and /Brepro
cl.exe /O2 /Zi /std:c11 test.c /link /DEBUG:FULL /Brepro /OUT:msvc2022_x64.exe

# Copy to fixtures
copy msvc2022_x64.exe tests\fixtures\
```

### Using Docker (Cross-platform)

```bash
# Use Wine + MSVC in Docker
docker run --rm -v $(pwd):/work wine-msvc \
  cl.exe /O2 test.c /link /DEBUG:FULL /Brepro
```

### Alternative: Use Existing PE Files

Any PE executable with debug information will work:
- Windows SDK tools (link.exe, cl.exe, etc.)
- Third-party tools compiled with MSVC

## Fixture Verification

After adding a fixture, verify it's a valid PE file:

```bash
file tests/fixtures/your_file.exe
# Should show: "PE32+ executable (console) x86-64, for MS Windows"
```
```

**Step 2: Write integration test (with skip if no fixtures)**

File: `tests/integration/test_real_pe_files.py`

```python
"""Integration tests using real PE files."""

import hashlib
import shutil
from pathlib import Path

import pytest

from msvc_pe_patcher.patcher import patch_pe_file, validate_pe_file

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def get_pe_fixtures() -> list[Path]:
    """Get all PE file fixtures."""
    if not FIXTURES_DIR.exists():
        return []

    return [
        f
        for f in FIXTURES_DIR.iterdir()
        if f.suffix in {".exe", ".dll"} and f.name != "README.md"
    ]


@pytest.mark.skipif(
    len(get_pe_fixtures()) == 0,
    reason="No PE fixtures found. See tests/fixtures/README.md",
)
class TestRealPEFiles:
    """Integration tests with real PE executables."""

    @pytest.mark.parametrize("fixture", get_pe_fixtures(), ids=lambda p: p.name)
    def test_patch_real_pe_file(self, fixture: Path, tmp_path: Path) -> None:
        """Test patching real PE files from various sources."""
        # Copy to temp location
        test_file = tmp_path / fixture.name
        shutil.copy(fixture, test_file)

        # Patch the file
        result = patch_pe_file(test_file, timestamp=1)

        # Verify success
        assert result.success, f"Failed: {result.errors}"
        assert result.patches_applied >= 1, "Expected at least COFF header patch"

        # Verify still valid PE
        assert validate_pe_file(test_file), "Patched file is no longer valid PE"

    @pytest.mark.parametrize("fixture", get_pe_fixtures(), ids=lambda p: p.name)
    def test_patching_is_idempotent(self, fixture: Path, tmp_path: Path) -> None:
        """Test that patching twice produces identical output."""
        test_file = tmp_path / fixture.name
        shutil.copy(fixture, test_file)

        # Patch once
        patch_pe_file(test_file, timestamp=1)
        hash1 = hashlib.sha256(test_file.read_bytes()).hexdigest()

        # Patch again
        patch_pe_file(test_file, timestamp=1)
        hash2 = hashlib.sha256(test_file.read_bytes()).hexdigest()

        # Should be identical
        assert hash1 == hash2, "Patching is not idempotent"

    @pytest.mark.parametrize("fixture", get_pe_fixtures(), ids=lambda p: p.name)
    def test_different_timestamps_produce_different_hashes(
        self, fixture: Path, tmp_path: Path
    ) -> None:
        """Test that different timestamps produce different file hashes."""
        file1 = tmp_path / f"{fixture.stem}_ts1{fixture.suffix}"
        file2 = tmp_path / f"{fixture.stem}_ts2{fixture.suffix}"

        shutil.copy(fixture, file1)
        shutil.copy(fixture, file2)

        patch_pe_file(file1, timestamp=1)
        patch_pe_file(file2, timestamp=2)

        hash1 = hashlib.sha256(file1.read_bytes()).hexdigest()
        hash2 = hashlib.sha256(file2.read_bytes()).hexdigest()

        assert hash1 != hash2, "Different timestamps should produce different hashes"
```

**Step 3: Run integration tests**

Run: `uv run pytest tests/integration/ -v`
Expected: Tests skipped if no fixtures, or pass if fixtures present

**Step 4: Commit**

```bash
git add tests/fixtures/README.md tests/integration/
git commit -m "test: add integration tests for real PE files"
```

---

## Task 8: Write Property-Based Tests

**Files:**
- Create: `tests/property/test_pe_validity.py`

**Step 1: Write property tests**

```python
"""Property-based tests using Hypothesis."""

import hashlib
import shutil
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

from msvc_pe_patcher.patcher import patch_pe_file, validate_pe_file
from tests.unit.test_helpers import create_mock_pe_file


@pytest.fixture
def mock_pe_file(tmp_path: Path) -> Path:
    """Create a mock PE file for testing."""
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(create_mock_pe_file())
    return pe_file


class TestPEValidityProperties:
    """Property-based tests for PE validity."""

    @given(timestamp=st.integers(min_value=0, max_value=2**32 - 1))
    def test_patching_preserves_pe_validity(
        self, mock_pe_file: Path, timestamp: int
    ) -> None:
        """Property: Patched files remain valid PE files."""
        # Create a copy for this test
        test_file = mock_pe_file.parent / f"test_{timestamp}.exe"
        shutil.copy(mock_pe_file, test_file)

        # Patch with random timestamp
        result = patch_pe_file(test_file, timestamp)

        # Should still be valid PE
        assert result.success
        assert validate_pe_file(test_file)

    @given(timestamp=st.integers(min_value=0, max_value=2**32 - 1))
    def test_patching_is_idempotent(self, mock_pe_file: Path, timestamp: int) -> None:
        """Property: Patching twice produces identical output."""
        test_file = mock_pe_file.parent / f"idempotent_{timestamp}.exe"
        shutil.copy(mock_pe_file, test_file)

        # Patch twice
        patch_pe_file(test_file, timestamp)
        hash1 = hashlib.sha256(test_file.read_bytes()).hexdigest()

        patch_pe_file(test_file, timestamp)
        hash2 = hashlib.sha256(test_file.read_bytes()).hexdigest()

        # Hashes must match
        assert hash1 == hash2

    @given(timestamp=st.integers(min_value=0, max_value=2**32 - 1))
    def test_all_timestamps_become_target_value(
        self, mock_pe_file: Path, timestamp: int
    ) -> None:
        """Property: All timestamps in patched file equal the target value."""
        import struct

        test_file = mock_pe_file.parent / f"verify_{timestamp}.exe"
        shutil.copy(mock_pe_file, test_file)

        patch_pe_file(test_file, timestamp)

        # Read back and verify COFF timestamp
        data = test_file.read_bytes()
        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        coff_ts_offset = pe_offset + 4 + 4
        actual_ts = struct.unpack("<I", data[coff_ts_offset : coff_ts_offset + 4])[0]

        assert actual_ts == timestamp
```

**Step 2: Run property tests**

Run: `uv run pytest tests/property/ -v --hypothesis-show-statistics`
Expected: Tests pass, Hypothesis shows statistics

**Step 3: Commit**

```bash
git add tests/property/
git commit -m "test: add property-based tests with Hypothesis"
```

---

## Task 9: Set Up GitHub Actions CI/CD

**Files:**
- Create: `.github/workflows/test.yml`
- Create: `.github/workflows/publish.yml`

**Step 1: Create test workflow**

File: `.github/workflows/test.yml`

```yaml
name: Test & Lint

on:
  push:
    branches: [main, feature/*]
  pull_request:
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.8", "3.9", "3.10", "3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3

      - name: Set up Python ${{ matrix.python-version }}
        run: uv python install ${{ matrix.python-version }}

      - name: Install dependencies
        run: uv sync --all-extras --dev

      - name: Lint with ruff
        run: |
          uv run ruff check src/ tests/
          uv run ruff format --check src/ tests/

      - name: Type check with mypy
        run: uv run mypy src/

      - name: Test with pytest
        run: uv run pytest --cov --cov-report=xml -v

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v4
        if: matrix.python-version == '3.12'
        with:
          files: ./coverage.xml
          fail_ci_if_error: false
```

**Step 2: Create publish workflow**

File: `.github/workflows/publish.yml`

```yaml
name: Publish to PyPI

on:
  push:
    tags:
      - "v*"
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3

      - name: Build package
        run: uv build

      - name: Upload build artifacts
        uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  test-publish:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: testpypi
      url: https://test.pypi.org/p/msvc-pe-patcher

    permissions:
      id-token: write

    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/

      - name: Publish to TestPyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          repository-url: https://test.pypi.org/legacy/

  production-publish:
    needs: test-publish
    runs-on: ubuntu-latest
    environment:
      name: pypi
      url: https://pypi.org/p/msvc-pe-patcher

    permissions:
      id-token: write

    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: dist/*
```

**Step 3: Verify workflow syntax**

Run: `uv run python -c "import yaml; yaml.safe_load(open('.github/workflows/test.yml'))"`
Expected: No errors (requires pyyaml: `uv pip install pyyaml`)

**Step 4: Commit**

```bash
git add .github/workflows/
git commit -m "ci: add GitHub Actions for testing and publishing"
```

---

## Task 10: Set Up ReadTheDocs Configuration

**Files:**
- Create: `.readthedocs.yml`
- Create: `docs/requirements.txt`
- Create: `docs/source/conf.py`
- Create: `docs/source/index.rst`
- Create: `docs/source/user-guide.rst`
- Create: `docs/source/developer-guide.rst`
- Create: `docs/source/technical-details.rst`

**Step 1: Create ReadTheDocs config**

File: `.readthedocs.yml`

```yaml
version: 2

build:
  os: ubuntu-22.04
  tools:
    python: "3.12"

sphinx:
  configuration: docs/source/conf.py
  fail_on_warning: false

python:
  install:
    - requirements: docs/requirements.txt
    - method: pip
      path: .
```

**Step 2: Create docs requirements**

File: `docs/requirements.txt`

```
sphinx>=7.0
sphinx-rtd-theme>=2.0
```

**Step 3: Create Sphinx config**

File: `docs/source/conf.py`

```python
"""Sphinx configuration for msvc-pe-patcher documentation."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Project information
project = "msvc-pe-patcher"
copyright = "2025, Tim Ansell"
author = "Tim Ansell"

# Get version from package
from msvc_pe_patcher import __version__

release = __version__

# Extensions
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
]

# Theme
html_theme = "sphinx_rtd_theme"

# HTML options
html_static_path = []
templates_path = []

# Napoleon settings (for Google/NumPy docstrings)
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
```

**Step 4: Create index page**

File: `docs/source/index.rst`

```rst
msvc-pe-patcher Documentation
==============================

**Normalize PE files for reproducible MSVC++ builds**

``msvc-pe-patcher`` is a Python tool that patches Windows PE (Portable Executable)
files to make MSVC builds reproducible by normalizing timestamps, GUIDs, and other
non-deterministic debug metadata.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   user-guide
   developer-guide
   technical-details

Quick Start
-----------

Install from PyPI:

.. code-block:: bash

   pip install msvc-pe-patcher

Patch a PE file:

.. code-block:: bash

   msvc-pe-patcher program.exe

Features
--------

* **Zero Dependencies** - Uses only Python standard library
* **Comprehensive Patching** - Patches all 8 non-deterministic fields
* **Type-Safe API** - Full mypy strict mode compliance
* **Well-Tested** - Unit, integration, property-based, and snapshot tests
* **Fast** - Processes files in milliseconds

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
```

**Step 5: Create user guide**

File: `docs/source/user-guide.rst`

```rst
User Guide
==========

Installation
------------

From PyPI
~~~~~~~~~

.. code-block:: bash

   pip install msvc-pe-patcher

From Source
~~~~~~~~~~~

.. code-block:: bash

   git clone https://github.com/mithro/msvc-pe-patcher.git
   cd msvc-pe-patcher
   pip install .

Using uv
~~~~~~~~

.. code-block:: bash

   uv pip install msvc-pe-patcher

Basic Usage
-----------

Simple Patching
~~~~~~~~~~~~~~~

Patch a PE file with default timestamp (1):

.. code-block:: bash

   msvc-pe-patcher program.exe

Custom Timestamp
~~~~~~~~~~~~~~~~

Use a specific Unix timestamp:

.. code-block:: bash

   msvc-pe-patcher program.exe 1234567890

Or using explicit flag:

.. code-block:: bash

   msvc-pe-patcher --timestamp 1234567890 program.exe

Verbose Output
~~~~~~~~~~~~~~

Show detailed information about each patched field:

.. code-block:: bash

   msvc-pe-patcher --verbose program.exe

Quiet Mode
~~~~~~~~~~

Suppress output except errors:

.. code-block:: bash

   msvc-pe-patcher --quiet program.exe

Integration Examples
--------------------

Makefile
~~~~~~~~

.. code-block:: makefile

   program.exe: program.cpp
       cl.exe /O2 /Zi program.cpp /link /DEBUG:FULL /Brepro
       msvc-pe-patcher program.exe 1

GitHub Actions
~~~~~~~~~~~~~~

.. code-block:: yaml

   - name: Build and normalize
     run: |
       cl.exe /O2 program.cpp /link /DEBUG:FULL /Brepro
       msvc-pe-patcher program.exe 1

   - name: Verify reproducibility
     run: |
       sha256sum program.exe > checksum.txt
       git diff --exit-code checksum.txt

Troubleshooting
---------------

File Not Found
~~~~~~~~~~~~~~

**Error:** ``ERROR: File not found: program.exe``

**Solution:** Ensure the file path is correct and the file exists.

Not a Valid PE File
~~~~~~~~~~~~~~~~~~~

**Error:** ``ERROR: Not a valid PE file``

**Solution:** Ensure you're patching a Windows PE executable (.exe) or DLL (.dll),
not a different file type.

Permission Denied
~~~~~~~~~~~~~~~~~

**Error:** ``ERROR: Failed to write file: Permission denied``

**Solution:** Ensure you have write permissions for the file. On Windows, the file
may be locked if it's currently running.
```

**Step 6: Create developer guide**

File: `docs/source/developer-guide.rst`

```rst
Developer Guide
===============

Development Setup
-----------------

Prerequisites
~~~~~~~~~~~~~

* Python 3.8 or higher
* uv (recommended) or pip
* Git

Clone Repository
~~~~~~~~~~~~~~~~

.. code-block:: bash

   git clone https://github.com/mithro/msvc-pe-patcher.git
   cd msvc-pe-patcher

Install Development Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using uv (recommended):

.. code-block:: bash

   uv sync --all-extras --dev

Using pip:

.. code-block:: bash

   pip install -e ".[dev]"

Running Tests
-------------

All Tests
~~~~~~~~~

.. code-block:: bash

   uv run pytest

With Coverage
~~~~~~~~~~~~~

.. code-block:: bash

   uv run pytest --cov --cov-report=html

Specific Test Types
~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Unit tests only (fast)
   uv run pytest tests/unit/

   # Integration tests (requires fixtures)
   uv run pytest tests/integration/

   # Property-based tests
   uv run pytest tests/property/

Code Quality
------------

Linting
~~~~~~~

.. code-block:: bash

   uv run ruff check src/ tests/

Auto-Fix
~~~~~~~~

.. code-block:: bash

   uv run ruff check --fix src/ tests/

Formatting
~~~~~~~~~~

.. code-block:: bash

   uv run ruff format src/ tests/

Type Checking
~~~~~~~~~~~~~

.. code-block:: bash

   uv run mypy src/

Project Architecture
--------------------

Directory Structure
~~~~~~~~~~~~~~~~~~~

::

   src/msvc_pe_patcher/
   ├── __init__.py       # Package metadata
   ├── __main__.py       # CLI entry point
   ├── cli.py            # Argument parsing
   └── patcher.py        # Core patching logic

   tests/
   ├── unit/             # Fast unit tests
   ├── integration/      # Tests with real PE files
   ├── property/         # Hypothesis property tests
   └── fixtures/         # Sample PE files

Module Overview
~~~~~~~~~~~~~~~

**patcher.py**
  Core PE manipulation logic. Contains functions for finding PE offsets,
  verifying signatures, and patching timestamps/GUIDs.

**cli.py**
  Command-line interface using argparse. Supports both positional and
  flag-based arguments.

Contributing
------------

Workflow
~~~~~~~~

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

Code Style
~~~~~~~~~~

* Follow PEP 8
* Use type hints (mypy strict mode)
* Write docstrings for all public functions
* Keep functions small and focused

Testing Requirements
~~~~~~~~~~~~~~~~~~~~

* All new code must have tests
* Maintain 95%+ code coverage
* Property tests for invariants
* Integration tests for real-world scenarios

Release Process
---------------

Version Bumping
~~~~~~~~~~~~~~~

1. Update version in ``src/msvc_pe_patcher/__init__.py``
2. Update version in ``pyproject.toml``
3. Commit: ``git commit -m "chore: bump version to X.Y.Z"``

Tagging
~~~~~~~

.. code-block:: bash

   git tag -a vX.Y.Z -m "Release X.Y.Z"
   git push origin vX.Y.Z

Publishing
~~~~~~~~~~

GitHub Actions automatically publishes to TestPyPI and PyPI when you push a tag.

1. Push tag triggers build
2. Package published to TestPyPI
3. Manual approval required
4. Package published to PyPI
5. GitHub Release created
```

**Step 7: Create technical details**

File: `docs/source/technical-details.rst`

```rst
Technical Details
=================

The Reproducibility Problem
---------------------------

MSVC++ builds are not reproducible even with ``/Brepro`` because:

1. **COFF Header Timestamp** - Build timestamp in PE header
2. **Debug Directory Timestamps** - 4 separate timestamps
3. **CODEVIEW GUID** - Random GUID linking .exe to .pdb
4. **CODEVIEW Age** - Incremental counter
5. **REPRO Hash** - Contains GUID and timestamps

This makes binary verification impossible in CI.

PE File Format
--------------

Structure Overview
~~~~~~~~~~~~~~~~~~

1. **DOS Header** (offset 0x00)
2. **PE Signature** (offset varies)
3. **COFF Header** (after PE signature)
4. **Optional Header** (after COFF)
5. **Section Table** (after optional header)
6. **Debug Directory** (RVA in optional header)

Fields Patched
~~~~~~~~~~~~~~

1. COFF Header TimeDateStamp (4 bytes at COFF+4)
2. Debug CODEVIEW Timestamp (4 bytes)
3. Debug CODEVIEW GUID (16 bytes)
4. Debug CODEVIEW Age (4 bytes)
5. Debug VC_FEATURE Timestamp (4 bytes)
6. Debug POGO Timestamp (4 bytes)
7. Debug REPRO Timestamp (4 bytes)
8. Debug REPRO Hash (36 bytes)

Algorithm
---------

High-Level Flow
~~~~~~~~~~~~~~~

1. Read entire PE file into memory
2. Find PE signature offset from DOS header
3. Verify PE signature
4. Patch COFF header timestamp
5. Find debug directory (RVA to file offset)
6. Iterate debug entries, patch timestamps
7. For CODEVIEW: patch GUID and Age
8. For REPRO: patch entire hash
9. Write modified file back

Offset Calculations
~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   DOS Header[0x3C:0x40] -> PE offset
   PE offset + 0 -> "PE\0\0" signature
   PE offset + 4 -> COFF header start
   COFF offset + 4 -> TimeDateStamp

   COFF offset + 20 -> Optional header start
   Optional offset + 112 -> Data directories (PE32+)
   Data directory[6] -> Debug directory RVA

   Convert RVA to file offset via section table
   Debug directory entries: 28 bytes each
   Entry offset + 4 -> Timestamp
   Entry offset + 12 -> Type
   Entry offset + 24 -> Pointer to data

Comparison with Alternatives
-----------------------------

ducible
~~~~~~~

* ❌ Unmaintained (last update 2018)
* ❌ Only patches COFF timestamp
* ❌ Misses debug directory fields

clang-cl + lld-link
~~~~~~~~~~~~~~~~~~~

* ✅ Fully reproducible (including PDBs)
* ✅ Supports ``/TIMESTAMP:`` flag
* ❌ Requires switching from MSVC toolchain

msvc-pe-patcher
~~~~~~~~~~~~~~~

* ✅ Works with native MSVC
* ✅ Patches all 8 fields
* ✅ Zero dependencies
* ❌ PDB files remain non-deterministic

Limitations
-----------

What This Fixes
~~~~~~~~~~~~~~~

* ✅ PE executables (.exe, .dll)
* ✅ Works with any MSVC version
* ✅ Preserves debugging capability

What This Cannot Fix
~~~~~~~~~~~~~~~~~~~~~

* ❌ PDB files (~11% content varies)
* ❌ Stripped binaries (no debug directory)

References
----------

* `Microsoft PE/COFF Specification <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>`_
* `Reproducible Builds Project <https://reproducible-builds.org/>`_
* `MSVC /Brepro Documentation <https://learn.microsoft.com/en-us/cpp/build/reference/brepro-reproducible-build>`_
```

**Step 8: Test documentation build**

Run: `cd docs && uv pip install -r requirements.txt && uv run sphinx-build -b html source build`
Expected: Documentation builds successfully

**Step 9: Commit**

```bash
git add .readthedocs.yml docs/
git commit -m "docs: add comprehensive ReadTheDocs documentation"
```

---

## Task 11: Update README for Package

**Files:**
- Modify: `README.md`

**Step 1: Update README with package information**

Update the installation section:

```markdown
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

```python
from pathlib import Path
from msvc_pe_patcher import patch_pe_file

result = patch_pe_file(Path("program.exe"), timestamp=1, verbose=True)
if result.success:
    print(f"Patched {result.patches_applied} fields")
else:
    print(f"Errors: {result.errors}")
```
```

**Step 2: Add documentation badge**

Add after title:

```markdown
[![Documentation](https://readthedocs.org/projects/msvc-pe-patcher/badge/?version=latest)](https://msvc-pe-patcher.readthedocs.io/en/latest/)
[![PyPI](https://img.shields.io/pypi/v/msvc-pe-patcher.svg)](https://pypi.org/project/msvc-pe-patcher/)
[![Python Version](https://img.shields.io/pypi/pyversions/msvc-pe-patcher.svg)](https://pypi.org/project/msvc-pe-patcher/)
[![Tests](https://github.com/mithro/msvc-pe-patcher/workflows/Test%20%26%20Lint/badge.svg)](https://github.com/mithro/msvc-pe-patcher/actions)
```

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update README for package distribution"
```

---

## Task 12: Final Verification and Testing

**Files:**
- Run all tests
- Verify package builds
- Test installation

**Step 1: Run complete test suite**

Run: `uv run pytest -v --cov --cov-report=term-missing`
Expected: All tests pass, coverage ≥95%

**Step 2: Run linting**

Run: `uv run ruff check src/ tests/`
Expected: No errors

**Step 3: Run type checking**

Run: `uv run mypy src/`
Expected: No errors

**Step 4: Build package**

Run: `uv build`
Expected: dist/ directory created with .whl and .tar.gz

**Step 5: Test local installation**

Run:
```bash
uv venv test-install
source test-install/bin/activate  # or test-install\Scripts\activate on Windows
uv pip install dist/*.whl
msvc-pe-patcher --version
deactivate
rm -rf test-install
```
Expected: Package installs and command works

**Step 6: Verify package structure**

Run: `unzip -l dist/*.whl | grep msvc_pe_patcher`
Expected: All source files present in wheel

**Step 7: Final commit**

```bash
git status
git add .
git commit -m "chore: final verification and package build"
```

---

## Success Criteria

After completing all tasks:

- ✅ Package installable via `pip install msvc-pe-patcher`
- ✅ CLI command `msvc-pe-patcher` works
- ✅ All tests pass (unit, integration, property)
- ✅ Test coverage ≥95%
- ✅ Ruff linting passes
- ✅ Mypy strict mode passes
- ✅ Documentation builds on ReadTheDocs
- ✅ GitHub Actions CI configured
- ✅ Package builds successfully
- ✅ Zero runtime dependencies

## Next Steps

1. **Push to GitHub:**
   ```bash
   git push origin feature/package-conversion
   ```

2. **Create Pull Request:**
   - Open PR from `feature/package-conversion` to `main`
   - GitHub Actions will run automatically

3. **Merge and Tag:**
   ```bash
   git checkout main
   git merge feature/package-conversion
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin main --tags
   ```

4. **Monitor Publishing:**
   - Watch GitHub Actions publish to TestPyPI
   - Test: `pip install --index-url https://test.pypi.org/simple/ msvc-pe-patcher`
   - Approve production PyPI deployment
   - Verify on https://pypi.org/project/msvc-pe-patcher/

5. **Configure ReadTheDocs:**
   - Import project at readthedocs.org
   - Connect to GitHub repository
   - Documentation builds automatically on push

## Maintenance

- **Bug Fixes:** Create issues on GitHub
- **Feature Requests:** Discuss in issues before implementing
- **Security:** Report privately to me@mith.ro
- **Releases:** Follow semantic versioning (X.Y.Z)
