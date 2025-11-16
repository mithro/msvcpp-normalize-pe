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
