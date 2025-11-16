"""Property-based tests using Hypothesis."""

import hashlib
import struct
import tempfile
from pathlib import Path

from hypothesis import given, strategies as st

from msvc_pe_patcher.patcher import patch_pe_file, validate_pe_file
from tests.unit.test_helpers import create_mock_pe_file


class TestPEValidityProperties:
    """Property-based tests for PE validity."""

    @given(timestamp=st.integers(min_value=0, max_value=2**32 - 1))
    def test_patching_preserves_pe_validity(self, timestamp: int) -> None:
        """Property: Patched files remain valid PE files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test PE file
            test_file = Path(tmpdir) / f"test_{timestamp}.exe"
            test_file.write_bytes(create_mock_pe_file())

            # Patch with random timestamp
            result = patch_pe_file(test_file, timestamp)

            # Should still be valid PE
            assert result.success
            assert validate_pe_file(test_file)

    @given(timestamp=st.integers(min_value=0, max_value=2**32 - 1))
    def test_patching_is_idempotent(self, timestamp: int) -> None:
        """Property: Patching twice produces identical output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / f"idempotent_{timestamp}.exe"
            test_file.write_bytes(create_mock_pe_file())

            # Patch twice
            patch_pe_file(test_file, timestamp)
            hash1 = hashlib.sha256(test_file.read_bytes()).hexdigest()

            patch_pe_file(test_file, timestamp)
            hash2 = hashlib.sha256(test_file.read_bytes()).hexdigest()

            # Hashes must match
            assert hash1 == hash2

    @given(timestamp=st.integers(min_value=0, max_value=2**32 - 1))
    def test_all_timestamps_become_target_value(self, timestamp: int) -> None:
        """Property: All timestamps in patched file equal the target value."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / f"verify_{timestamp}.exe"
            test_file.write_bytes(create_mock_pe_file())

            patch_pe_file(test_file, timestamp)

            # Read back and verify COFF timestamp
            data = test_file.read_bytes()
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
            coff_ts_offset = pe_offset + 4 + 4
            actual_ts = struct.unpack("<I", data[coff_ts_offset : coff_ts_offset + 4])[0]

            assert actual_ts == timestamp
