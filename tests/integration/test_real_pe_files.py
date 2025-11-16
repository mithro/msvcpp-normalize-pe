"""Integration tests using real PE files."""

import hashlib
import shutil
from pathlib import Path
from typing import List

import pytest

from msvcpp_normalize_pe.patcher import patch_pe_file, validate_pe_file

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def get_pe_fixtures() -> List[Path]:
    """Get all PE file fixtures."""
    if not FIXTURES_DIR.exists():
        return []

    return [
        f for f in FIXTURES_DIR.iterdir() if f.suffix in {".exe", ".dll"} and f.name != "README.md"
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
