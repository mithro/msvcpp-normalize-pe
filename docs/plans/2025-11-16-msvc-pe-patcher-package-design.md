# msvc-pe-patcher Package Design

**Date:** 2025-11-16
**Status:** Approved
**Author:** Design Collaboration

## Executive Summary

This document describes the transformation of `patch_pe_timestamp.py` from a standalone script into a professional Python package (`msvc-pe-patcher`) suitable for PyPI distribution with comprehensive testing, CI/CD, and documentation.

## Requirements

### Functional Requirements
- **Package Type**: Installable pip package (`pip install msvc-pe-patcher`)
- **Distribution**: PyPI (production) + TestPyPI (validation)
- **Scope**: Keep current functionality only (YAGNI principle)
- **CLI**: Hybrid approach - simple positional args + modern flags
- **Dependencies**: Zero runtime dependencies (stdlib only)

### Quality Requirements
- **Testing**: All four types
  - Unit tests (mocked file I/O, fast)
  - Integration tests (real PE files from different MSVC versions)
  - Property-based tests (Hypothesis for invariant checking)
  - Snapshot/regression tests (byte-for-byte reproducibility)
- **Coverage**: 95%+ line coverage, 100% of patching logic
- **Type Safety**: Full mypy strict mode compliance
- **Code Quality**: Ruff linting with strict rule set

### Documentation Requirements
- **User Guide**: Installation, usage, examples, troubleshooting
- **Developer Guide**: Contributing, architecture, development setup
- **Technical Deep-Dive**: PE format, patching algorithm, comparisons
- **Hosting**: ReadTheDocs with Sphinx

### Infrastructure Requirements
- **Build System**: uv-first approach (aligns with project preferences)
- **CI/CD**: GitHub Actions with ruff, mypy, pytest
- **Tooling**: ruff (lint/format), mypy (types), pytest (tests)

## Architecture

### Chosen Approach: Modern uv-first Package

Selected over traditional setuptools and Hatch approaches because:
- Aligns with project-wide uv preference (see CLAUDE.md)
- Fastest dependency resolution and installation
- Modern PEP 621 compliant
- Single pyproject.toml for all configuration

## Project Structure

```
msvc-pe-patcher/
├── src/
│   └── msvc_pe_patcher/
│       ├── __init__.py          # Package metadata, version
│       ├── __main__.py          # Entry point for 'python -m msvc_pe_patcher'
│       ├── cli.py               # CLI implementation (~150 lines)
│       └── patcher.py           # Core patching logic (from current script)
├── tests/
│   ├── unit/                    # Fast unit tests (mocked I/O)
│   │   └── test_patcher.py
│   ├── integration/             # Tests with real PE files
│   │   └── test_real_pe_files.py
│   ├── property/                # Hypothesis property-based tests
│   │   └── test_pe_validity.py
│   ├── snapshots/               # Regression test snapshots
│   │   └── test_reproducibility.py
│   └── fixtures/                # Sample .exe/.dll files
│       ├── msvc2019_x64.exe
│       ├── msvc2022_x64.exe
│       ├── msvc2019_x86.dll
│       └── README.md            # Documents fixture origins
├── docs/
│   ├── source/                  # Sphinx source files
│   │   ├── conf.py              # Sphinx configuration
│   │   ├── index.rst            # Landing page
│   │   ├── user-guide.rst       # Installation, usage, examples
│   │   ├── developer-guide.rst  # Contributing, development setup
│   │   └── technical-details.rst # PE format deep-dive
│   └── requirements.txt         # Sphinx + theme dependencies
├── .github/
│   └── workflows/
│       ├── test.yml             # CI: ruff, mypy, pytest
│       ├── docs.yml             # Build docs on PR
│       └── publish.yml          # Publish to TestPyPI → PyPI
├── pyproject.toml               # Single source of truth
├── README.md                    # GitHub landing page
├── LICENSE                      # Apache 2.0 (existing)
├── .gitignore
└── .readthedocs.yml             # ReadTheDocs configuration
```

### Key Architectural Decisions

1. **src/ layout**: Better import isolation, prevents accidental local imports during testing
2. **Separate CLI from core logic**: `cli.py` for argument parsing, `patcher.py` for PE manipulation
3. **Zero dependencies**: Keeps package lightweight, reduces supply chain risk
4. **Test organization by type**: Clear separation makes it easy to run fast tests vs slow tests

## Component Design

### 1. Core Patching Logic (`patcher.py`)

Refactored from current `patch_pe_timestamp.py`:

```python
# Public API
def patch_pe_file(path: Path, timestamp: int = 1) -> PatchResult
def validate_pe_file(path: Path) -> bool

# Internal functions (well-tested)
def _find_pe_offset(data: bytes) -> int
def _patch_coff_header(data: bytearray, pe_offset: int, timestamp: int) -> int
def _find_debug_directory(data: bytes, pe_offset: int) -> Optional[DebugDirectory]
def _patch_debug_entries(data: bytearray, debug_dir: DebugDirectory, timestamp: int) -> int
def _patch_codeview_guid(data: bytearray, codeview_offset: int) -> None
def _patch_repro_hash(data: bytearray, repro_offset: int, size: int) -> None

# Data classes
@dataclass
class PatchResult:
    success: bool
    patches_applied: int
    errors: List[str]

@dataclass
class DebugDirectory:
    file_offset: int
    num_entries: int
```

Key changes from original:
- Type hints throughout (mypy strict compliance)
- Dataclasses for structured return values
- Separated parsing from patching for testability
- Internal functions use `_` prefix convention

### 2. CLI Implementation (`cli.py`)

Hybrid argument parsing supporting both styles:

```python
def main() -> int:
    """Entry point for msvc-pe-patcher command."""
    parser = argparse.ArgumentParser(
        description="Normalize PE files for reproducible MSVC++ builds",
        epilog="Examples:\n"
               "  msvc-pe-patcher program.exe\n"
               "  msvc-pe-patcher program.exe 1234567890\n"
               "  msvc-pe-patcher --timestamp 1 program.exe\n",
    )

    parser.add_argument("pe_file", help="PE file to patch (.exe or .dll)")
    parser.add_argument("timestamp", nargs="?", type=int, default=None,
                        help="Timestamp value (default: 1)")
    parser.add_argument("--timestamp", dest="timestamp_flag", type=int,
                        help="Timestamp value (explicit flag)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed patching information")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress output except errors")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview changes without writing")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # Reconcile positional vs flag timestamp
    timestamp = args.timestamp_flag or args.timestamp or 1

    result = patch_pe_file(Path(args.pe_file), timestamp)

    if not args.quiet:
        print_result(result, verbose=args.verbose)

    return 0 if result.success else 1
```

### 3. Testing Strategy

#### Unit Tests (`tests/unit/test_patcher.py`)
```python
def test_find_pe_offset_valid():
    """Test PE offset detection with valid DOS header."""
    data = create_mock_dos_header(pe_offset=0x100)
    assert _find_pe_offset(data) == 0x100

def test_patch_coff_header_success():
    """Test COFF header timestamp patching."""
    data = create_mock_pe_file()
    patches = _patch_coff_header(data, pe_offset=0x80, timestamp=42)
    assert patches == 1
    assert struct.unpack('<I', data[0x84:0x88])[0] == 42
```

#### Integration Tests (`tests/integration/test_real_pe_files.py`)
```python
@pytest.mark.parametrize("fixture", [
    "msvc2019_x64.exe",
    "msvc2022_x64.exe",
    "msvc2019_x86.dll",
])
def test_patch_real_pe_file(fixture, tmp_path):
    """Test patching real PE files from various MSVC versions."""
    pe_file = FIXTURES_DIR / fixture
    test_file = tmp_path / fixture
    shutil.copy(pe_file, test_file)

    result = patch_pe_file(test_file, timestamp=1)

    assert result.success
    assert result.patches_applied >= 1  # At minimum COFF header
    assert validate_pe_file(test_file)  # Still valid after patching
```

#### Property-Based Tests (`tests/property/test_pe_validity.py`)
```python
from hypothesis import given, strategies as st

@given(timestamp=st.integers(min_value=0, max_value=2**32-1))
def test_patching_preserves_pe_validity(timestamp):
    """Property: Patched files remain valid PE files."""
    pe_file = get_valid_pe_fixture()
    patch_pe_file(pe_file, timestamp)
    assert validate_pe_file(pe_file)

@given(timestamp=st.integers(min_value=0, max_value=2**32-1))
def test_patching_is_idempotent(timestamp):
    """Property: Patching twice produces identical output."""
    pe_file = get_valid_pe_fixture()

    patch_pe_file(pe_file, timestamp)
    hash1 = hashlib.sha256(pe_file.read_bytes()).hexdigest()

    patch_pe_file(pe_file, timestamp)
    hash2 = hashlib.sha256(pe_file.read_bytes()).hexdigest()

    assert hash1 == hash2
```

#### Snapshot Tests (`tests/snapshots/test_reproducibility.py`)
```python
def test_reproducible_output(snapshot):
    """Test byte-for-byte reproducibility."""
    pe_file = get_fixture("msvc2022_x64.exe")
    patch_pe_file(pe_file, timestamp=1)

    patched_bytes = pe_file.read_bytes()
    snapshot.assert_match(patched_bytes, "msvc2022_x64_patched.exe")
```

## CI/CD Pipeline

### Workflow 1: Test & Lint (`.github/workflows/test.yml`)

```yaml
name: Test & Lint

on:
  push:
    branches: [main]
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
        uses: astral-sh/setup-uv@v1

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
        run: uv run pytest --cov --cov-report=xml

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml
```

### Workflow 2: Documentation (`.github/workflows/docs.yml`)

```yaml
name: Documentation

on:
  push:
    branches: [main]
  pull_request:

jobs:
  build-docs:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v1

      - name: Install dependencies
        run: uv pip install -r docs/requirements.txt

      - name: Build docs
        run: |
          cd docs
          uv run sphinx-build -b html source build/html

      - name: Upload docs artifact
        uses: actions/upload-artifact@v3
        with:
          name: documentation
          path: docs/build/html
```

### Workflow 3: Publish (`.github/workflows/publish.yml`)

```yaml
name: Publish to PyPI

on:
  push:
    tags:
      - 'v*'

jobs:
  test-publish:
    runs-on: ubuntu-latest
    environment:
      name: testpypi
      url: https://test.pypi.org/p/msvc-pe-patcher

    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v1

      - name: Build package
        run: uv build

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

    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v1

      - name: Build package
        run: uv build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          generate_release_notes: true
```

## Documentation Structure

### ReadTheDocs Configuration (`.readthedocs.yml`)

```yaml
version: 2

build:
  os: ubuntu-22.04
  tools:
    python: "3.12"

sphinx:
  configuration: docs/source/conf.py

python:
  install:
    - requirements: docs/requirements.txt
    - method: pip
      path: .
```

### Documentation Sections

#### User Guide (`docs/source/user-guide.rst`)
- Installation (pip, uv, from source)
- Quick start examples
- CLI reference with all flags
- Integration examples (Makefile, GitHub Actions, batch scripts)
- Troubleshooting common issues

#### Developer Guide (`docs/source/developer-guide.rst`)
- Development environment setup with uv
- Running tests (all types individually)
- Code organization and architecture
- Contributing guidelines and PR process
- Release process (TestPyPI → PyPI)

#### Technical Details (`docs/source/technical-details.rst`)
- The reproducibility problem (why /Brepro isn't enough)
- PE file format primer with diagrams
- Detailed breakdown of 8 patched fields
- Algorithm walkthrough with offset calculations
- Comparison with alternatives (ducible, clang-cl)
- Limitations (PDB files remain non-deterministic)
- References and research links

## Package Configuration

### pyproject.toml (Complete)

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
dependencies = []  # Zero runtime dependencies

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
    "sphinx>=7.0",
    "sphinx-rtd-theme>=2.0",
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
"tests/*" = ["S101"]  # Allow assert in tests

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

## Migration Strategy

### Phase 1: Project Structure Setup
1. Create directory structure (`src/`, `tests/`, `docs/`)
2. Write `pyproject.toml` with uv configuration
3. Create `.github/workflows/` with test, docs, publish workflows
4. Add `.readthedocs.yml` configuration

### Phase 2: Code Refactoring
1. Split current script into `patcher.py` (core) and `cli.py` (interface)
2. Add type hints throughout (mypy strict compliance)
3. Refactor functions for testability (separate parsing from mutation)
4. Create `__init__.py` and `__main__.py` entry points

### Phase 3: Testing Implementation
1. Write unit tests (target: 95% coverage)
2. Create test fixtures (sample PE files)
3. Implement integration tests
4. Add property-based tests with Hypothesis
5. Create snapshot tests for reproducibility verification

### Phase 4: Documentation
1. Write Sphinx configuration
2. Create user guide with examples
3. Write developer guide with contribution workflow
4. Write technical deep-dive
5. Test local doc build
6. Connect ReadTheDocs

### Phase 5: CI/CD Setup
1. Configure GitHub Actions workflows
2. Set up Codecov integration
3. Configure PyPI trusted publishing
4. Test TestPyPI publication

### Phase 6: Release
1. Publish v1.0.0 to TestPyPI
2. Test installation from TestPyPI
3. Publish to production PyPI
4. Create GitHub release with notes
5. Announce on relevant channels

## Success Criteria

- ✅ Package installable via `pip install msvc-pe-patcher`
- ✅ All tests pass on Python 3.8-3.12
- ✅ Test coverage ≥95%
- ✅ mypy strict mode passes with no errors
- ✅ ruff linting passes with configured rules
- ✅ Documentation builds successfully on ReadTheDocs
- ✅ CI/CD pipeline fully automated
- ✅ Reproducibility tests confirm byte-for-byte identical output
- ✅ Zero runtime dependencies (stdlib only)
- ✅ Backward compatible CLI (existing commands still work)

## Future Enhancements (Out of Scope)

These are explicitly deferred to maintain YAGNI principle:
- Batch processing multiple files
- Verification mode (check if already normalized)
- Library API for programmatic use
- GUI interface
- PDB file normalization (fundamentally difficult with MSVC)
- Support for non-PE formats

## References

- **PEP 621**: Storing project metadata in pyproject.toml
- **uv Documentation**: https://github.com/astral-sh/uv
- **Hypothesis Documentation**: Property-based testing guide
- **ReadTheDocs**: Sphinx integration guide
- **PyPI Trusted Publishing**: GitHub Actions setup
- **Microsoft PE/COFF Specification**: File format reference
