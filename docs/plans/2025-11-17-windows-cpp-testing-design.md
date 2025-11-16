# Windows C++ Compilation and Testing Design

**Date**: 2025-11-17
**Status**: Approved
**Author**: Claude Code (with Tim Ansell)

## Overview

This design document describes a comprehensive Windows-based C++ compilation testing system for the msvcpp-normalize-pe project. The system will:

1. **Verify reproducibility** - Compile C++ programs, patch them, and verify byte-for-byte identical output against reference binaries
2. **Generate test fixtures** - Build PE files in CI to use as test fixtures for integration tests
3. **End-to-end validation** - Complete workflow: compile → patch → verify → test runtime

## Goals

- Test that msvcpp-normalize-pe works correctly with real MSVC-compiled binaries
- Verify reproducibility across different environments and CI runs
- Cover multiple MSVC versions, architectures, and optimization levels
- Provide reference binaries for local testing and development
- Ensure patched binaries remain executable and functionally correct

## Architecture

### Workflow Structure

**New File**: `.github/workflows/test-windows.yml`

**Triggers**:
- `push` - Run on all pushes
- `pull_request` - Run on all PRs
- `workflow_dispatch` - Manual trigger for reference generation

**Strategy**: Matrix-based monolithic approach
- Single large matrix job covering all combinations
- `fail-fast: false` to test all combinations even if some fail
- ~24 jobs per workflow run

### Matrix Dimensions

```yaml
matrix:
  msvc: [2017, 2019, 2022]      # 3 versions
  arch: [x86, x64]               # 2 architectures (32-bit and 64-bit)
  opt: [Od, O2]                  # 2 optimization levels (debug, optimized)
  program: [simple, complex]     # 2 test programs
```

**Total combinations**: 3 × 2 × 2 × 2 = 24 jobs per run

## Components

### Test Programs

**Location**: `tests/fixtures/sources/`

#### simple.cpp
```cpp
// Minimal program - tests basic PE structure
#include <iostream>
int main() {
    std::cout << "msvcpp-normalize-pe test" << std::endl;
    return 0;
}
```

**Purpose**: Test basic PE structure with minimal dependencies

#### complex.cpp
```cpp
// More realistic program - tests PE with imports, multiple sections
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

int compute(const std::vector<int>& data) {
    return std::accumulate(data.begin(), data.end(), 0);
}

int main() {
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    std::cout << "Sum: " << compute(numbers) << std::endl;
    return 0;
}
```

**Purpose**: Test PE files with:
- Standard library imports
- Multiple functions
- More complex section structure
- Realistic use case

### Reference Binaries

**Location**: `tests/fixtures/references/` (Git submodule)

**Repository**: Separate repo (e.g., `mithro/msvcpp-normalize-pe-test-binaries`)

**Rationale**:
- Keeps main repository lightweight
- Binary files don't bloat main repo history
- Can be updated independently
- Optional for users who don't need references

**Naming Convention**: `{program}-msvc{version}-{arch}-{opt}.exe`

**Examples**:
- `simple-msvc2022-x64-O2.exe`
- `complex-msvc2019-x86-Od.exe`
- `simple-msvc2017-x64-Od.exe`

**Total Files**: 24 reference binaries (one per matrix combination)

### Repository Structure

```
tests/
├── fixtures/
│   ├── sources/
│   │   ├── simple.cpp
│   │   └── complex.cpp
│   └── references/  ← Git submodule
│       ├── simple-msvc2017-x86-Od.exe
│       ├── simple-msvc2017-x86-O2.exe
│       ├── simple-msvc2017-x64-Od.exe
│       ├── simple-msvc2017-x64-O2.exe
│       ├── complex-msvc2017-x86-Od.exe
│       └── ... (24 total)
```

## Workflow Steps

Each matrix job executes the following steps:

### 1. Checkout Code
```yaml
- uses: actions/checkout@v4
  with:
    submodules: true  # Checkout reference binaries submodule
```

### 2. Setup MSVC
```yaml
- uses: ilammy/msvc-dev-cmd@v1
  with:
    arch: ${{ matrix.arch }}
    toolset: ${{ matrix.msvc }}
```

**Purpose**: Configure environment for specific MSVC version and architecture

### 3. Compile C++ Program
```bash
cl.exe /std:c++17 /${{ matrix.opt }} /Zi ${{ matrix.program }}.cpp \
  /Fe:${{ matrix.program }}.exe /link /DEBUG:FULL /Brepro
```

**Flags**:
- `/std:c++17` - C++17 standard
- `/Od` or `/O2` - Optimization level from matrix
- `/Zi` - Generate debug information
- `/DEBUG:FULL` - Full debug info in PE
- `/Brepro` - Reproducible build mode

### 4. Verify Compilation
```bash
# Check that .exe was created
test -f ${{ matrix.program }}.exe
```

### 5. Install Python and Dependencies
```yaml
- uses: actions/setup-python@v5
  with:
    python-version: '3.12'

- name: Install package
  run: pip install .
```

**Note**: Installs current code (not PyPI version) to test latest changes

### 6. Patch Binary
```bash
msvcpp-normalize-pe ${{ matrix.program }}.exe --timestamp 1 --verbose
```

### 7. Verify Reproducibility
```bash
# Compute hash of patched binary
ACTUAL_HASH=$(sha256sum ${{ matrix.program }}.exe | cut -d' ' -f1)

# Get reference binary name
REF_NAME="${{ matrix.program }}-msvc${{ matrix.msvc }}-${{ matrix.arch }}-${{ matrix.opt }}.exe"
REF_PATH="tests/fixtures/references/$REF_NAME"

# Compare hashes
if [ -f "$REF_PATH" ]; then
  EXPECTED_HASH=$(sha256sum "$REF_PATH" | cut -d' ' -f1)
  if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
    echo "Hash mismatch!"
    echo "Expected: $EXPECTED_HASH"
    echo "Actual:   $ACTUAL_HASH"
    exit 1
  fi
else
  echo "Reference binary not found: $REF_NAME"
  echo "Upload artifacts to generate initial references"
  exit 1
fi
```

### 8. Runtime Test
```bash
# Execute patched binary to verify it still works
./${{ matrix.program }}.exe
```

**Success criteria**: Exit code 0

### 9. Upload Artifacts (Always)

Upload both pre-patch and post-patch binaries:

```yaml
- uses: actions/upload-artifact@v4
  if: always()  # Upload even on failure
  with:
    name: ${{ matrix.program }}-msvc${{ matrix.msvc }}-${{ matrix.arch }}-${{ matrix.opt }}
    path: |
      ${{ matrix.program }}-original.exe
      ${{ matrix.program }}.exe
    retention-days: 30
```

**Artifacts**:
- `{program}-original.exe` - Before patching
- `{program}.exe` - After patching

**Purpose**:
- Generate initial reference binaries
- Debug reproducibility failures
- Investigate patching issues
- Verify correctness

## Error Handling

### Compilation Failures

**Symptom**: `cl.exe` returns non-zero exit code

**Likely Causes**:
- MSVC version/toolset not available
- Syntax error in test program
- Missing MSVC components

**Action**: Job fails with compiler output for debugging

### Patching Failures

**Symptom**: `msvcpp-normalize-pe` returns non-zero exit code

**Likely Causes**:
- Invalid PE file structure
- Missing debug directory
- Bug in patcher code

**Action**:
- Job fails with error output
- Original binary uploaded as artifact for investigation

### Hash Mismatch (Reproducibility Failure)

**Symptom**: Patched binary hash doesn't match reference

**Implications**:
- Reproducibility broken
- Most critical failure type
- Could indicate patcher bug or environment issue

**Action**:
1. Log both hashes (expected vs actual)
2. Upload both binaries as artifacts
3. Fail job with clear error message
4. Maintainer investigates differences

### Runtime Test Failures

**Symptom**: Patched binary crashes or returns non-zero exit code

**Implications**:
- Patcher corrupted executable code
- Critical bug requiring immediate fix

**Action**:
- Job fails
- Investigate patcher logic immediately

### Missing Reference Binaries

**Symptom**: Reference binary file doesn't exist in submodule

**Action**:
- **Fail job** with message: "Reference binary not found: {name}"
- Upload artifacts (both original and patched)
- Maintainer reviews artifacts and commits to submodule

**Rationale**: Ensures reference set stays complete, prevents silent skips

## Initial Setup

### One-Time Setup Steps

1. **Create submodule repository**
   ```bash
   # On GitHub, create new repo: msvcpp-normalize-pe-test-binaries
   ```

2. **Add submodule to main repo**
   ```bash
   cd msvcpp-normalize-pe
   git submodule add https://github.com/mithro/msvcpp-normalize-pe-test-binaries.git \
     tests/fixtures/references
   git commit -m "Add test binaries submodule"
   ```

3. **Run workflow to generate references**
   - Push changes to trigger workflow
   - All 24 jobs will fail (no references exist yet)
   - Workflow uploads all artifacts

4. **Download and commit references**
   ```bash
   # Download all artifacts from GitHub Actions
   # Extract patched binaries

   cd tests/fixtures/references
   # Copy all patched .exe files here

   git add *.exe
   git commit -m "Initial reference binaries"
   git push
   ```

5. **Update submodule reference**
   ```bash
   cd ../../..  # Back to main repo
   git add tests/fixtures/references
   git commit -m "Update reference binaries submodule"
   git push
   ```

6. **Subsequent runs will pass**
   - Workflow compiles, patches, compares against references
   - All jobs should pass

## Maintenance

### Updating Reference Binaries

**When to update**:
- MSVC behavior changes
- Patcher logic intentionally changes binary format
- Bug fixes that change output
- New features that modify PE structure

**Process**:
1. Run workflow (will fail with hash mismatches)
2. Download artifacts
3. Review changes carefully (compare old vs new binaries)
4. If changes are correct:
   - Update submodule repo with new binaries
   - Update submodule reference in main repo
5. Document why references changed in commit message

### Adding New Test Programs

1. Add new `.cpp` file to `tests/fixtures/sources/`
2. Update matrix to include new program
3. Run workflow to generate references
4. Download artifacts and commit to submodule
5. Total jobs will increase (currently 24, add 12 per new program)

### Adding New MSVC Versions

1. Update matrix: `msvc: [2017, 2019, 2022, 2024]`
2. Verify `ilammy/msvc-dev-cmd` supports new version
3. Run workflow to generate references
4. Download artifacts and commit to submodule
5. Total jobs will increase by 8 per new version

## Benefits

1. **True Reproducibility Testing**: Compares against known references across environments and time
2. **Comprehensive Coverage**: Multiple MSVC versions, architectures, optimization levels
3. **Real-World Validation**: Uses actual MSVC compiler, not synthetic test data
4. **Runtime Verification**: Ensures patched binaries remain functional
5. **Easy Debugging**: Artifacts uploaded for all runs, making investigation simple
6. **Lightweight Main Repo**: Submodule keeps binary files separate
7. **CI Integration**: Automated testing on every push/PR

## Limitations

1. **CI Cost**: 24 jobs per run may consume significant CI minutes
2. **Windows Runners**: Requires Windows runners (more expensive than Linux)
3. **Build Time**: Each compilation + patch + test takes ~2-5 minutes
4. **Reference Maintenance**: Requires manual update when intentional changes occur
5. **Submodule Complexity**: Developers must remember to `git submodule update`

## Future Enhancements

1. **Conditional Matrix**: Run full matrix on main, subset on PRs
2. **DLL Testing**: Add DLL compilation and testing
3. **PDB Analysis**: Investigate PDB file reproducibility
4. **Benchmark Tracking**: Track patch performance across versions
5. **Visual Diff**: Tool to visualize binary differences on hash mismatch
6. **Automated Reference Updates**: Bot to propose reference updates when patcher changes

## Success Criteria

- [ ] Workflow runs successfully on Windows
- [ ] All 24 matrix combinations compile
- [ ] All binaries patch successfully
- [ ] All patched binaries match references (after initial setup)
- [ ] All patched binaries execute correctly
- [ ] Artifacts uploaded for debugging
- [ ] Submodule structure works correctly
- [ ] Documentation clear for maintainers

## References

- GitHub Actions Windows Runners: https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners
- ilammy/msvc-dev-cmd Action: https://github.com/ilammy/msvc-dev-cmd
- MSVC /Brepro Flag: https://learn.microsoft.com/en-us/cpp/build/reference/brepro-reproducible-build
- Git Submodules: https://git-scm.com/book/en/v2/Git-Tools-Submodules
