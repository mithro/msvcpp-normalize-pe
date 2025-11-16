# Reference Binaries

This directory will contain pre-built, pre-patched reference binaries for reproducibility testing.

## Status: Pending Submodule Setup

This directory is currently a placeholder. The actual reference binaries will be stored in a separate Git repository added as a submodule.

## Future Submodule Setup

```bash
# Create separate repository for binaries
# On GitHub: create mithro/msvcpp-normalize-pe-test-binaries

# Add as submodule (run from repo root)
git submodule add https://github.com/mithro/msvcpp-normalize-pe-test-binaries.git \
  tests/fixtures/references

# Update .gitignore if needed
echo ".worktrees/" >> .gitignore
```

## Generating Initial References

After the workflow is created and running:

1. Run workflow - all jobs will fail (no references exist)
2. Download all artifacts from the workflow run
3. Clone the submodule repository
4. Copy all `*-patched.exe` files to the submodule
5. Commit and push to submodule
6. Update submodule reference in main repo

## Binary Naming Convention

Format: `{program}-msvc{version}-{arch}-{opt}.exe`

Examples:
- `simple-msvc2022-x64-O2.exe`
- `complex-msvc2019-x86-Od.exe`
- `simple-msvc2017-x64-Od.exe`

## Total Files

24 reference binaries (3 MSVC × 2 arch × 2 opt × 2 programs)
