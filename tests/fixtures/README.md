# Test Fixtures

This directory contains test fixtures for msvcpp-normalize-pe.

## Structure

```
fixtures/
├── sources/          # C++ source files for Windows compilation tests
│   ├── simple.cpp    # Minimal test program
│   ├── complex.cpp   # Realistic program with STL
│   └── README.md
├── references/       # Reference binaries (Git submodule, to be set up)
│   ├── .gitkeep
│   └── README.md
└── README.md         # This file
```

## Generating Test Fixtures

### Automated (GitHub Actions)

The Windows compilation test workflow automatically builds binaries for:
- MSVC versions: 2017, 2019, 2022
- Architectures: x86, x64
- Optimization levels: /Od, /O2
- Programs: simple, complex

See `.github/workflows/test-windows.yml` for details.

### Manual (Windows with MSVC)

```bash
# Simple program
cl.exe /std:c++17 /O2 /Zi sources/simple.cpp /Fe:simple.exe /link /DEBUG:FULL /Brepro

# Patch it
msvcpp-normalize-pe simple.exe --timestamp 1
```

## Reference Binaries

Reference binaries for reproducibility testing will be stored in a separate Git submodule.
See `references/README.md` for setup instructions.

## Integration Tests

The integration tests (`tests/integration/test_real_pe_files.py`) use PE files from this directory.
Currently, these tests are skipped because no reference binaries are committed yet.
