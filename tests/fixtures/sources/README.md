# C++ Test Program Sources

This directory contains C++ source files used by the Windows compilation tests.

## Programs

### simple.cpp
Minimal "Hello World" style program that:
- Uses iostream for basic output
- Tests basic PE structure
- Compiles quickly (~1-2 seconds)

### complex.cpp
More realistic program that:
- Uses STL containers (vector, string)
- Uses STL algorithms (accumulate)
- Has multiple functions
- Tests PE with more complex section structure and imports

## Compilation

These programs are compiled by the GitHub Actions workflow with:
- MSVC version: 2019 (default on windows-latest runners)
- Architectures: x86 (32-bit), x64 (64-bit)
- Optimization levels: /Od (debug), /O2 (optimized)
- Flags: `/std:c++17 /Zi /DEBUG:FULL /Brepro`

## Purpose

The compiled binaries are used to:
1. Verify msvcpp-normalize-pe works with real MSVC output
2. Test reproducibility across environments
3. Generate reference binaries for integration tests
4. Validate that patched binaries remain executable
