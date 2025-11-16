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
