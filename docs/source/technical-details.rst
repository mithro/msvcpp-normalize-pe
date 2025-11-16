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
