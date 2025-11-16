User Guide
==========

Installation
------------

From PyPI
~~~~~~~~~

.. code-block:: bash

   pip install msvcpp-normalize-pe

From Source
~~~~~~~~~~~

.. code-block:: bash

   git clone https://github.com/mithro/msvcpp-normalize-pe.git
   cd msvcpp-normalize-pe
   pip install .

Using uv
~~~~~~~~

.. code-block:: bash

   uv pip install msvcpp-normalize-pe

Basic Usage
-----------

Simple Patching
~~~~~~~~~~~~~~~

Patch a PE file with default timestamp (1):

.. code-block:: bash

   msvcpp-normalize-pe program.exe

Custom Timestamp
~~~~~~~~~~~~~~~~

Use a specific Unix timestamp:

.. code-block:: bash

   msvcpp-normalize-pe program.exe 1234567890

Or using explicit flag:

.. code-block:: bash

   msvcpp-normalize-pe --timestamp 1234567890 program.exe

Verbose Output
~~~~~~~~~~~~~~

Show detailed information about each patched field:

.. code-block:: bash

   msvcpp-normalize-pe --verbose program.exe

Quiet Mode
~~~~~~~~~~

Suppress output except errors:

.. code-block:: bash

   msvcpp-normalize-pe --quiet program.exe

Integration Examples
--------------------

Makefile
~~~~~~~~

.. code-block:: makefile

   program.exe: program.cpp
       cl.exe /O2 /Zi program.cpp /link /DEBUG:FULL /Brepro
       msvcpp-normalize-pe program.exe 1

GitHub Actions
~~~~~~~~~~~~~~

.. code-block:: yaml

   - name: Build and normalize
     run: |
       cl.exe /O2 program.cpp /link /DEBUG:FULL /Brepro
       msvcpp-normalize-pe program.exe 1

   - name: Verify reproducibility
     run: |
       sha256sum program.exe > checksum.txt
       git diff --exit-code checksum.txt

Troubleshooting
---------------

File Not Found
~~~~~~~~~~~~~~

**Error:** ``ERROR: File not found: program.exe``

**Solution:** Ensure the file path is correct and the file exists.

Not a Valid PE File
~~~~~~~~~~~~~~~~~~~

**Error:** ``ERROR: Not a valid PE file``

**Solution:** Ensure you're patching a Windows PE executable (.exe) or DLL (.dll),
not a different file type.

Permission Denied
~~~~~~~~~~~~~~~~~

**Error:** ``ERROR: Failed to write file: Permission denied``

**Solution:** Ensure you have write permissions for the file. On Windows, the file
may be locked if it's currently running.
