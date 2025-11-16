msvcpp-normalize-pe Documentation
==================================

**Normalize PE files for reproducible MSVC++ builds**

.. warning::
   **AI-Assisted Development Notice**

   This project was developed as an experiment in AI-assisted "vibe coding" using Claude Code.
   While the code has comprehensive tests and linting, it was primarily generated through AI
   assistance. The implementation is based on reverse-engineering PE file formats and may have
   edge cases or behaviors that haven't been thoroughly tested with all possible MSVC
   configurations. Use with caution in production environments and verify results with your
   specific toolchain.

``msvcpp-normalize-pe`` is a Python tool that patches Windows PE (Portable Executable)
files to make MSVC builds reproducible by normalizing timestamps, GUIDs, and other
non-deterministic debug metadata.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   user-guide
   developer-guide
   technical-details

Quick Start
-----------

Install from PyPI:

.. code-block:: bash

   pip install msvcpp-normalize-pe

Patch a PE file:

.. code-block:: bash

   msvcpp-normalize-pe program.exe

Features
--------

* **Zero Dependencies** - Uses only Python standard library
* **Comprehensive Patching** - Patches all 8 non-deterministic fields
* **Type-Safe API** - Full mypy strict mode compliance
* **Well-Tested** - Unit, integration, property-based, and snapshot tests
* **Fast** - Processes files in milliseconds

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
