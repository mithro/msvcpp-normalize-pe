msvcpp-normalize-pe Documentation
==================================

**Normalize PE files for reproducible MSVC++ builds**

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
