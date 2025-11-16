Developer Guide
===============

Development Setup
-----------------

Prerequisites
~~~~~~~~~~~~~

* Python 3.8 or higher
* uv (recommended) or pip
* Git

Clone Repository
~~~~~~~~~~~~~~~~

.. code-block:: bash

   git clone https://github.com/mithro/msvcpp-normalize-pe.git
   cd msvcpp-normalize-pe

Install Development Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using uv (recommended):

.. code-block:: bash

   uv sync --all-extras --dev

Using pip:

.. code-block:: bash

   pip install -e ".[dev]"

Running Tests
-------------

All Tests
~~~~~~~~~

.. code-block:: bash

   uv run pytest

With Coverage
~~~~~~~~~~~~~

.. code-block:: bash

   uv run pytest --cov --cov-report=html

Specific Test Types
~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Unit tests only (fast)
   uv run pytest tests/unit/

   # Integration tests (requires fixtures)
   uv run pytest tests/integration/

   # Property-based tests
   uv run pytest tests/property/

Code Quality
------------

Linting
~~~~~~~

.. code-block:: bash

   uv run ruff check src/ tests/

Auto-Fix
~~~~~~~~

.. code-block:: bash

   uv run ruff check --fix src/ tests/

Formatting
~~~~~~~~~~

.. code-block:: bash

   uv run ruff format src/ tests/

Type Checking
~~~~~~~~~~~~~

.. code-block:: bash

   uv run mypy src/

Project Architecture
--------------------

Directory Structure
~~~~~~~~~~~~~~~~~~~

::

   src/msvcpp_normalize_pe/
   ├── __init__.py       # Package metadata
   ├── __main__.py       # CLI entry point
   ├── cli.py            # Argument parsing
   └── patcher.py        # Core patching logic

   tests/
   ├── unit/             # Fast unit tests
   ├── integration/      # Tests with real PE files
   ├── property/         # Hypothesis property tests
   └── fixtures/         # Sample PE files

Module Overview
~~~~~~~~~~~~~~~

**patcher.py**
  Core PE manipulation logic. Contains functions for finding PE offsets,
  verifying signatures, and patching timestamps/GUIDs.

**cli.py**
  Command-line interface using argparse. Supports both positional and
  flag-based arguments.

Contributing
------------

Workflow
~~~~~~~~

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

Code Style
~~~~~~~~~~

* Follow PEP 8
* Use type hints (mypy strict mode)
* Write docstrings for all public functions
* Keep functions small and focused

Testing Requirements
~~~~~~~~~~~~~~~~~~~~

* All new code must have tests
* Maintain 95%+ code coverage
* Property tests for invariants
* Integration tests for real-world scenarios

Release Process
---------------

Version Bumping
~~~~~~~~~~~~~~~

1. Update version in ``src/msvcpp_normalize_pe/__init__.py``
2. Update version in ``pyproject.toml``
3. Commit: ``git commit -m "chore: bump version to X.Y.Z"``

Tagging
~~~~~~~

.. code-block:: bash

   git tag -a vX.Y.Z -m "Release X.Y.Z"
   git push origin vX.Y.Z

Publishing
~~~~~~~~~~

GitHub Actions automatically publishes to TestPyPI and PyPI when you push a tag.

1. Push tag triggers build
2. Package published to TestPyPI
3. Manual approval required
4. Package published to PyPI
5. GitHub Release created
