"""Sphinx configuration for msvc-pe-patcher documentation."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Project information
project = "msvcpp-normalize-pe"
copyright = "2025, Tim Ansell"
author = "Tim Ansell"

# Get version from package
from msvcpp_normalize_pe import __version__

release = __version__

# Extensions
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
]

# Theme
html_theme = "sphinx_rtd_theme"

# HTML options
html_static_path = []
templates_path = []

# Napoleon settings (for Google/NumPy docstrings)
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
