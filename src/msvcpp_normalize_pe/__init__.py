"""msvcpp-normalize-pe: Normalize PE files for reproducible MSVC++ builds."""

__version__ = "1.0.0"
__author__ = "Tim Ansell"
__email__ = "me@mith.ro"

from msvcpp_normalize_pe.patcher import PatchResult, patch_pe_file, validate_pe_file

__all__ = ["patch_pe_file", "validate_pe_file", "PatchResult", "__version__"]
