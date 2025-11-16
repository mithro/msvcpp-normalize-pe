"""Allow running as python -m msvc_pe_patcher."""

import sys

from msvcpp_normalize_pe.cli import main

if __name__ == "__main__":
    sys.exit(main())
