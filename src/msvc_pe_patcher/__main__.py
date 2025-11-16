"""Allow running as python -m msvc_pe_patcher."""

import sys

from msvc_pe_patcher.cli import main

if __name__ == "__main__":
    sys.exit(main())
