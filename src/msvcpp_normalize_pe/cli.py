"""Command-line interface for msvc-pe-patcher."""

import argparse
import sys
from pathlib import Path

from msvcpp_normalize_pe import __version__
from msvcpp_normalize_pe.patcher import patch_pe_file


def main() -> int:
    """Entry point for msvc-pe-patcher command."""
    parser = argparse.ArgumentParser(
        prog="msvcpp-normalize-pe",
        description="Normalize PE files for reproducible MSVC++ builds",
        epilog="""
Examples:
  msvc-pe-patcher program.exe
  msvc-pe-patcher program.exe 1234567890
  msvc-pe-patcher --timestamp 1 program.exe
  msvc-pe-patcher --verbose program.exe
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("pe_file", help="PE file to patch (.exe or .dll)")

    parser.add_argument(
        "timestamp",
        nargs="?",
        type=int,
        default=None,
        help="Timestamp value (default: 1)",
    )

    parser.add_argument(
        "--timestamp",
        dest="timestamp_flag",
        type=int,
        metavar="VALUE",
        help="Timestamp value (explicit flag form)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed patching information",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress output except errors",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Reconcile positional vs flag timestamp
    timestamp = args.timestamp_flag or args.timestamp or 1

    # Validate conflicts
    if args.verbose and args.quiet:
        print("ERROR: Cannot use --verbose and --quiet together", file=sys.stderr)
        return 1

    # Patch the file
    pe_path = Path(args.pe_file)
    result = patch_pe_file(pe_path, timestamp, verbose=args.verbose and not args.quiet)

    # Handle errors
    if not result.success:
        for error in result.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    # Success message (unless quiet)
    if not args.quiet and not args.verbose:
        print(f"Patched {result.patches_applied} field(s) in {pe_path.name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
