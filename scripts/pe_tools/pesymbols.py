#!/usr/bin/env python3
"""
PE symbols (imports/exports) listing.
Usage: pesymbols.py <path>
"""
from __future__ import annotations

import sys

try:
    import pefile
except ImportError:
    print("Error: pefile not installed. Install with: pip install pefile", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: pesymbols.py <path>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    try:
        pe = pefile.PE(path)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    out: list[str] = []

    out.append("=== Imports ===")
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace")
            out.append(f"\n  {dll}")
            for imp in entry.imports:
                name = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord{imp.ordinal}"
                out.append(f"    {name}")
    else:
        out.append("  (none)")
    out.append("")

    out.append("=== Exports ===")
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode("utf-8", errors="replace") if exp.name else f"#{exp.ordinal}"
            out.append(f"  {exp.ordinal:4}  0x{exp.address:08x}  {name}")
    else:
        out.append("  (none)")

    pe.close()
    print("\n".join(out))


if __name__ == "__main__":
    main()
