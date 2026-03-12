#!/usr/bin/env python3
"""
PE info tool: headers, sections, imports, exports.
Usage: peinfo.py <path> [--headers|--sections|--imports|--exports|--all]
"""
from __future__ import annotations

import argparse
import sys

try:
    import pefile
except ImportError:
    print("Error: pefile not installed. Install with: pip install pefile", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser(description="Display PE file information")
    ap.add_argument("path", help="Path to PE file")
    ap.add_argument(
        "mode",
        nargs="?",
        default="all",
        choices=["headers", "sections", "imports", "exports", "all"],
        help="Output mode (default: all)",
    )
    args = ap.parse_args()

    try:
        pe = pefile.PE(args.path)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    out: list[str] = []

    def do_headers() -> None:
        out.append("=== DOS header ===")
        out.append(f"  e_magic: 0x{pe.DOS_HEADER.e_magic:04x}")
        out.append(f"  e_lfanew: {pe.DOS_HEADER.e_lfanew}")
        out.append("")
        out.append("=== File header ===")
        out.append(f"  Machine: 0x{pe.FILE_HEADER.Machine:04x}")
        out.append(f"  NumberOfSections: {pe.FILE_HEADER.NumberOfSections}")
        out.append(f"  Characteristics: 0x{pe.FILE_HEADER.Characteristics:04x}")
        out.append("")
        if hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER:
            oh = pe.OPTIONAL_HEADER
            out.append("=== Optional header ===")
            out.append(f"  Magic: 0x{oh.Magic:04x}")
            out.append(f"  AddressOfEntryPoint: 0x{oh.AddressOfEntryPoint:08x}")
            out.append(f"  ImageBase: 0x{oh.ImageBase:08x}")
            out.append(f"  SectionAlignment: 0x{oh.SectionAlignment:08x}")
            out.append(f"  FileAlignment: 0x{oh.FileAlignment:08x}")
            out.append("")

    def do_sections() -> None:
        out.append("=== Sections ===")
        for sec in pe.sections:
            name = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            out.append(
                f"  {name:8}  VirtAddr=0x{sec.VirtualAddress:08x}  "
                f"VirtSize=0x{sec.Misc_VirtualSize:08x}  "
                f"RawAddr=0x{sec.PointerToRawData:08x}  "
                f"RawSize=0x{sec.SizeOfRawData:08x}  "
                f"Chars=0x{sec.Characteristics:08x}"
            )
        out.append("")

    def do_imports() -> None:
        out.append("=== Import directory ===")
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                out.append(f"  {entry.dll.decode('utf-8', errors='replace')}")
                for imp in entry.imports[:50]:
                    name = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord{imp.ordinal}"
                    out.append(f"    {imp.hint:4}  {name}")
                if len(entry.imports) > 50:
                    out.append(f"    ... ({len(entry.imports) - 50} more)")
                out.append("")
        else:
            out.append("  (no imports)")
            out.append("")

    def do_exports() -> None:
        out.append("=== Export directory ===")
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:100]:
                name = exp.name.decode("utf-8", errors="replace") if exp.name else f"#{exp.ordinal}"
                out.append(f"  {exp.ordinal:4}  0x{exp.address:08x}  {name}")
            if len(pe.DIRECTORY_ENTRY_EXPORT.symbols) > 100:
                out.append(f"  ... ({len(pe.DIRECTORY_ENTRY_EXPORT.symbols) - 100} more)")
            out.append("")
        else:
            out.append("  (no exports)")
            out.append("")

    mode = args.mode
    if mode in ("headers", "all"):
        do_headers()
    if mode in ("sections", "all"):
        do_sections()
    if mode in ("imports", "all"):
        do_imports()
    if mode in ("exports", "all"):
        do_exports()

    pe.close()
    print("\n".join(out))


if __name__ == "__main__":
    main()
