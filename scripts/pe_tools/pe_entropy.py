#!/usr/bin/env python3
"""
PE entropy: compute Shannon entropy for PE file (whole or per section).
Usage: pe_entropy.py <path> [section_name] [window_size]
"""
from __future__ import annotations

import math
import sys

try:
    import pefile
except ImportError:
    print("Error: pefile not installed. Install with: pip install pefile", file=sys.stderr)
    sys.exit(1)


def entropy(data: bytes, window: int = 256) -> list[tuple[int, int, float]]:
    results = []
    for i in range(0, len(data), window):
        chunk = data[i : i + window]
        if len(chunk) < 16:
            break
        freq = [0] * 256
        for b in chunk:
            freq[b] += 1
        n = len(chunk)
        ent = 0.0
        for f in freq:
            if f > 0:
                p = f / n
                ent -= p * math.log2(p)
        results.append((i, len(chunk), round(ent, 4)))
    return results


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: pe_entropy.py <path> [section_name] [window_size]", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    section_name = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
    window = int(sys.argv[3]) if len(sys.argv) > 3 else 256

    try:
        pe = pefile.PE(path)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    data: bytes
    if section_name:
        found = None
        for sec in pe.sections:
            name = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            if name == section_name:
                data = sec.get_data()
                found = True
                break
        if not found:
            print(f"Section {section_name!r} not found", file=sys.stderr)
            sys.exit(1)
    else:
        data = pe.get_memory_mapped_image()

    pe.close()

    results = entropy(data, window)
    total_ent = 0.0
    if data:
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        for f in freq:
            if f > 0:
                p = f / n
                total_ent -= p * math.log2(p)

    print(f"Total size: {len(data)} bytes")
    print(f"Overall entropy: {total_ent:.4f} bits/byte")
    print(f"Window size: {window} bytes")
    print(f"Windows analyzed: {len(results)}")
    print()
    if results:
        ents = [r[2] for r in results]
        print(f"Min window entropy: {min(ents):.4f}")
        print(f"Max window entropy: {max(ents):.4f}")
        print(f"Avg window entropy: {sum(ents) / len(ents):.4f}")
        print()
        print("Offset      Size  Entropy")
        print("-" * 35)
        for offset, size, ent in results[:50]:
            bar = "#" * int(ent * 4)
            print(f"0x{offset:08x}  {size:4d}  {ent:.4f}  {bar}")
        if len(results) > 50:
            print(f"... ({len(results) - 50} more windows)")


if __name__ == "__main__":
    main()
