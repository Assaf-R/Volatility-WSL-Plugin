#!/usr/bin/env python3
"""Patch the symbol ADDRESSES of a Linux ISF using the real deployed kernel.

Why this exists
---------------
An ISF built by rebuilding Microsoft's WSL2 kernel locally has correct struct
layouts (types) but, if your toolchain differs from Microsoft's, symbol
*addresses* that don't match the kernel actually running in WSL. Wrong addresses
break every Volatility plugin (psscan finds nothing, pslist is empty, ...).

This script keeps the ISF's types and replaces each symbol's `address` with the
address from the deployed kernel, matched by symbol name. Only names that occur
exactly once in the deployed kernel's symbol table are patched, so a duplicated
static symbol can never be pointed at the wrong copy.

Getting the deployed kernel's symbols (the --nm-file input)
-----------------------------------------------------------
    pip install vmlinux-to-elf
    vmlinux-to-elf "C:\\Program Files\\WSL\\tools\\kernel" deployed_vmlinux.elf
    nm deployed_vmlinux.elf > deployed_symbols.nm      # run nm inside WSL/Linux

Usage
-----
    python patch_isf_addresses.py --isf-in built.json.xz \\
        --nm-file deployed_symbols.nm --isf-out patched.json.xz

Check the result with vmcoreinfo_vs_isf.py before installing it.
"""
import argparse
import json
import lzma
from collections import defaultdict


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--isf-in", required=True, help="ISF to fix (.json or .json.xz)")
    ap.add_argument("--nm-file", required=True, help="`nm` output of the deployed kernel ELF (3 columns: addr type name)")
    ap.add_argument("--isf-out", required=True, help="where to write the patched ISF (.json.xz)")
    args = ap.parse_args()

    opener = lzma.open if args.isf_in.endswith(".xz") else open
    with opener(args.isf_in, "rt") as f:
        isf = json.load(f)

    # name -> every address the deployed kernel has for that name
    real = defaultdict(list)
    with open(args.nm_file) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 3:
                real[parts[2]].append(int(parts[0], 16))

    changed = same = ambiguous = missing = 0
    for name, sym in isf["symbols"].items():
        cands = real.get(name)
        if not cands:
            missing += 1
        elif len(cands) != 1:
            ambiguous += 1  # duplicated static name: leave as-is
        elif cands[0] == sym["address"]:
            same += 1
        else:
            sym["address"] = cands[0]
            changed += 1

    print(f"symbols in ISF          : {len(isf['symbols']):,}")
    print(f"  already correct       : {same:,}")
    print(f"  corrected             : {changed:,}")
    print(f"  ambiguous (left as-is): {ambiguous:,}")
    print(f"  not in deployed table : {missing:,}")

    with lzma.open(args.isf_out, "wt", preset=9) as f:
        json.dump(isf, f)
    print("wrote", args.isf_out)


if __name__ == "__main__":
    main()
