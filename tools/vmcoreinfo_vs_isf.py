#!/usr/bin/env python3
"""Validate a Linux ISF against the running kernel's own VMCOREINFO note.

A Linux kernel keeps a VMCOREINFO note in RAM (it starts with "OSRELEASE=")
that lists real runtime symbol addresses (link address + KASLR) and, separately,
KERNELOFFSET. So `runtime address - KERNELOFFSET` must equal the address stored
in a correct ISF. If they differ, the ISF was built from a binary whose layout
differs from the running kernel and Volatility results will be empty or wrong
(fix with patch_isf_addresses.py).

Usage
-----
    python vmcoreinfo_vs_isf.py --dump vmmemwsl.pid<PID>.dmp \\
        --isf symbols/linux/wsl2-6.18.33.2-microsoft-standard-WSL2.json.xz

The dump is the guest-RAM file written by `windows.wsl.linux_plugins` (or any
raw Linux memory image). Exit status is 0 only if every compared symbol matches.
"""
import argparse
import json
import lzma
import re
import sys

CHUNK = 128 * 1024 * 1024
NEEDLE = b"OSRELEASE="


def find_vmcoreinfo(path: str):
    """Scan the file for the note; return its text, or None."""
    with open(path, "rb") as f:
        tail = b""
        while True:
            data = f.read(CHUNK)
            if not data:
                return None
            buf = tail + data
            i = buf.find(NEEDLE)
            while i != -1:
                blob = buf[i : i + 6000]
                if b"PAGESIZE=" in blob[:400] and b"SYMBOL(" in blob:
                    return blob.split(b"\x00")[0].decode("latin-1")
                i = buf.find(NEEDLE, i + 1)
            tail = buf[-len(NEEDLE) :]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump", required=True, help="raw guest memory image")
    ap.add_argument("--isf", required=True, help="ISF to check (.json or .json.xz)")
    args = ap.parse_args()

    opener = lzma.open if args.isf.endswith(".xz") else open
    with opener(args.isf, "rt") as f:
        syms = json.load(f)["symbols"]

    note = find_vmcoreinfo(args.dump)
    if note is None:
        sys.exit(f"no VMCOREINFO note found in {args.dump}")

    lines = note.splitlines()
    kaslr = 0
    for ln in lines:
        for key in ("OSRELEASE", "BUILD-ID", "PAGESIZE", "KERNELOFFSET"):
            if ln.startswith(key + "="):
                print(ln)
        if ln.startswith("KERNELOFFSET="):
            kaslr = int(ln.split("=")[1], 16)

    print(f"\n{'symbol':<24}{'kernel says (runtime-KASLR)':>30}{'ISF says':>24}   match?")
    same = diff = 0
    for ln in lines:
        m = re.match(r"SYMBOL\((\w+)\)=([0-9a-fA-F]+)$", ln)
        if not m or m.group(1) not in syms:
            continue
        name = m.group(1)
        expected = int(m.group(2), 16) - kaslr
        actual = syms[name]["address"]
        if expected < 0xFFFFFFFF80000000:
            # e.g. mem_section: the note publishes a heap pointer's value, not a
            # link-time kernel-text address, so it can't be compared to the ISF.
            print(f"{name:<24}{expected:>30x}{actual:>24x}   skipped (not a static kernel-text address)")
            continue
        ok = expected == actual
        same += ok
        diff += not ok
        print(f"{name:<24}{expected:>30x}{actual:>24x}   {'yes' if ok else 'NO (off by %+#x)' % (actual - expected)}")
    print(f"\nsymbols matching: {same}, differing: {diff}")
    sys.exit(0 if diff == 0 and same else 1)


if __name__ == "__main__":
    main()
