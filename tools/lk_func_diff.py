#!/usr/bin/env python3
"""
Diff two functions between two BlackBerry LK aboot images
(emmc_appsboot.mbn, ARM32, loaded at 0x8f600000 from file offset 0x8000).

Disassembles a fixed-length window at each address, normalizes address/
immediate operands, and prints a unified diff of the instruction streams.
String references (movw/movt pairs) are annotated with the referenced text.

Usage:
    py -3.11 lk_func_diff.py <a.mbn> <addr-a> <b.mbn> <addr-b> [--len 0x400]
"""
import argparse
import difflib
import re
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

LOAD_OFF = 0x8000
LOAD_VADDR = 0x8F600000


def va2off(va):
    return LOAD_OFF + (va - LOAD_VADDR)


def strings_table(data):
    tbl = {}
    for m in re.finditer(rb"[ -~]{4,}", data):
        off = m.start()
        if off < LOAD_OFF:
            continue
        tbl[LOAD_VADDR + (off - LOAD_OFF)] = m.group().decode()
    return tbl


def listing(data, start, length, strings):
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = False
    chunk = data[va2off(start): va2off(start) + length]
    out = []
    regs = {}
    for insn in md.disasm(chunk, start):
        op = insn.op_str
        ann = ""
        if insn.mnemonic == "movw":
            m = re.match(r"(\w+), #(0x[0-9a-fA-F]+)", op)
            if m:
                regs[m.group(1)] = int(m.group(2), 0)
        elif insn.mnemonic == "movt":
            m = re.match(r"(\w+), #(0x[0-9a-fA-F]+)", op)
            if m and m.group(1) in regs:
                v = regs.pop(m.group(1)) | (int(m.group(2), 0) << 16)
                if v in strings:
                    ann = f"   ; {strings[v]!r}"
        norm = re.sub(r"#-?0x[0-9a-fA-F]+", "#I", op)
        if insn.mnemonic in ("b", "bl", "bx", "blx"):
            norm = re.sub(r"0x[0-9a-fA-F]+", "T", norm)
        out.append(f"{insn.mnemonic} {norm}{ann}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("fa")
    ap.add_argument("adda")
    ap.add_argument("fb")
    ap.add_argument("addrb")
    ap.add_argument("--len", type=lambda x: int(x, 0), default=0x400)
    args = ap.parse_args()

    da = open(args.fa, "rb").read()
    db = open(args.fb, "rb").read()
    sa = strings_table(da)
    sb = strings_table(db)

    la = listing(da, int(args.adda, 0), args.len, sa)
    lb = listing(db, int(args.addrb, 0), args.len, sb)

    print(f"[*] A: {args.fa} @ {args.adda} ({len(la)} insns)")
    print(f"[*] B: {args.fb} @ {args.addrb} ({len(lb)} insns)")
    print()
    diff = difflib.unified_diff(la, lb, fromfile="AAN-era", tofile="ABL-era", lineterm="", n=3)
    for line in diff:
        print(line)


if __name__ == "__main__":
    sys.exit(main())
