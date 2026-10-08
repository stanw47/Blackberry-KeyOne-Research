#!/usr/bin/env python3
"""lk_xref.py - find code references to strings/addresses in the KEYone LK
(MBN-wrapped raw ARM payload at file 0x8000 -> VA 0x8f600000).

Handles both literal pools (ldr rX, [pc, #imm]) and ARM movw/movt address
construction, which is how BlackBerry's aboot loads most strings.

Usage:
  py tools/lk_xref.py <emmc_appsboot.mbn> <string> [<string> ...]
"""
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

LOAD_FOFF = 0x8000
LOAD_VADDR = 0x8F600000


def find_string_va(data, needle):
    b = needle.encode()
    i = 0
    out = []
    while True:
        j = data.find(b, i)
        if j < 0:
            break
        start = j
        while start > 0 and 32 <= data[start - 1] < 127:
            start -= 1
        end = j
        while end < len(data) and 32 <= data[end] < 127:
            end += 1
        va = LOAD_VADDR + (start - LOAD_FOFF)
        out.append((start, va, data[start:end].decode("latin1")))
        i = end
    return out


def main():
    path = sys.argv[1]
    needles = sys.argv[2:]
    data = open(path, "rb").read()
    targets = {}
    for n in needles:
        for _, va, full in find_string_va(data, n):
            targets[va] = full
            print("string %r -> VA %#x  %r" % (n, va, full[:80]))
    if not targets:
        return 1
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.skipdata = True
    regs = {}
    for i in md.disasm(data[LOAD_FOFF:], LOAD_VADDR):
        m, ops = i.mnemonic, i.op_str
        if m == "movw":
            mm = re.match(r"(r\d+|sp), #(0x[0-9a-f]+)", ops)
            if mm:
                regs[mm.group(1)] = int(mm.group(2), 16)
        elif m == "movt":
            mm = re.match(r"(r\d+|sp), #(0x[0-9a-f]+)", ops)
            if mm:
                r = mm.group(1)
                val = (int(mm.group(2), 16) << 16) | (regs.get(r, 0) & 0xFFFF)
                regs[r] = val
                if val in targets:
                    print("  xref %#010x: movw/movt %s -> %r"
                          % (i.address, r, targets[val][:60]))
        elif m == "ldr" and "[pc" in ops:
            mm = re.search(r"\[pc, #(0x[0-9a-f]+)\]", ops)
            if mm:
                pa = (i.address + 4 + int(mm.group(1), 16)) & ~3
                fo = LOAD_FOFF + (pa - LOAD_VADDR)
                if 0 <= fo < len(data) - 4:
                    val = struct.unpack_from("<I", data, fo)[0]
                    if val in targets:
                        print("  xref %#010x: ldr pool=%#x -> %r"
                              % (i.address, pa, targets[val][:60]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
