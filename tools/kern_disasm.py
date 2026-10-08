#!/usr/bin/env python3
"""Disassemble the shipped ARM64 kernel Image by symbol VA.

Usage:
  py -3.11 tools/kern_disasm.py artifacts/kernel.bin <va> <len|+len>

VA->file mapping verified in notes/32: file = VA - 0xffffffc000080000
"""
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

BASE_VA = 0xFFFFFFC000080000


def main():
    path, va, ln = sys.argv[1], int(sys.argv[2], 0), sys.argv[3]
    ln = int(ln[1:], 0) if ln.startswith("+") else int(ln, 0) - va
    data = open(path, "rb").read()
    off = va - BASE_VA
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for i in md.disasm(data[off:off + ln], va):
        print("0x%09x  %-8s %s" % (i.address, i.mnemonic, i.op_str))


if __name__ == "__main__":
    main()
