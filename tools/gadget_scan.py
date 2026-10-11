#!/usr/bin/env python3
"""gadget_scan.py - scan ABL766 for ROP gadgets useful for the nv_sig overflow.

Usage: py -3.11 gadget_scan.py
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"firmware\keyone-abl766\ABL766 - Hn03\target\product\bbry_qc8953\emmc_appsboot.mbn"
LOAD_OFF = 0x8000
LOAD_VADDR = 0x8F600000

def va2off(va):
    return va - LOAD_VADDR + LOAD_OFF

def main():
    data = open(BIN, "rb").read()
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    code = data[va2off(0x8F600000):va2off(0x8F700000)]
    pops = {}
    writes = []
    bx_lr = []
    for ins in md.disasm(code, 0x8F600000):
        if ins.mnemonic == "pop" and "pc" in ins.op_str:
            if ins.op_str not in pops:
                pops[ins.op_str] = ins.address
        if ins.mnemonic == "str" and ins.op_str.count("[") == 1 and "sp" not in ins.op_str:
            writes.append((ins.address, ins.op_str))
        if ins.mnemonic == "bx" and ins.op_str == "lr":
            bx_lr.append(ins.address)
    print("== pop gadgets (first occurrence) ==")
    for k, v in sorted(pops.items())[:24]:
        print(f"  {v:#010x}  pop {k}")
    print()
    print("== str rX,[rY] gadgets (first 20) ==")
    for a, o in writes[:20]:
        print(f"  {a:#010x}  str {o}")
    print()
    print(f"bx lr count: {len(bx_lr)}, first: {bx_lr[:5]}")

if __name__ == "__main__":
    main()
