#!/usr/bin/env python3
"""usb_audit.py - list functions in the ABL766 USB/auth cluster and flag canary-free ones."""
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
    start, end = 0x8F624000, 0x8F627400
    code = data[va2off(start):va2off(end)]
    insns = list(md.disasm(code, start))
    # split into functions at push-prologue boundaries
    funcs = []
    cur = []
    for ins in insns:
        if ins.mnemonic == "push" and cur:
            funcs.append(cur)
            cur = []
        cur.append(ins)
    if cur:
        funcs.append(cur)
    print(f"functions in cluster: {len(funcs)}")
    canary_free = []
    for f in funcs:
        text = "; ".join(f"{i.mnemonic} {i.op_str}" for i in f[:8])
        has_canary = "0x2ed0" in text and "0x8f7c" in text
        if not has_canary:
            canary_free.append(f)
    print(f"canary-free functions: {len(canary_free)}")
    for f in canary_free:
        addr = f[0].address
        n = len(f)
        # look for copy-ish calls
        calls = [i for i in f if i.mnemonic == "bl" and i.op_str.startswith("#0x")]
        interesting = [c for c in calls if c.op_str in ("#0x8f67b358", "#0x8f67b60c", "#0x8f67b0bc", "#0x8f67b578", "#0x8f67b464", "#0x8f62617c", "#0x8f624a2c")]
        print(f"  {addr:#010x} ({n} insns) calls: {[c.op_str for c in interesting]}")
        for ins in f[:6]:
            print(f"      {ins.address:#010x} {ins.mnemonic} {ins.op_str}")

if __name__ == "__main__":
    main()
