#!/usr/bin/env python3
"""gadget_call2.py - find blx r4..r8 gadgets with arg setup from controlled regs."""
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
    insns = list(md.disasm(code, 0x8F600000))
    hits = []
    for i, ins in enumerate(insns):
        if ins.mnemonic == "blx" and ins.op_str in ("r4", "r5", "r6", "r7", "r8"):
            window = insns[max(0, i-8):i+1]
            txt = [f"{w.mnemonic} {w.op_str}" for w in window]
            hits.append((ins.address, txt))
    print(f"blx r4-r8 gadgets: {len(hits)}")
    for addr, txt in hits[:25]:
        print(f"== {addr:#010x} ==")
        for t in txt:
            print("   ", t)

if __name__ == "__main__":
    main()
