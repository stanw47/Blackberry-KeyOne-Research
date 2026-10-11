#!/usr/bin/env python3
"""gadget_call.py - find register-setup call gadgets in ABL766.

Looks for sequences like:
    mov r0, r4 / mov r0, r5 / mov r1, r4 / ...
    ...
    blx rN   (or blx rN with a nearby pop)
so a ROP chain can do: pop {r4,r5,r6,pc} -> gadget -> target.
"""
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
        if ins.mnemonic == "blx" and ins.op_str.startswith("r"):
            # look back up to 6 instructions for mov r0/r1 setups
            window = insns[max(0, i-6):i]
            movs = [w for w in window if w.mnemonic == "mov" and w.op_str.startswith(("r0,", "r1,"))]
            if movs:
                hits.append((ins.address, [f"{w.mnemonic} {w.op_str}" for w in window], f"blx {ins.op_str}"))
    print(f"call gadgets: {len(hits)}")
    for addr, window, call in hits[:40]:
        print(f"  {addr:#010x}: {'; '.join(window)} ; {call}")

if __name__ == "__main__":
    main()
