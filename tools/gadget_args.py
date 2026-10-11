#!/usr/bin/env python3
"""gadget_args.py - scan ABL766 for argument-loading gadgets."""
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

    print("== pops containing r0/r1/r2/r3 ==")
    seen = set()
    for ins in insns:
        if ins.mnemonic == "pop" and any(f"r{i}" in ins.op_str for i in (0, 1, 2, 3)):
            if ins.op_str not in seen:
                seen.add(ins.op_str)
                print(f"  {ins.address:#010x}  pop {ins.op_str}")
    print()
    print("== mov r0/r1 chains ending in bl/bx/blx via reg ==")
    cnt = 0
    for i, ins in enumerate(insns):
        if ins.mnemonic in ("bl", "bx", "blx") and (ins.op_str.startswith("r") or ins.op_str.startswith("#0x")):
            window = insns[max(0, i-5):i]
            moves = [w for w in window if w.mnemonic == "mov" and w.op_str.startswith(("r0,", "r1,"))]
            if len(moves) >= 2:
                txt = "; ".join(f"{w.mnemonic} {w.op_str}" for w in window)
                print(f"  {ins.address:#010x}: {txt}; {ins.mnemonic} {ins.op_str}")
                cnt += 1
                if cnt > 30:
                    break

if __name__ == "__main__":
    main()
