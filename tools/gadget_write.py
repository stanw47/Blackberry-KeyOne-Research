#!/usr/bin/env python3
"""gadget_write.py - find write gadgets using controlled regs (r4-r8, sb, sl, fp)."""
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"firmware\keyone-abl766\ABL766 - Hn03\target\product\bbry_qc8953\emmc_appsboot.mbn"
LOAD_OFF = 0x8000
LOAD_VADDR = 0x8F600000
CTRL = {"r4", "r5", "r6", "r7", "r8", "sb", "sl", "fp"}

def va2off(va):
    return va - LOAD_VADDR + LOAD_OFF

def main():
    data = open(BIN, "rb").read()
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    code = data[va2off(0x8F600000):va2off(0x8F700000)]
    insns = list(md.disasm(code, 0x8F600000))
    hits = []
    for i, ins in enumerate(insns):
        if ins.mnemonic != "str":
            continue
        ops = ins.op_str
        # format: rX, [rY]  or rX, [rY, #imm]
        if not ops.startswith("r") and not ops.startswith("sb") and not ops.startswith("sl") and not ops.startswith("fp"):
            continue
        try:
            src, rest = ops.split(", ", 1)
        except ValueError:
            continue
        if src not in CTRL:
            continue
        if not rest.startswith("["):
            continue
        base = rest[1:].split("]")[0].split(",")[0].strip()
        if base not in CTRL:
            continue
        # look at next 4 instructions for a chainable ending
        nxt = insns[i+1:i+5]
        txt = "; ".join(f"{w.mnemonic} {w.op_str}" for w in nxt)
        if any(w.mnemonic in ("pop", "bx") for w in nxt):
            hits.append((ins.address, ops, txt))
    print(f"controlled write gadgets: {len(hits)}")
    for a, o, t in hits[:30]:
        print(f"  {a:#010x}  str {o}   ; then: {t}")

if __name__ == "__main__":
    main()
