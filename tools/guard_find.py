#!/usr/bin/env python3
"""guard_find.py - find the runtime initializer of the stack guard (0x8f7c2ed0)."""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"firmware\keyone-abl766\ABL766 - Hn03\target\product\bbry_qc8953\emmc_appsboot.mbn"
GUARD = 0x8F7C2ED0

def main():
    data = open(BIN, "rb").read()
    e_phoff = struct.unpack("<I", data[0x1C:0x20])[0]
    e_phentsize = struct.unpack("<H", data[0x2A:0x2C])[0]
    e_phnum = struct.unpack("<H", data[0x2C:0x2E])[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack("<IIIIIIII", data[o:o+32])
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for va, off, filesz, memsz, flags in segs:
        code = data[off:off+filesz]
        insns = list(md.disasm(code, va))
        # track which register currently holds GUARD (from movw/movt)
        for i, ins in enumerate(insns):
            if ins.mnemonic == "movw":
                p = ins.op_str.split(", #")
                if len(p) != 2: continue
                try: lo = int(p[1], 16)
                except Exception: continue
                reg = p[0].strip()
                # look ahead: movt same reg, then up to 20 insns for str via that reg (allow mov/add chains)
                j = i + 1
                hi = None
                while j < min(i+6, len(insns)):
                    if insns[j].mnemonic == "movt" and insns[j].op_str.startswith(reg + ","):
                        hi = int(insns[j].op_str.split(", #")[1], 16)
                        break
                    j += 1
                if hi is None: continue
                if ((hi << 16) | lo) != GUARD: continue
                # found a movw/movt pair loading GUARD into reg at insns[j]
                # scan ahead for a store whose base is reg (or a reg copied from it)
                aliases = {reg}
                for k in range(j+1, min(j+24, len(insns))):
                    kk = insns[k]
                    if kk.mnemonic == "mov" and kk.op_str.split(",")[0].strip() in aliases:
                        aliases.add(kk.op_str.split(",")[1].strip())
                    if kk.mnemonic in ("str", "strb", "strh", "stm", "stmia", "stmdb"):
                        base = None
                        if "[" in kk.op_str:
                            base = kk.op_str.split("[")[1].split("]")[0].split(",")[0].strip()
                        if base in aliases:
                            print(f"STORE candidate: ref@{insns[i].address:#x} pair@{insns[j].address:#x} -> {kk.address:#x} {kk.mnemonic} {kk.op_str}")
    print("done")

if __name__ == "__main__":
    main()
