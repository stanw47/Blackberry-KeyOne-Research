#!/usr/bin/env python3
"""guard_init.py - find any store to the stack-guard global (0x8f7c2ed0) in all segments."""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"firmware\keyone-abl766\ABL766 - Hn03\target\product\bbry_qc8953\emmc_appsboot.mbn"
GUARD = 0x8F7C2ED0

def main():
    data = open(BIN, "rb").read()
    # ELF program headers
    e_phoff = struct.unpack("<I", data[0x1C:0x20])[0]
    e_phentsize = struct.unpack("<H", data[0x2A:0x2C])[0]
    e_phnum = struct.unpack("<H", data[0x2C:0x2E])[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack("<IIIIIIII", data[o:o+32])
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))
            print(f"LOAD seg va={p_vaddr:#x} off={p_offset:#x} filesz={p_filesz:#x} memsz={p_memsz:#x} flags={p_flags:#x}")
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for va, off, filesz, memsz, flags in segs:
        if not (flags & 1):
            continue
        code = data[off:off+filesz]
        pend = {}
        for ins in md.disasm(code, va):
            if ins.mnemonic == "movw":
                p = ins.op_str.split(", #")
                if len(p) == 2:
                    try: pend[p[0].strip()] = (ins.address, int(p[1], 16))
                    except Exception: pass
            elif ins.mnemonic == "movt":
                p = ins.op_str.split(", #")
                if len(p) == 2 and p[0].strip() in pend:
                    a, lo = pend.pop(p[0].strip())
                    try: full = (int(p[1], 16) << 16) | lo
                    except Exception: continue
                    if full == GUARD:
                        # look ahead for str using this reg
                        reg = p[0].strip()
                        o2 = a - va + off
                        n = 0
                        for ins2 in md.disasm(data[o2:o2+64], a):
                            n += 1
                            if n > 16: break
                            if ins2.mnemonic in ("str", "strb", "strh") and f"[{reg}" in ins2.op_str:
                                print(f"STORE to guard: ref@{a:#x} -> {ins2.address:#x} {ins2.mnemonic} {ins2.op_str}")
            else:
                try: pend.pop(ins.op_str.split(",")[0].strip(), None)
                except Exception: pass
    # also: literal pool search for the guard address in any segment
    pat = struct.pack("<I", GUARD)
    for va, off, filesz, memsz, flags in segs:
        seg = data[off:off+filesz]
        idx = [i for i in range(len(seg)) if seg.startswith(pat, i)]
        if idx:
            print(f"literal refs in seg va={va:#x}: {[hex(va+i) for i in idx]}")

if __name__ == "__main__":
    main()
