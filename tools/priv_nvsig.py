import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000

def va2off(va):
    return va - LOAD_VADDR + LOAD_OFF

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
code = data[LOAD_OFF:LOAD_OFF + 0x1634BC]

TARGETS = [0xF9D5A10, 0xF9CFCD0]  # "NVSIG..." and "rtas"
labels = {0xF9D5A10: "NVSIG-str", 0xF9CFCD0: "rtas-str"}

for t in TARGETS:
    print(f"=== refs to {labels[t]} ({t:#x}) ===")
    pend = {}
    refs = []
    insns = list(md.disasm(code, LOAD_VADDR))
    for ins in insns:
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
                if full == t:
                    refs.append(a)
    print([hex(a) for a in refs])
    for a in refs[:4]:
        print(f"--- around {a:#x} ---")
        for ins in md.disasm(data[va2off(a-0x60):va2off(a+0x40)], a-0x60):
            print(f"{ins.address:#010x} {ins.mnemonic} {ins.op_str}")
        print()
