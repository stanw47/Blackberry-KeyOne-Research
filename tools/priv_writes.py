import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000
FILE_BASE = LOAD_VADDR - LOAD_OFF
CODE_END_VA = LOAD_VADDR + 0x1634BC

TARGETS = {0xFA63058: "LCG-state", 0xFA81584: "guard", 0xFA81F90: "secure-canary-flag"}

def va2off(va):
    return va - FILE_BASE

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

found = []
pend = {}
va = LOAD_VADDR
while va < CODE_END_VA:
    chunk = data[va2off(va):va2off(va) + 0x1000]
    pend = {}
    for ins in md.disasm(chunk, va):
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
                if full in TARGETS:
                    found.append((a, p[0].strip(), TARGETS[full]))
    va += 0x1000

print("movw/movt refs:")
for a, r, name in found:
    print(f"  {a:#010x} reg={r} -> {name}")

for a, r, name in found:
    print(f"=== around {a:#x} ({name}, reg {r}) ===")
    for ins in md.disasm(data[va2off(a - 0x30):va2off(a + 0x40)], a - 0x30):
        mark = ""
        if ins.mnemonic in ("str", "strb", "strh") and f"[{r}" in ins.op_str and ins.address > a:
            mark = "   <== WRITE"
        if ins.address > a + 0x38:
            break
        print(f"{ins.address:#010x} {ins.mnemonic} {ins.op_str}{mark}")
    print()
