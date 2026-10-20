import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000
TARGET_STR = 0xF9C7460  # "Secure canary SCM failed: %x"

def va2off(va):
    return va - LOAD_VADDR + LOAD_OFF

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
code = data[LOAD_OFF:LOAD_OFF + 0x1634BC]
pend = {}
refs = []
for ins in md.disasm(code, LOAD_VADDR):
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
            if full == TARGET_STR:
                refs.append((a, p[0].strip()))
    else:
        try: pend.pop(ins.op_str.split(",")[0].strip(), None)
        except Exception: pass

print("refs to 'Secure canary SCM failed':", [(hex(a), r) for a, r in refs])
# disassemble around the first ref (the function containing it)
for a, reg in refs[:1]:
    start = a - 0x120
    print(f"=== disasm around {a:#x} ===")
    for ins in md.disasm(data[va2off(start):va2off(a)+0x60], start):
        print(f"{ins.address:#010x} {ins.mnemonic} {ins.op_str}")
