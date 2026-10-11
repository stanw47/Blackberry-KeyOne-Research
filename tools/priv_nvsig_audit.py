import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000
FILE_BASE = LOAD_VADDR - LOAD_OFF
CODE_END_VA = LOAD_VADDR + 0x1634BC

def va2off(va):
    return va - FILE_BASE

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

def dis(start, end, label):
    print(f"=== {label} ===")
    for ins in md.disasm(data[va2off(start):va2off(end)], start):
        print(f"{ins.address:#010x} {ins.mnemonic} {ins.op_str}")
    print()

dis(0xF9534C0, 0xF954400, "nv_sig challenge/response handlers")

# cookie scan
print("=== movw/movt -> 0xbba78701 ===")
found = []
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
                if full == 0xbba78701:
                    found.append(a)
    va += 0x1000
print([hex(a) for a in found])
