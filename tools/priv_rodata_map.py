import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000
FILE_BASE = LOAD_VADDR - LOAD_OFF

def va2off(va):
    return va - FILE_BASE

LO_RO = 0xF9C0000
HI_RO = 0xF9E0000

print("=== dword pointers into rodata region ===")
for off in range(0, len(data) - 3, 4):
    val = struct.unpack("<I", data[off:off+4])[0]
    if LO_RO <= val < HI_RO:
        print(f"  file@{off:#x} va@{off+FILE_BASE:#x} -> {val:#x}")

print()
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True
code = data[LOAD_OFF:LOAD_OFF + 0x1634BC]
print("=== movw/movt refs into rodata region ===")
pend = {}
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
            if LO_RO <= full < HI_RO:
                print(f"  {a:#x} (reg {p[0].strip()}) -> {full:#x}")
