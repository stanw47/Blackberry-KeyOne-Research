import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_REG, ARM_OP_IMM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000
FILE_BASE = LOAD_VADDR - LOAD_OFF
STATE = 0xFA63058  # LCG state

def va2off(va):
    return va - FILE_BASE

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True
code = data[LOAD_OFF:LOAD_OFF + 0x1634BC]

# 1) dword pointer tables referencing state addr
print("=== dword ptrs to LCG state ===")
for off in range(0, len(data) - 3, 4):
    val = struct.unpack("<I", data[off:off+4])[0]
    if val == STATE:
        print(f"  file@{off:#x} va@{off+FILE_BASE:#x}")

# 2) movw/movt refs + following str
print("=== movw/movt refs to LCG state ===")
pend = {}
insns = list(md.disasm(code, LOAD_VADDR))
for idx, ins in enumerate(insns):
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
            if full == STATE:
                reg = p[0].strip()
                print(f"  ref@{a:#x} (reg {reg}):")
                for ins2 in insns:
                    if ins2.address <= a:
                        continue
                    if ins2.address > a + 0x40:
                        break
                    if ins2.mnemonic in ("str", "strb", "strh") and f"[{reg}" in ins2.op_str:
                        print(f"      {ins2.address:#010x} {ins2.mnemonic} {ins2.op_str}")
                    if ins2.mnemonic == "movw" or ins2.mnemonic == "movt":
                        if ins2.op_str.startswith(reg + ","):
                            break
