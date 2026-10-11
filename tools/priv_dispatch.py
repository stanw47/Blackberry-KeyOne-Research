import struct
from collections import Counter
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

cands = Counter()
locs = {}
va = LOAD_VADDR
while va < CODE_END_VA:
    chunk = data[va2off(va):va2off(va) + 0x1000]
    for ins in md.disasm(chunk, va):
        if ins.mnemonic in ("cmp", "subs") and ins.op_str.startswith("r") and ", #" in ins.op_str:
            try:
                val = int(ins.op_str.split(", #")[1].split(",")[0], 16)
            except Exception:
                continue
            if 0x1000 <= val <= 0x2100:
                cands[val] += 1
                locs.setdefault(val, []).append(ins.address)
        elif ins.mnemonic == "movw" and ", #" in ins.op_str:
            try:
                val = int(ins.op_str.split(", #")[1], 16)
            except Exception:
                continue
            if val in (0x8701, 0xa701):
                cands.setdefault(f"movw-{val:#x}", 0)
                cands[f"movw-{val:#x}"] += 1
                locs.setdefault(f"movw-{val:#x}", []).append(ins.address)
    va += 0x1000

for val, cnt in cands.most_common(40):
    print(f"  cmp/val {val:#x}: {cnt}x  e.g. {[hex(a) for a in locs[val][:4]]}")
