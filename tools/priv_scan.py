import struct
from collections import Counter
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000

def va2off(va):
    return va - LOAD_VADDR + LOAD_OFF

def off2va(off):
    return off - LOAD_OFF + LOAD_VADDR

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
code = data[LOAD_OFF:LOAD_OFF + 0x1634bc]
pend = {}
counter = Counter()
for ins in md.disasm(code, LOAD_VADDR):
    if ins.mnemonic == "movw":
        p = ins.op_str.split(", #")
        if len(p) == 2:
            try: pend[p[0].strip()] = int(p[1], 16)
            except Exception: pass
    elif ins.mnemonic == "movt":
        p = ins.op_str.split(", #")
        if len(p) == 2 and p[0].strip() in pend:
            lo = pend.pop(p[0].strip())
            try: full = (int(p[1], 16) << 16) | lo
            except Exception: continue
            counter[full] += 1
    else:
        try: pend.pop(ins.op_str.split(",")[0].strip(), None)
        except Exception: pass

print("top movw/movt address constants (candidate guard/globals):")
for addr, cnt in counter.most_common(15):
    print(f"  {addr:#010x} x{cnt}")

# strings
for s in (b"scm_call for random", b"Invalid message cookie", b"NVSIG", b"resp_len", b"rtas", b"canary", b"stack"):
    off = data.find(s)
    print(s, "->", hex(off2va(off)) if off >= 0 else "NOT FOUND")
