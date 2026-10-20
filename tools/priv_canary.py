import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000
GUARD = 0x0FA81584

def va2off(va):
    return va - LOAD_VADDR + LOAD_OFF

# strings around the canary area
for va in (0xF9C7460, 0xF9C7470, 0xF9C7480, 0xF9C74A0):
    i = va2off(va)
    print(hex(va), ":", data[i:i+64].split(b"\x00")[0])

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
code = data[LOAD_OFF:LOAD_OFF + 0x1634BC]
pend = {}
print()
print("stores near guard refs:")
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
            if full == GUARD:
                reg = p[0].strip()
                o2 = a - LOAD_VADDR + LOAD_OFF
                n = 0
                for ins2 in md.disasm(data[o2:o2+64], a):
                    n += 1
                    if n > 16: break
                    if ins2.mnemonic in ("str", "strb", "strh") and f"[{reg}" in ins2.op_str:
                        print(f"  ref@{a:#x} -> {ins2.address:#x} {ins2.mnemonic} {ins2.op_str}")
    else:
        try: pend.pop(ins.op_str.split(",")[0].strip(), None)
        except Exception: pass
