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

def dis(start, end, label):
    print(f"=== {label} ===")
    for ins in md.disasm(data[va2off(start):va2off(end)], start):
        print(f"{ins.address:#010x} {ins.mnemonic} {ins.op_str}")
    print()

dis(0xF916E94, 0xF916F40, "get_canary 0xf916e3c (tail: guard write?)")
dis(0xF971798, 0xF971860, "fallback RNG 0xf971798")
dis(0xF916328, 0xF9163C0, "scm wrapper 0xf916328")
dis(0xF916234, 0xF916330, "0xf916234 (buf get)")

# who writes the flag 0xfa81f90?
print("=== refs to 0xfa81f90 (flag) ===")
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
            if full == 0xFA81F90:
                refs.append((a, p[0].strip()))
print([(hex(a), r) for a, r in refs])
