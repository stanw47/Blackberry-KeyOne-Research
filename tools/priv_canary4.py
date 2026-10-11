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

print("=== full FUNC 0xf916460 (old-style SCM) ===")
for ins in md.disasm(data[va2off(0xF916460):va2off(0xF916640)], 0xF916460):
    print(f"{ins.address:#010x} {ins.mnemonic} {ins.op_str}")

print()
print("=== callers of 0xf916ce4 (canary init) ===")
callers = []
for ins in md.disasm(code, LOAD_VADDR):
    if ins.mnemonic == "bl" and ins.op_str == "#0xf916ce4":
        callers.append(ins.address)
print([hex(c) for c in callers])

for c in callers[:6]:
    print(f"=== around caller {c:#x} ===")
    for ins in md.disasm(data[va2off(c-0x40):va2off(c+0x40)], c-0x40):
        print(f"{ins.address:#010x} {ins.mnemonic} {ins.op_str}")
    print()
