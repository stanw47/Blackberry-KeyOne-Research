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

def disasm_range(start, end, label):
    print(f"=== {label} {start:#x}-{end:#x} ===")
    for ins in md.disasm(data[va2off(start):va2off(end)], start):
        print(f"{ins.address:#010x} {ins.mnemonic} {ins.op_str}")
    print()

disasm_range(0xF9163C0, 0xF9164C0, "FUNC 0xf916460 (mystery call)")
disasm_range(0xF916640, 0xF9166D0, "FUNC 0xf9166a8 (scm send?)")
disasm_range(0xF9168A0, 0xF9169C0, "FUNC guard-writer ~0xf916920")
disasm_range(0xF920F20, 0xF920F80, "FUNC 0xf920f3c (mystery 2)")
