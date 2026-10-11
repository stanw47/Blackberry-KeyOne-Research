import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000
FILE_BASE = LOAD_VADDR - LOAD_OFF

def va2off(va):
    return va - FILE_BASE

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

def dis(start, end, label):
    print(f"=== {label} ===")
    for ins in md.disasm(data[va2off(start):va2off(end)], start):
        print(f"{ins.address:#010x} {ins.mnemonic} {ins.op_str}")
    print()

dis(0xF931960, 0xF931C00, "packet layer around sendNextPacket")
