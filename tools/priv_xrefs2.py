import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_REG, ARM_OP_IMM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000
FILE_BASE = LOAD_VADDR - LOAD_OFF

def va2off(va):
    return va - FILE_BASE

def off2va(off):
    return off + FILE_BASE

TARGETS = {0xF9D5A10: "NVSIG-str", 0xF9CFCD0: "rtas-str",
           0xF9C7460: "Secure-canary", 0xF9C7480: "scm-rand-failed",
           0xF9D4468: "insecure-device", 0xF9D4494: "debug-token-skip",
           0xF9D4EDC: "true-str", 0xF9CB6B0: "bbss_insecure"}

print("=== dword scans (pointer tables) ===")
for off in range(0, len(data) - 3, 4):
    val = struct.unpack("<I", data[off:off+4])[0]
    if val in TARGETS:
        print(f"  file@{off:#x} va@{off2va(off):#x} = {TARGETS[val]} ({val:#x})")

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True
code = data[LOAD_OFF:LOAD_OFF + 0x1634BC]

print("=== adr-based refs ===")
for ins in md.disasm(code, LOAD_VADDR):
    if ins.mnemonic == "adr":
        dst = ins.operands[0].reg
        imm = ins.operands[1].imm
        target = (ins.address & ~3) + 8 + imm
        if target in TARGETS:
            print(f"{ins.address:#010x}: adr {ins.reg_name(dst)}, {TARGETS[target]} ({target:#x})")
    elif ins.mnemonic == "add":
        # add rX, pc, #imm
        if ins.operands[1].type == 1 and ins.reg_name(ins.operands[1].reg) == "pc" and ins.operands[2].type == 2:
            target = (ins.address & ~3) + 8 + ins.operands[2].imm
            if target in TARGETS:
                print(f"{ins.address:#010x}: add {ins.reg_name(ins.operands[0].reg)}, pc, #{ins.operands[2].imm:#x} -> {TARGETS[target]} ({target:#x})")
