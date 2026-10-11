import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_REG, ARM_OP_IMM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000
CODE_END = LOAD_VADDR + 0x1634BC

def va2off(va):
    return va - LOAD_VADDR + LOAD_OFF

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True
code = data[LOAD_OFF:LOAD_OFF + 0x1634BC]

TARGETS = {0xF9D5A10: "NVSIG-str", 0xF9CFCD0: "rtas-str",
           0xF9C7460: "Secure-canary", 0xF9C7480: "scm-rand-failed",
           0xF9D4468: "insecure-device", 0xF9D4494: "debug-token-skip"}

insns = list(md.disasm(code, LOAD_VADDR))
print("=== literal-pool xrefs ===")
for ins in insns:
    if ins.mnemonic != "ldr":
        continue
    base = None
    imm = None
    for op in ins.operands:
        if op.type == 3:  # mem
            if op.mem.base != 0 and ins.reg_name(op.mem.base) == "pc":
                base = "pc"
                imm = op.mem.disp
    if base is None or imm is None:
        continue
    pool_addr = (ins.address & ~3) + 8 + imm
    if not (LOAD_VADDR <= pool_addr < CODE_END):
        continue
    val = struct.unpack("<I", data[va2off(pool_addr):va2off(pool_addr)+4])[0]
    if val in TARGETS:
        dst = ins.operands[0]
        dreg = ins.reg_name(dst.reg) if dst.type == 1 else "?"
        print(f"{ins.address:#010x}: ldr {dreg}, [pc, #{imm:#x}] -> {TARGETS[val]} ({val:#x}) pool@{pool_addr:#x}")
