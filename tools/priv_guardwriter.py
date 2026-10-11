import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000
GUARD = 0xFA81584

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True
code = data[LOAD_OFF:LOAD_OFF + 0x1634BC]

def va2off(va):
    return va - LOAD_VADDR + LOAD_OFF

def regs_written(ins):
    regs = set()
    if ins.mnemonic in ("mov", "movw", "movt", "ldr", "ldrb", "ldrh", "add", "sub",
                        "and", "orr", "eor", "lsl", "lsr", "asr", "mul", "mla",
                        "pop", "ldm", "uxth", "uxth.w", "mvn", "rsb", "adr", "blx",
                        "neg", "bic"):
        try:
            ops = [op for op in ins.operands if op.type == 1]
            if ops:
                regs.add(ins.reg_name(ops[0].reg))
        except Exception:
            pass
    if ins.mnemonic == "bl":
        for r in ("r0", "r1", "r2", "r3", "r12"):
            regs.add(r)
    return regs

pend = {}
hits = []
insns = list(md.disasm(code, LOAD_VADDR))
for ins in insns:
    if ins.mnemonic == "movw":
        p = ins.op_str.split(", #")
        if len(p) == 2:
            try:
                pend[p[0].strip()] = (ins.address, int(p[1], 16))
            except Exception:
                pass
        continue
    if ins.mnemonic == "movt":
        p = ins.op_str.split(", #")
        if len(p) == 2 and p[0].strip() in pend:
            a, lo = pend.pop(p[0].strip())
            try:
                full = (int(p[1], 16) << 16) | lo
            except Exception:
                continue
            if full == GUARD:
                hits.append((a, p[0].strip()))
        continue

print("movw/movt pairs -> guard:", [(hex(a), r) for a, r in hits])

for a, reg in hits:
    off = va2off(a)
    print(f"=== guard ref @{a:#x} (reg {reg}) ===")
    done = False
    n = 0
    for ins in insns:
        if ins.address <= a:
            continue
        if n > 25:
            break
        n += 1
        if ins.mnemonic in ("str", "strb", "strh") and ins.op_str.startswith(f"[{reg}"):
            print(f"  -> {ins.address:#010x} {ins.mnemonic} {ins.op_str}   <== GUARD WRITE")
        if reg in regs_written(ins):
            break
        if ins.mnemonic in ("bx", "pop") and "pc" in ins.op_str:
            break
        if ins.mnemonic == "b" and ins.op_str[0] == "#":
            print(f"  (branch at {ins.address:#x})")
