import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_REG, ARM_OP_IMM

path = r"C:\Users\Stanley Williamson\Desktop\Blackberry KeyOne Research\firmware\keyone-abl766\ABL766 - Hn03\target\product\bbry_qc8953\emmc_appsboot.mbn"
d = open(path, 'rb').read()
BASE = 0x8f600000
OFF = 0x8000
LOAD_SZ = 0x1a526c
md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True
code = d[OFF:OFF+LOAD_SZ]

def find_str(s):
    i = d.find(s)
    if i < 0:
        return None
    return BASE + (i - OFF)

targets = {
    b'Skipping Factory transistion wipe': 'Skipping-wipe',
    b'Wipe failed, Cannot switch bootmode': 'Wipe-failed',
    b'Attempting to switch mode to FACTORY MODE': 'Factory-switch',
}
tv = {}
for s, n in targets.items():
    va = find_str(s)
    print(n, 'va', hex(va) if va else None)
    if va:
        tv[va] = n

# literal pool scan
print("literal-pool refs:")
for ins in md.disasm(code, BASE):
    if ins.mnemonic != 'ldr':
        continue
    base = None
    imm = None
    for op in ins.operands:
        if op.type == 3 and op.mem.base != 0 and ins.reg_name(op.mem.base) == 'pc':
            base = 'pc'
            imm = op.mem.disp
    if base is None:
        continue
    pool = (ins.address & ~3) + 8 + imm
    po = pool - BASE + OFF
    if not (0 <= po < len(d) - 3):
        continue
    val = struct.unpack('<I', d[po:po+4])[0]
    if val in tv:
        print(f"  {ins.address:#x}: ldr -> {tv[val]}")
