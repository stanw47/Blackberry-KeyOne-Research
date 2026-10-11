import struct, re
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

path = r"C:\Users\Stanley Williamson\Desktop\Blackberry KeyOne Research\firmware\keyone-abl766\ABL766 - Hn03\target\product\bbry_qc8953\emmc_appsboot.mbn"
d = open(path, 'rb').read()
BASE = 0x8f600000
OFF = 0x8000
LOAD_SZ = 0x1a526c

def off2va(o):
    return BASE + (o - OFF)
def va2off(va):
    return va - BASE + OFF

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
code = d[OFF:OFF+LOAD_SZ]

# symtab: ELF32 shoff=0x1ad308; find .symtab
e_shoff = 0x1ad308
e_shentsize = 40
e_shnum = 12
symtab_off = None
symtab_size = None
strtab_off = None
strtab_size = None
for i in range(e_shnum):
    o = e_shoff + i*40
    name_off, typ, flags, addr, off_, size, link, info, align, entsize = struct.unpack('<IIIIIIIIII', d[o:o+40])
    if typ == 2 and addr == 0 and size == 0x1f290:  # symtab
        symtab_off = off_
        symtab_size = size
        strtab_off = None
        so = e_shoff + link*40
        _, _, _, _, str_off, str_size, _, _, _, _ = struct.unpack('<IIIIIIIIII', d[so:so+40])
        strtab_off = str_off
        strtab_size = str_size
        break

def sname(off):
    e = d.find(b'\x00', strtab_off + off)
    return d[strtab_off+off:e].decode('latin1')

syms = []
n = symtab_size // 16
for i in range(n):
    e = d[symtab_off+i*16:symtab_off+(i+1)*16]
    name_off, value, size, info, other, shndx = struct.unpack('<IIIBBH', e)
    if shndx != 0 and value:
        syms.append((sname(name_off), value, size))
print("symtab entries:", len(syms))

# strings of interest
targets = {
    'FACTORY switch': b'Attempting to switch mode to FACTORY MODE',
    'Skipping wipe': b'Skipping Factory transistion wipe',
    'Wipe failed': b'Wipe failed, Cannot switch bootmode',
    'INITIATING SECURE WIPE': b'bbauthtool: INITIATING SECURE WIPE!',
    'set_pending_wipe': b'set_pending_wipe failed: %d',
}
for name, s in targets.items():
    i = d.find(s)
    va = off2va(i) if i >= 0 else None
    print(f"{name}: file {i:#x} va {va:#x}")

# movw/movt refs to each target VA
TARGET_VAS = {}
for name, s in targets.items():
    i = d.find(s)
    if i >= 0:
        TARGET_VAS[off2va(i)] = name

pend = {}
refs = []
for ins in md.disasm(code, BASE):
    if ins.mnemonic == 'movw':
        p = ins.op_str.split(', #')
        if len(p) == 2:
            try: pend[p[0].strip()] = (ins.address, int(p[1], 16))
            except Exception: pass
    elif ins.mnemonic == 'movt':
        p = ins.op_str.split(', #')
        if len(p) == 2 and p[0].strip() in pend:
            a, lo = pend.pop(p[0].strip())
            try: full = (int(p[1], 16) << 16) | lo
            except Exception: continue
            if full in TARGET_VAS:
                refs.append((a, TARGET_VAS[full]))
print("refs:")
for a, name in refs:
    # find containing symbol
    func = None
    for n, v, sz in syms:
        if v <= a < v + sz:
            func = (n, v, sz)
    print(f"  {a:#x} -> {name}   func: {func}")
