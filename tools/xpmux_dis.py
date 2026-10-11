import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

path = r"C:\Users\Stanley Williamson\Desktop\Blackberry KeyOne Research\firmware\keyone-abl766\ABL766 - Hn03\host\windows-x86\bin\libxpmux.dll"
d = open(path, 'rb').read()
pe = struct.unpack('<I', d[0x3c:0x40])[0]
machine, nsect, ts, symptr, nsyms, optsz, chars = struct.unpack('<HHIIIHH', d[pe+4:pe+24])
opt = pe + 24
magic = struct.unpack('<H', d[opt:opt+2])[0]
imgbase = struct.unpack('<I', d[opt+28:opt+32])[0]
secs = []
for i in range(nsect):
    s = d[opt+optsz+i*40:opt+optsz+(i+1)*40]
    vsize, va, rsize, rptr = struct.unpack('<IIII', s[8:24])
    secs.append((va, vsize, rptr, rsize))

def rva2off(rva):
    for va, vsize, rptr, rsize in secs:
        if va <= rva < va+vsize:
            return rptr + (rva-va)
    return None

if magic == 0x10b:
    exp_rva, exp_size = struct.unpack('<II', d[opt+96:opt+104])
else:
    exp_rva, exp_size = struct.unpack('<II', d[opt+112:opt+120])
print("image base", hex(imgbase), "exp dir rva", hex(exp_rva))
off = rva2off(exp_rva)
chars2, ts2, maj, min, namerva, ordinalbase, nfunc, nnames, afun, anames, aords = struct.unpack('<IIHHIIIIIII', d[off:off+40])
exports = []
foff = rva2off(afun)
noff_base = rva2off(anames)
for j in range(nfunc):
    ordi = j + ordinalbase
    frva = struct.unpack('<I', d[foff+j*4:foff+j*4+4])[0]
    name = f"ordinal_{ordi}"
    if j < nnames and noff_base:
        nrv = struct.unpack('<I', d[noff_base+j*4:noff_base+j*4+4])[0]
        noff = rva2off(nrv)
        if noff:
            name = d[noff:noff+80].split(b'\x00')[0].decode()
    if frva:
        exports.append((name, frva))
print("exports:", exports)

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

def disasm_rva(rva, nbytes, label):
    o = rva2off(rva)
    if o is None:
        return
    print(f"=== {label} @rva {rva:#x} ===")
    cnt = 0
    for ins in md.disasm(d[o:o+nbytes], imgbase + rva):
        print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
        cnt += 1
        if cnt > 70:
            break
    print()

for name, rva in exports:
    disasm_rva(rva, 0x400, name)
