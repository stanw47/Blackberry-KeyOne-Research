import struct, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

path = r"C:\Program Files (x86)\Common Files\Research In Motion\USB Drivers\BbDevMgr.exe"
d = open(path, 'rb').read()
pe = struct.unpack('<I', d[0x3c:0x40])[0]
machine, nsect, ts, symptr, nsyms, optsz, chars = struct.unpack('<HHIIIHH', d[pe+4:pe+24])
opt = pe + 24
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
def off2rva(o):
    for va, vsize, rptr, rsize in secs:
        if rptr <= o < rptr+rsize:
            return va + (o-rptr)
    return None

print("imgbase", hex(imgbase))
for s in [b'MUX Version', b'incompatible version', b'CHANNEL_OPEN_REQUEST', b'CHANNEL_OPEN_NAK']:
    i = d.find(s)
    if i >= 0:
        print(f"{s!r} at rva {off2rva(i):#x} (va {imgbase+off2rva(i):#x})")

# xrefs to 'incompatible version' and 'MUX Version'
for s in [b'incompatible version', b'MUX Version']:
    i = d.find(s)
    rva = off2rva(i)
    va = imgbase + rva
    p = struct.pack('<I', va)
    refs = [m.start() for m in re.finditer(re.escape(p), d)]
    print(s, 'refs:', [(hex(r), hex(off2rva(r))) for r in refs])

md = Cs(CS_ARCH_X86, CS_MODE_32)
# disasm around the first 'incompatible version' ref
i = d.find(b'incompatible version')
rva = off2rva(i)
va = imgbase + rva
p = struct.pack('<I', va)
refs = [m.start() for m in re.finditer(re.escape(p), d)]
for r in refs[:1]:
    rr = off2rva(r)
    print(f"=== around {rr:#x} ===")
    for ins in md.disasm(d[rva2off(rr-0x60):rva2off(rr+0x80)], imgbase+rr-0x60):
        print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
