import struct

path = r"C:\Users\Stanley Williamson\Desktop\Blackberry KeyOne Research\firmware\keyone-abl766\ABL766 - Hn03\host\windows-x86\bin\authboot.exe"
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
strtab_off = symptr + nsyms*18
strtab_len = struct.unpack('<I', d[strtab_off:strtab_off+4])[0]
strtab = d[strtab_off:strtab_off+strtab_len]
def sname(off):
    e = strtab.find(b'\x00', off)
    return strtab[off:e].decode('latin1')

imp_rva, _ = struct.unpack('<II', d[opt+104:opt+112])
off = rva2off(imp_rva)
thunks = {}
i = 0
while True:
    e = d[off+i*20:off+(i+1)*20]
    if len(e) < 20:
        break
    oft, _, _, name_rva, ft_rva = struct.unpack('<IIIII', e)
    if oft == 0:
        break
    noff = rva2off(name_rva)
    nm = d[noff:noff+64].split(b'\x00')[0].decode()
    toff = rva2off(ft_rva)
    j = 0
    while toff:
        slot = rva2off(ft_rva + j*4)
        val = struct.unpack('<I', d[slot:slot+4])[0]
        if val == 0:
            break
        thunks[imgbase + ft_rva + j*4] = nm
        j += 1
    i += 1

for k in range(0x4bc424, 0x4bc470, 4):
    print(f'{k:#x}: {thunks.get(k, "?")}')

i = 0
while i < nsyms:
    e = d[symptr+i*18:symptr+(i+1)*18]
    if e[:4] == b'\x00\x00\x00\x00':
        name = sname(struct.unpack('<I', e[4:8])[0])
    else:
        name = e[:8].rstrip(b'\x00').decode('latin1')
    val, secnum, typ, scls, naux = struct.unpack('<IhHBB', e[8:18])
    va = secs[secnum-1][0] + val if 1 <= secnum <= nsect else 0
    if scls == 3 and 0x405f00 <= va <= 0x406f00:
        print(f'sym {name!r} at {va:#x}')
    i += 1 + naux
