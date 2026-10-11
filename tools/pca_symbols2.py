import struct

path = r"C:\Users\Stanley Williamson\Desktop\Blackberry KeyOne Research\firmware\keyone-abl766\ABL766 - Hn03\host\windows-x86\bin\pcauthtool.exe"
d = open(path, 'rb').read()
pe_off = struct.unpack('<I', d[0x3c:0x40])[0]
machine, nsect, ts, symptr, nsyms, optsz, chars = struct.unpack('<HHIIIHH', d[pe_off+4:pe_off+24])

# sections
secs = []
opt_off = pe_off + 24
for i in range(nsect):
    s = d[opt_off + optsz + i*40 : opt_off + optsz + (i+1)*40]
    name = s[:8].rstrip(b'\x00').decode('latin1')
    vsize, va, rsize, rptr = struct.unpack('<IIII', s[8:24])
    secs.append((name, va, rsize, rptr))
    print(f"sec {i}: {name} va={va:#x} rsize={rsize:#x} rptr={rptr:#x}")

strtab_off = symptr + nsyms*18
strtab_len = struct.unpack('<I', d[strtab_off:strtab_off+4])[0]
strtab = d[strtab_off:strtab_off+strtab_len]
def sname(off):
    e = strtab.find(b'\x00', off)
    return strtab[off:e].decode('latin1')

def sec_va(i):
    return secs[i-1][1] if 1 <= i <= nsect else None

syms = []
i = 0
while i < nsyms:
    e = d[symptr+i*18:symptr+(i+1)*18]
    if e[:4] == b'\x00\x00\x00\x00':
        noff = struct.unpack('<I', e[4:8])[0]
        name = sname(noff)
    else:
        name = e[:8].rstrip(b'\x00').decode('latin1')
    val, secnum, typ, scls, naux = struct.unpack('<IhHBB', e[8:18])
    syms.append((name, val, secnum, scls))
    i += 1 + naux

print("total:", len(syms))
funcs = [s for s in syms if s[2] == 1 and s[3] == 3]  # static funcs in .text
print("static funcs in .text:", len(funcs))
for name, val, sec, cls in funcs:
    va = sec_va(sec) + val
    if any(k in name.lower() for k in ('auth', 'rtas', 'chall', 'packet', 'usb', 'send', 'verify', 'cred', 'sign', 'password', 'handshake', 'frame', 'nv', 'open', 'connect', 'server', 'host', 'resolve')):
        print(f"  {name:48s} va={va:#x}")
