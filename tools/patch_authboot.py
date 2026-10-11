import struct, re, shutil, sys

path = r"C:\Users\Stanley Williamson\Desktop\Blackberry KeyOne Research\firmware\keyone-abl766\ABL766 - Hn03\host\windows-x86\bin\authboot.exe"
outpath = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-auth\authboot_patched.exe"

d = bytearray(open(path, 'rb').read())
pe = struct.unpack('<I', d[0x3c:0x40])[0]
nsect, _, _, _, _, optsz, _ = struct.unpack('<HHIIIHH', d[pe+4:pe+24])
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

old_va = imgbase + 0xa86ac
p = struct.pack('<I', old_va)
refs = [m.start() for m in re.finditer(re.escape(p), bytes(d))]
print("refs to AUTHBOOT string:", [hex(rva2off(r)) for r in refs])

new_str = b"AUTHBOOT-venicena\x00"
# slack region: end of .rdata
rdata = secs[2]
slack_off = rdata[2] + rdata[3]
# find a zero-filled gap near the end of rdata
gap = None
for off in range(slack_off - 0x800, slack_off - len(new_str)):
    if bytes(d[off:off+len(new_str)]) == b'\x00' * len(new_str):
        gap = off
        break
assert gap is not None, "no slack found"
new_rva = rdata[0] + (gap - rdata[2])
new_va = imgbase + new_rva
print(f"placing '{new_str.decode()}' at file off {gap:#x}, rva {new_rva:#x}, va {new_va:#x}")

d[gap:gap+len(new_str)] = new_str
for r in refs:
    d[r:r+4] = struct.pack('<I', new_va)
    print(f"patched ref at file off {r:#x} (rva {rva2off(r):#x})")

open(outpath, 'wb').write(d)
print("wrote", outpath)
