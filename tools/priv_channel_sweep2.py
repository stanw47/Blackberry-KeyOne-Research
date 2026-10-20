import struct, re, subprocess, os, sys

BIN = r"C:\Users\Stanley Williamson\Desktop\Blackberry KeyOne Research\firmware\keyone-abl766\ABL766 - Hn03\host\windows-x86\bin\authboot.exe"
WORK = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-auth"

def make_patched(name):
    d = bytearray(open(BIN, 'rb').read())
    pe = struct.unpack('<I', d[0x3c:0x40])[0]
    machine, nsect, ts, symptr, nsyms, optsz, chars = struct.unpack('<HHIIIHH', d[pe+4:pe+24])
    opt = pe + 24
    imgbase = struct.unpack('<I', d[opt+28:opt+32])[0]
    secs = []
    for i in range(nsect):
        s = d[opt+optsz+i*40:opt+optsz+(i+1)*40]
        vsize, va, rsize, rptr = struct.unpack('<IIII', s[8:24])
        secs.append((va, vsize, rptr, rsize))
    old_va = imgbase + 0xa86ac
    p = struct.pack('<I', old_va)
    refs = [m.start() for m in re.finditer(re.escape(p), bytes(d))]
    code_refs = [r for r in refs if r < 0x9d400]
    new_str = name.encode() + b'\x00'
    rdata = secs[2]
    gap = None
    for off in range(rdata[2] + rdata[3] - 0x800, rdata[2] + rdata[3] - len(new_str)):
        if bytes(d[off:off+len(new_str)]) == b'\x00' * len(new_str):
            gap = off
            break
    assert gap is not None, f"no slack for {name}"
    new_va = imgbase + (rdata[0] + (gap - rdata[2]))
    d[gap:gap+len(new_str)] = new_str
    for r in code_refs:
        d[r:r+4] = struct.pack('<I', new_va)
    out = os.path.join(WORK, "ab_sweep.exe")
    open(out, 'wb').write(d)
    return out

names = [
    "AUTHBOOT-veniceunlocked",
    "AUTHBOOT-venicestv100",
    "AUTHBOOT-stv100-1",
    "NVSIG-venicena",
    "NVSIG-veniceunlocked",
    "DBGSIG-venicena",
]
exe = None
for name in names:
    exe = make_patched(name)
    print(f"=== trying {name} ===", flush=True)
    try:
        r = subprocess.run([exe, '-s', '1161797525', '-d', '6148', 'getvar', 'authboot_api_ver'],
                           cwd=WORK, capture_output=True, text=True, timeout=45)
        out = (r.stdout or '') + (r.stderr or '')
    except subprocess.TimeoutExpired:
        out = '(timeout)'
    print(out.strip()[:500], flush=True)
    subprocess.run(['taskkill', '/F', '/IM', 'ab_sweep.exe'], capture_output=True)
