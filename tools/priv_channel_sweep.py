import struct, re, subprocess, time, os, sys

BIN = r"C:\Users\Stanley Williamson\Desktop\Blackberry KeyOne Research\firmware\keyone-abl766\ABL766 - Hn03\host\windows-x86\bin\authboot.exe"
WORK = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-auth"

def make_patched(suffix):
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
    code_refs = [r for r in refs if r < 0x9d400]  # .text only
    new_str = f"AUTHBOOT-venice{suffix}\x00".encode()
    rdata = secs[2]
    gap = None
    for off in range(rdata[2] + rdata[3] - 0x800, rdata[2] + rdata[3] - len(new_str)):
        if bytes(d[off:off+len(new_str)]) == b'\x00' * len(new_str):
            gap = off
            break
    assert gap is not None
    new_va = imgbase + (rdata[0] + (gap - rdata[2]))
    d[gap:gap+len(new_str)] = new_str
    for r in code_refs:
        d[r:r+4] = struct.pack('<I', new_va)
    out = os.path.join(WORK, f"ab_{suffix}.exe")
    open(out, 'wb').write(d)
    return out

results = []
for suffix in ['att', 'emea', 'vzw', 'na', 'sprint']:
    exe = make_patched(suffix)
    print(f"=== trying venice{suffix} ===", flush=True)
    t0 = time.time()
    try:
        r = subprocess.run([exe, '-s', '1161797525', '-d', '6148', 'getvar', 'authboot_api_ver'],
                           cwd=WORK, capture_output=True, text=True, timeout=60)
        out = (r.stdout or '') + (r.stderr or '')
    except subprocess.TimeoutExpired:
        out = '(timeout)'
    print(out.strip()[:600], flush=True)
    results.append((suffix, out))
    # kill any leftover
    subprocess.run(['taskkill', '/F', '/IM', f'ab_{suffix}.exe'], capture_output=True)

print('=== SUMMARY ===')
for s, o in results:
    print(s, '->', [l for l in o.splitlines() if 'channel' in l.lower() or 'attempt' in l.lower() or 'correct' in l.lower()])
