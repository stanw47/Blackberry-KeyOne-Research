import struct

def imports(path):
    d = open(path, 'rb').read()
    pe = struct.unpack('<I', d[0x3c:0x40])[0]
    machine, nsect, ts, symptr, nsyms, optsz, chars = struct.unpack('<HHIIIHH', d[pe+4:pe+24])
    opt = pe + 24
    magic = struct.unpack('<H', d[opt:opt+2])[0]
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
        imp_rva, imp_size = struct.unpack('<II', d[opt+104:opt+112])
        exp_rva, exp_size = struct.unpack('<II', d[opt+96:opt+104])
    else:
        imp_rva, imp_size = struct.unpack('<II', d[opt+120:opt+128])
        exp_rva, exp_size = struct.unpack('<II', d[opt+112:opt+120])
    out = []
    off = rva2off(imp_rva)
    if off:
        i = 0
        while True:
            e = d[off+i*20:off+(i+1)*20]
            if len(e) < 20:
                break
            oft, tstamp, fw, name_rva, ft_rva = struct.unpack('<IIIII', e)
            if oft == 0:
                break
            noff = rva2off(name_rva)
            nm = d[noff:noff+64].split(b'\x00')[0].decode()
            out.append(nm)
            i += 1
    # exports
    exp = []
    off = rva2off(exp_rva)
    if off and off + 40 <= len(d):
        try:
            chars2, ts2, maj, min, namerva, ordinalbase, nfunc, nnames, afun, anames, aords = struct.unpack('<IIHHIIIIIII', d[off:off+40])
            for j in range(nnames):
                noff = rva2off(struct.unpack('<I', d[off+anames+j*4:off+anames+j*4+4])[0])
                if noff:
                    nm = d[noff:noff+80].split(b'\x00')[0].decode()
                    exp.append(nm)
        except Exception:
            pass
    return out, exp

if __name__ == '__main__':
    for f in ['libusbauth.dll', 'libxpmux.dll']:
        p = r"C:\Users\Stanley Williamson\Desktop\Blackberry KeyOne Research\firmware\keyone-abl766\ABL766 - Hn03\host\windows-x86\bin" + '\\' + f
        im, ex = imports(p)
        print('===', f, '===')
        print('imports:', im)
        print('exports:', ex)
