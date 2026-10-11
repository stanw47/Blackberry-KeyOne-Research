import struct, re

def load(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'\x7fELF'
    is64 = d[4] == 2
    if is64:
        e_shoff = struct.unpack('<Q', d[40:48])[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHH', d[58:64])
    else:
        e_shoff = struct.unpack('<I', d[32:36])[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHH', d[46:52])
    shdr_size = e_shentsize
    names = {}
    for i in range(e_shnum):
        s = d[e_shoff + i*shdr_size : e_shoff + (i+1)*shdr_size]
        if is64:
            name_off = struct.unpack('<I', s[0:4])[0]
            typ = struct.unpack('<I', s[4:8])[0]
            off = struct.unpack('<Q', s[24:32])[0]
            size = struct.unpack('<Q', s[32:40])[0]
            link = struct.unpack('<I', s[40:44])[0]
        else:
            name_off = struct.unpack('<I', s[0:4])[0]
            typ = struct.unpack('<I', s[4:8])[0]
            off = struct.unpack('<I', s[16:20])[0]
            size = struct.unpack('<I', s[20:24])[0]
            link = struct.unpack('<I', s[24:28])[0]
        names[i] = (name_off, typ, off, size, link)
    shstr = names[e_shstrndx]
    shn = d[shstr[2]:shstr[2]+shstr[3]]
    def secname(i):
        no = names[i][0]
        return shn[no:shn.find(b'\x00', no)].decode('latin1')
    secs = {}
    for i in range(e_shnum):
        nm = secname(i)
        secs[nm] = names[i]
    # dynsym
    di = [k for k in secs if k == '.dynsym'][0]
    _, _, off, size, link = secs[di]
    stoff = secs[secname(link)][2]
    out = []
    esz = 24 if is64 else 16
    for j in range(size // esz):
        e = d[off+j*esz:off+(j+1)*esz]
        if is64:
            name_off = struct.unpack('<I', e[0:4])[0]
            info = e[4]
        else:
            name_off = struct.unpack('<I', e[0:4])[0]
            info = e[12]
        if name_off:
            nm = d[stoff+name_off:]
            nm = nm[:nm.find(b'\x00')].decode('latin1')
            out.append((nm, info & 0xf))
    return d, out

for f in ['librtas.so', 'libbbauth.so', 'libbbauthtool.so']:
    d, syms = load(r'C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-auth' + '\\' + f)
    print('===', f, '===')
    for nm, t in syms:
        if t == 1 and any(k in nm for k in ('rtas', 'chall', 'auth', 'packet', 'mux', 'Mux', 'encrypt', 'register', 'sign', 'password', 'handshake')):
            print('  ', nm)
