import struct, re

path = r"C:\Users\Stanley Williamson\Desktop\Blackberry KeyOne Research\firmware\keyone-abl766\ABL766 - Hn03\host\windows-x86\bin\pcauthtool.exe"
d = open(path, 'rb').read()
print("size", len(d), d[:2])

# PE header
pe_off = struct.unpack('<I', d[0x3c:0x40])[0]
machine, nsect, ts, symptr, nsyms, optsz, chars = struct.unpack('<HHIIIHH', d[pe_off+4:pe_off+24])
print(f"machine={machine:#x} sections={nsect} symptr={symptr:#x} nsyms={nsyms}")

# COFF symbol table
if nsyms:
    strtab_off = symptr + nsyms*18
    strtab_len = struct.unpack('<I', d[strtab_off:strtab_off+4])[0]
    strtab = d[strtab_off:strtab_off+strtab_len]
    def sname(off):
        e = strtab.find(b'\x00', off)
        return strtab[off:e].decode('latin1')
    syms = []
    for i in range(nsyms):
        e = d[symptr+i*18:symptr+(i+1)*18]
        name = e[:8].rstrip(b'\x00').decode('latin1')
        val, secnum, typ, scls, naux = struct.unpack('<IhHBB', e[8:18])
        if name.startswith('__imp_'):
            name = 'imp_' + name[6:]
        elif not name:
            name = 'AUX'
        syms.append((name, val, secnum, scls, naux))
        i += naux
    interesting = [s for s in syms if any(k in s[0].lower() for k in ('auth','rtas','challenge','chall','packet','usb','send','verify','cred','sign','password','handshake','frame','nv'))]
    print("interesting syms:")
    for s in interesting:
        print(f"  {s[0]:40s} val={s[1]:#x} sec={s[2]} cls={s[3]}")
    print("total syms:", len(syms))
