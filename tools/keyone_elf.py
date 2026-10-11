import struct, re
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

path = r"C:\Users\Stanley Williamson\Desktop\Blackberry KeyOne Research\firmware\keyone-abl766\ABL766 - Hn03\target\product\bbry_qc8953\emmc_appsboot.mbn"
d = open(path, 'rb').read()
print("size", hex(len(d)), "magic", d[:4])

# ELF parse
if d[:4] == b'\x7fELF':
    e_ident = d[:16]
    cls = e_ident[4]
    endian = e_ident[5]
    fmt = '<' if endian == 1 else '>'
    if cls == 2:  # 64
        e_entry = struct.unpack(fmt + 'Q', d[24:32])[0]
        e_phoff = struct.unpack(fmt + 'Q', d[32:40])[0]
        e_shoff = struct.unpack(fmt + 'Q', d[40:48])[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack(fmt + 'HHH', d[58:64])
    else:  # 32
        e_entry = struct.unpack(fmt + 'I', d[24:28])[0]
        e_phoff = struct.unpack(fmt + 'I', d[28:32])[0]
        e_shoff = struct.unpack(fmt + 'I', d[32:36])[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack(fmt + 'HHH', d[46:52])
    print(f"cls={cls} endian={endian} entry={e_entry:#x} phoff={e_phoff:#x} shoff={e_shoff:#x} shnum={e_shnum}")
    phdrs = []
    e_phentsize = struct.unpack(fmt + 'HH', d[54:58])[0] if cls == 2 else struct.unpack(fmt + 'HH', d[42:46])[0]
    e_phnum = struct.unpack(fmt + 'H', d[56:58])[0] if cls == 2 else struct.unpack(fmt + 'H', d[44:46])[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if cls == 2:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(fmt + 'IIQQQQQQ', d[o:o+56])
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(fmt + 'IIIIIIII', d[o:o+32])
        phdrs.append((p_type, p_offset, p_vaddr, p_filesz, p_memsz))
        if p_type == 1:
            print(f"  LOAD: off={p_offset:#x} va={p_vaddr:#x} filesz={p_filesz:#x}")
    # section names + symtab
    shstr = None
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        if cls == 2:
            name_off, typ = struct.unpack(fmt + 'II', d[o:o+8])
            off_, size, link = struct.unpack(fmt + 'QQI', d[o+24:o+44])
        else:
            name_off, typ = struct.unpack(fmt + 'II', d[o:o+8])
            off_, size, link = struct.unpack(fmt + 'III', d[o+16:o+28])
        if i == e_shstrndx:
            shstr = d[off_:off_+size]
    def secname(no):
        return shstr[no:shstr.find(b'\x00', no)].decode('latin1')
    sections = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        if cls == 2:
            name_off, typ, flags = struct.unpack(fmt + 'IIQ', d[o:o+16])
            addr, off_, size, link, info, align, entsize = struct.unpack(fmt + 'QQQIIQQ', d[o+16:o+64])
        else:
            name_off, typ, flags = struct.unpack(fmt + 'III', d[o:o+12])
            addr, off_, size, link, info, align, entsize = struct.unpack(fmt + 'IIIIIII', d[o+12:o+40])
        sections.append((secname(name_off), typ, addr, off_, size, link, entsize))
    print("sections:", [(n, hex(a), hex(sz)) for n, t, a, o_, sz, l, es in sections if t in (1, 2)])
    # symtab
    for n, t, a, o_, sz, l, es in sections:
        if n in ('.symtab', '.dynsym'):
            print(f"symtab {n}: addr={a:#x} off={o_:#x} size={sz:#x} link={l} entsize={es}")
