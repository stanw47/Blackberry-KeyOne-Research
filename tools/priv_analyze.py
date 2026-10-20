import struct, re

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
print("size", len(data))
print("magic", data[:4])

# ELF?
e_phoff = struct.unpack("<I", data[0x1C:0x20])[0]
e_phentsize = struct.unpack("<H", data[0x2A:0x2C])[0]
e_phnum = struct.unpack("<H", data[0x2C:0x2E])[0]
e_shoff = struct.unpack("<I", data[0x20:0x24])[0]
e_shentsize = struct.unpack("<H", data[0x2E:0x30])[0]
e_shnum = struct.unpack("<H", data[0x30:0x32])[0]
print("phnum", e_phnum, "shnum", e_shnum)
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack("<IIIIIIII", data[o:o+32])
    if p_type == 1:
        print(f"LOAD va={p_vaddr:#x} off={p_offset:#x} filesz={p_filesz:#x} memsz={p_memsz:#x}")

secs = []
for n in range(e_shnum):
    o = e_shoff + n * e_shentsize
    secs.append(struct.unpack("<IIIIIIIIII", data[o:o+40]))

symtab = None
for i, s in enumerate(secs):
    if s[1] == 2:  # SYMTAB
        symtab = s
        break
if symtab:
    symoff, symsize, symentsize = symtab[4], symtab[5], symtab[9]
    strsec = secs[symtab[6]]
    stroff = strsec[4]
    print(f"SYMTAB off={symoff:#x} size={symsize:#x} entsize={symentsize}")
    n = symsize // symentsize
    pats = re.compile(r"rtas|authboot|canary|stack_chk|bootmode|unlock|wipe", re.I)
    hits = []
    for i in range(n):
        o = symoff + i * symentsize
        name, value, size, info, other, shndx = struct.unpack("<IIIBBH", data[o:o+16])
        if name:
            end = data.find(b"\x00", stroff + name)
            nm = data[stroff + name:end].decode("latin1")
            if pats.search(nm):
                hits.append((value, nm, size))
    for v, nm, s in sorted(hits)[:60]:
        print(f"  {v:#010x} {nm} {s:#x}")
else:
    print("no symtab")

# cookie search
pat = struct.pack("<I", 0xBBA78701)
idx = [i for i in range(len(data)) if data.startswith(pat, i)]
print("cookie 0xbba78701 at file offs:", [hex(i) for i in idx][:10])
