import struct

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
print("file size:", hex(len(data)))
print("magic:", data[:4])

e_ident = data[:16]
e_type, e_machine = struct.unpack("<HH", data[16:20])
e_entry = struct.unpack("<I", data[24:28])[0]
e_phoff = struct.unpack("<I", data[28:32])[0]
e_shoff = struct.unpack("<I", data[32:36])[0]
e_flags = struct.unpack("<I", data[36:40])[0]
e_ehsize, e_phentsize, e_phnum = struct.unpack("<HHH", data[40:46])
e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", data[46:52])
print(f"type={e_type:#x} machine={e_machine:#x} entry={e_entry:#x} phoff={e_phoff:#x} shoff={e_shoff:#x} shnum={e_shnum}")

for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_offset, p_vaddr, p_paddr = struct.unpack("<IIII", data[off:off+16])
    p_filesz, p_memsz, p_flags, p_align = struct.unpack("<IIII", data[off+16:off+32])
    print(f"phdr{i}: type={p_type:#x} off={p_offset:#x} vaddr={p_vaddr:#x} filesz={p_filesz:#x} memsz={p_memsz:#x} flags={p_flags:#x}")
