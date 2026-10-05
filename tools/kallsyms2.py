import struct, sys
img = open(sys.argv[1], 'rb').read()
N = len(img)
def u16(o): return struct.unpack_from('<H', img, o)[0]
def u32(o): return struct.unpack_from('<I', img, o)[0]
def s32(o): return struct.unpack_from('<i', img, o)[0]
def u64(o): return struct.unpack_from('<Q', img, o)[0]

cands = []
for o in range(0, N - 512, 2):
    if u16(o) != 0: continue
    a = u16(o + 2)
    if a == 0 or a > 0x300: continue
    b = u16(o + 4)
    if b <= a or b > 0x400: continue
    vals = [u16(o + 2*i) for i in range(256)]
    ok = True
    for i in range(255):
        if vals[i] >= vals[i+1]: ok = False; break
    if ok and vals[-1] < 0x4000: cands.append((o, vals))
print('token_index candidates:', [(hex(o), v[-1]) for o, v in cands][:10])
if not cands: sys.exit(1)
ti_off, ti = cands[-1]

table_start = None
for guess in range(ti_off - ti[255] - 64, ti_off - ti[255] + 1):
    if guess < 0: continue
    ok = True
    for i in range(256):
        p = guess + ti[i]
        if p >= ti_off: ok = False; break
        if img.find(b'\x00', p, ti_off) < 0: ok = False; break
    if ok:
        p = guess + ti[255]
        if img.find(b'\x00', p, ti_off) == ti_off - 1:
            table_start = guess; break
print('token_table start:', hex(table_start) if table_start else None)
if table_start is None: sys.exit(1)

tokens = []
for i in range(256):
    p = table_start + ti[i]
    e = img.index(b'\x00', p)
    tokens.append(img[p:e])

m_end = table_start
m_start = None
for o in range(m_end - 4, m_end - 0x20000, -4):
    if u32(o) == 0:
        ok = True; prev = 0; k = o
        while k + 4 <= m_end:
            v = u32(k)
            if v < prev: ok = False; break
            prev = v; k += 4
        if ok: m_start = o; break
print('markers start:', hex(m_start) if m_start else None)
if m_start is None: sys.exit(1)
markers_count = (m_end - m_start) // 4

def decode_names(names_start, num):
    out = []; p = names_start
    for i in range(num):
        if p >= m_start: return None
        ln = img[p]; p += 1
        if ln & 0x80:
            ln = (ln & 0x7f) | (img[p] << 7); p += 1
        s = bytearray()
        for j in range(ln):
            t = img[p]; p += 1
            s += tokens[t]
        out.append(bytes(s))
    return out, p

found = None
for o in range(m_start - 0x40, m_start - 0x300000, -4):
    v = u32(o)
    if 50000 < v < 300000:
        for ns in (o+4, o+8):
            r = decode_names(ns, v)
            if r:
                names, endp = r
                if markers_count*256 >= v - 255 and markers_count*256 <= v + 255:
                    found = (o, v, ns, names, endp); break
    if found: break
print('num_syms off/val/names_start:', (hex(found[0]), found[1], hex(found[2])) if found else None)
if not found: sys.exit(1)

_, num_syms, names_start, names, names_end = found
print('decoded', len(names), 'names')
rel_base_off = found[0] - 8
rel_base = u64(rel_base_off)
print('relative_base @', hex(rel_base_off), '=', hex(rel_base))
offsets_off = rel_base_off - 4*num_syms
def to_addr(v): return rel_base + v if v >= 0 else rel_base - 1 - v
addrs = [to_addr(s32(offsets_off + 4*i)) for i in range(num_syms)]

want = ['arm_lpae_map_sg','arm_lpae_init_pte','arm_lpae_unmap','__arm_lpae_map',
        'kgsl_iommu_set_svm_region','kgsl_iommu_addr_in_range','iommu_addr_in_svm_ranges',
        'kgsl_ioctl_map_user_mem','arm_smmu_map_sg','arm_smmu_unmap']
for i, nm in enumerate(names):
    for w in want:
        if nm == w.encode() or nm.endswith(b'.'+w.encode()):
            print('%-32s %#x' % (nm.decode('latin1'), addrs[i]))
