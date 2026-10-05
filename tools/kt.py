import struct, sys
img = open(sys.argv[1], 'rb').read()
N = len(img)
def parse_tokens(o):
    toks = []; p = o
    for i in range(256):
        e = img.find(b'\x00', p, p+64)
        if e < 0: return None
        s = img[p:e]
        if len(s) == 0 or len(s) > 40: return None
        for c in s:
            if not (32 <= c < 127): return None
        toks.append(s); p = e + 1
    return toks, p
hits = []
for o in range(0, N - 4096):
    if not (32 <= img[o] < 127): continue
    r = parse_tokens(o)
    if not r: continue
    toks, end = r
    if end - o > 8192: continue
    if end + 512 > N: continue
    vals = [struct.unpack_from('<H', img, end + 2*i)[0] for i in range(256)]
    if vals[0] != 0: continue
    ok = True
    for i in range(255):
        if vals[i] >= vals[i+1]: ok = False; break
    if not ok: continue
    if vals[-1] >= end - o: continue
    good = True
    for i in range(256):
        p = o + vals[i]
        e = img.find(b'\x00', p, end)
        if e < 0 or img[p:e] != toks[i]: good = False; break
    if good: hits.append((o, end, vals[-1], [t.decode('latin1') for t in toks[:8]]))
print('token_table hits:', len(hits))
for h in hits[:5]:
    print('  start=%#x end=%#x maxtok=%d sample=%s' % (h[0], h[1], h[2], h[3]))
