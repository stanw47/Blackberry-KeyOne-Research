#!/usr/bin/env python3
"""kallsyms3.py - symbol resolver for the KEYone ABL766 raw kernel image.

The stock tools (vmlinux-to-elf) failed on this dump; this parses the in-image
kallsyms tables directly and maps symbols to file offsets.

Usage:
  py tools/kallsyms3.py artifacts/kernel.bin SYMBOL [SYMBOL ...]
  py tools/kallsyms3.py artifacts/kernel.bin --dump symbols.txt

Layout (this image, auto-verified):
  token_table @ 0x10BED00 (256 NUL-terminated tokens)
  token_index @ 0x10BF100 (256 x u16)
  num_syms    @ 0xF38800  (u32)
  names       @ 0xF38900  (compressed names)
  addresses   @ num_syms_off - num_syms*8 (u64 each, ascending)
VA->file offset: file_off = VA - 0xffffffc000080000
Beware: the first expanded name char is a type letter (T/t/D/...) and is
dropped, matching kallsyms_expand_symbol().
"""
import struct
import sys

VA_BASE = 0xFFFFFFC000080000


def parse_kallsyms(d):
    u16 = lambda o: struct.unpack_from("<H", d, o)[0]
    u32 = lambda o: struct.unpack_from("<I", d, o)[0]
    u64 = lambda o: struct.unpack_from("<Q", d, o)[0]

    ti = 0x10BF100
    vals = [u16(ti + 2 * i) for i in range(256)]

    table = None
    for start in range(ti - 4096, ti):
        p = start
        offsets = []
        ok = True
        for _ in range(256):
            offsets.append(p - start)
            e = d.find(b"\x00", p, ti)
            if e < 0:
                ok = False
                break
            p = e + 1
        if ok and offsets == vals:
            table = start
            break
    if table is None:
        raise SystemExit("token_table not found")

    toks = []
    for i in range(256):
        p = table + vals[i]
        e = d.find(b"\x00", p, ti)
        toks.append(d[p:e])

    num_off = 0xF38800
    num = u32(num_off)
    if not 50000 < num < 300000:
        raise SystemExit("num_syms sanity failed: %d" % num)

    names_start = num_off + 4
    while d[names_start] == 0:
        names_start += 1

    names = []
    p = names_start
    for _ in range(num):
        ln = d[p]
        p += 1
        if ln & 0x80:
            ln = (ln & 0x7F) | (d[p] << 7)
            p += 1
        s = bytearray()
        for _ in range(ln):
            s += toks[d[p]]
            p += 1
        names.append(s[1:])  # drop kallsyms type char

    addr_start = num_off - num * 8
    addrs = [u64(addr_start + 8 * i) for i in range(num)]
    return names, addrs, names_start, addr_start


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    img, args = sys.argv[1], sys.argv[2:]
    d = open(img, "rb").read()
    names, addrs, names_start, addr_start = parse_kallsyms(d)

    if args[0] == "--dump":
        with open(args[1], "w", encoding="utf-8") as f:
            for n, a in zip(names, addrs):
                f.write("%016x %s\n" % (a, n.decode("latin1")))
        print("wrote %s (%d symbols)" % (args[1], len(names)))
        return

    want = set(args)
    found = 0
    for n, a in zip(names, addrs):
        nm = n.decode("latin1")
        if nm in want or nm.split(".")[0] in want:
            print("%-44s %#x  (file %#x)" % (nm, a, a - VA_BASE))
            found += 1
    if not found:
        raise SystemExit("no match")


if __name__ == "__main__":
    main()
