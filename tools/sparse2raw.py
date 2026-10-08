#!/usr/bin/env python3
"""sparse2raw.py - convert an Android sparse image (magic 0xED26FF3A) to raw.

Usage: py tools/sparse2raw.py in.img out.raw
"""
import struct
import sys

MAGIC = 0xED26FF3A


def convert(src, dst):
    d = open(src, "rb").read()
    magic, major, minor, hsz, csz, blk, total_blks, total_chunks, _ = \
        struct.unpack_from("<IHHHHIIII", d, 0)
    if magic != MAGIC:
        raise SystemExit("not a sparse image (magic %#x)" % magic)
    out = bytearray()
    o = hsz
    for _ in range(total_chunks):
        ctype, _, cblks, tsz = struct.unpack_from("<HHII", d, o)
        body = d[o + csz:o + tsz]
        if ctype == 0xCAC1:      # raw
            out += body
        elif ctype == 0xCAC2:    # fill
            val = body[:4]
            out += val * (cblks * blk // 4)
        elif ctype == 0xCAC3:    # don't care
            out += b"\x00" * (cblks * blk)
        # 0xCAC4 (crc32) carries no data
        o += tsz
    open(dst, "wb").write(out)
    return len(out)


if __name__ == "__main__":
    n = convert(sys.argv[1], sys.argv[2])
    print("wrote %s (%d bytes)" % (sys.argv[2], n))
