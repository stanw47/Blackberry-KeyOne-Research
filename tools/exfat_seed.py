#!/usr/bin/env python3
"""exfat_seed.py - build a minimal valid exFAT image (fuzz seed for fsck.exfat).

Ports the relan/exfat mkexfatfs layout (vbr.c/fat.c/cbm.c/uct.c/rootdir.c).
Needs the upcase table from relan/exfat mkfs/uctc.c:

  git clone --depth 1 https://github.com/relan/exfat
  py tools/exfat_seed.py out.img --uctc <clone>/mkfs/uctc.c

Layout (sector 512, cluster 4096, volume 1 MiB):
  vbr @0, fat @0x10000, bitmap (cluster 2), upcase (clusters 3-4),
  rootdir (cluster 5).
"""
import argparse
import re
import struct
import sys

SECTOR = 512
SBITS = 9
SPBITS = 3
CLUSTER = SECTOR << SPBITS
VOLUME = 0x100000


def load_upcase(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    body = txt.split("{", 1)[1]
    nums = re.findall(r"0x([0-9a-fA-F]{2})", body)
    b = bytes(int(x, 16) for x in nums)
    if len(b) != 5836:
        raise SystemExit("upcase table is %d bytes, expected 5836" % len(b))
    return b


def round_up(v, a):
    return (v + a - 1) // a * a


def vbr_checksum(sectors):
    s = 0
    for i, sec in enumerate(sectors):
        for j, byte in enumerate(sec):
            if i == 0 and j in (0x6A, 0x6B, 0x70):
                continue
            s = (((s << 31) | (s >> 1)) + byte) & 0xFFFFFFFF
    return s


def build(upcase):
    fat_pos = 65536
    fat_size = VOLUME // CLUSTER * 4
    cbm_pos = round_up(fat_pos + fat_size, CLUSTER)
    cbm_size = ((VOLUME - cbm_pos) // CLUSTER + 7) // 8 or 1
    uct_pos = round_up(cbm_pos + cbm_size, CLUSTER)
    uct_size = len(upcase)
    root_pos = round_up(uct_pos + uct_size, CLUSTER)
    root_size = CLUSTER

    img = bytearray(VOLUME)

    sb = bytearray(SECTOR)
    sb[0:3] = b"\xeb\x76\x90"
    sb[3:11] = b"EXFAT   "
    struct.pack_into("<Q", sb, 64, 0)
    struct.pack_into("<Q", sb, 72, VOLUME // SECTOR)
    struct.pack_into("<I", sb, 80, fat_pos // SECTOR)
    struct.pack_into("<I", sb, 84,
                     round_up(fat_pos // SECTOR + (fat_size + SECTOR - 1) // SECTOR,
                              1 << SPBITS) - fat_pos // SECTOR)
    struct.pack_into("<I", sb, 88, cbm_pos // SECTOR)
    struct.pack_into("<I", sb, 92,
                     VOLUME // CLUSTER - ((fat_pos // SECTOR + struct.unpack_from("<I", sb, 84)[0]) >> SPBITS))
    struct.pack_into("<I", sb, 96, (root_pos - cbm_pos) // CLUSTER + 2)
    struct.pack_into("<I", sb, 100, 0x12345678)
    sb[104] = 0
    sb[105] = 1
    struct.pack_into("<H", sb, 106, 0)
    sb[108] = SBITS
    sb[109] = SPBITS
    sb[110] = 1
    sb[111] = 0x80
    sb[112] = 0
    struct.pack_into("<H", sb, 510, 0xAA55)

    vbr_sectors = [bytes(sb)]
    sig = bytearray(SECTOR)
    struct.pack_into("<I", sig, SECTOR - 4, 0xAA550000)
    vbr_sectors += [bytes(sig)] * 8
    vbr_sectors += [bytes(SECTOR)] * 2
    chk = vbr_checksum(vbr_sectors)
    cksum_sec = struct.pack("<I", chk) * (SECTOR // 4)
    img[0:SECTOR] = sb
    for i in range(1, 9):
        img[i * SECTOR:(i + 1) * SECTOR] = sig
    img[11 * SECTOR:12 * SECTOR] = cksum_sec

    fat = struct.pack("<I", 0xFFFFFFF8) + struct.pack("<I", 0xFFFFFFFF)
    fat += struct.pack("<I", 0xFFFFFFFF)
    fat += struct.pack("<I", 4) + struct.pack("<I", 0xFFFFFFFF)
    fat += struct.pack("<I", 0xFFFFFFFF)
    img[fat_pos:fat_pos + len(fat)] = fat

    img[cbm_pos] = 0x0F  # clusters 2..5 allocated

    img[uct_pos:uct_pos + uct_size] = upcase

    def entry():
        return bytearray(32)

    label = entry()
    label[0] = 0x03
    bitmap = entry()
    bitmap[0] = 0x81
    struct.pack_into("<I", bitmap, 20, 2)
    struct.pack_into("<Q", bitmap, 24, cbm_size)
    upc = entry()
    upc[0] = 0x82
    sum_ = 0
    for b in upcase:
        sum_ = (((sum_ << 31) | (sum_ >> 1)) + b) & 0xFFFFFFFF
    struct.pack_into("<I", upc, 4, sum_)
    struct.pack_into("<I", upc, 20, 3)
    struct.pack_into("<Q", upc, 24, uct_size)
    img[root_pos:root_pos + 96] = label + bitmap + upc
    _ = root_size
    return bytes(img)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--uctc", required=True, help="path to relan/exfat mkfs/uctc.c")
    args = ap.parse_args()
    img = build(load_upcase(args.uctc))
    open(args.out, "wb").write(img)
    print("wrote %s (%d bytes)" % (args.out, len(img)))


if __name__ == "__main__":
    sys.exit(main())
