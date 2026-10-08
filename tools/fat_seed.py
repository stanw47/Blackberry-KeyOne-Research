#!/usr/bin/env python3
"""fat_seed.py - build a small valid FAT16 image (fuzzing seed for fsck_msdos).

Usage: py tools/fat_seed.py out.img
"""
import struct
import sys

SECTOR = 512
RESERVED = 1
NFATS = 2
ROOT_ENTS = 224
FAT_SIZE = 16
TOTAL_SECTORS = 4129
ROOT_DIR_SEC = RESERVED + NFATS * FAT_SIZE
DATA_SEC = ROOT_DIR_SEC + (ROOT_ENTS * 32 + SECTOR - 1) // SECTOR


def dirent(name8, ext3, attr, cluster, size, ctime=0x4A21, cdate=0x5221):
    e = bytearray(32)
    e[0:8] = name8.ljust(8)[:8].encode()
    e[8:11] = ext3.ljust(3)[:3].encode()
    e[11] = attr
    e[22:24] = struct.pack("<H", ctime)
    e[24:26] = struct.pack("<H", cdate)
    e[26:28] = struct.pack("<H", cluster)
    e[28:32] = struct.pack("<I", size)
    return bytes(e)


def lfn_checksum(short):
    s = 0
    for c in short:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def lfn_entry(seq, last, name_utf16, chk):
    e = bytearray(32)
    e[0] = seq | (0x40 if last else 0)
    e[11] = 0x0F
    e[12] = 0
    e[13] = chk
    e[26:28] = b"\x00\x00"
    slots = [name_utf16[i:i + 2] for i in range(0, len(name_utf16), 2)]
    pos = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
    for i, p in enumerate(pos):
        if i < len(slots):
            e[p:p + 2] = slots[i]
        elif i == len(slots):
            e[p:p + 2] = b"\x00\x00"
        else:
            e[p:p + 2] = b"\xff\xff"
    return bytes(e)


def build():
    img = bytearray(TOTAL_SECTORS * SECTOR)
    bpb = bytearray(512)
    bpb[0:3] = b"\xeb\x3c\x90"
    bpb[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", bpb, 11, SECTOR)
    bpb[13] = 1
    struct.pack_into("<H", bpb, 14, RESERVED)
    bpb[16] = NFATS
    struct.pack_into("<H", bpb, 17, ROOT_ENTS)
    struct.pack_into("<H", bpb, 19, TOTAL_SECTORS)
    bpb[21] = 0xF0
    struct.pack_into("<H", bpb, 22, FAT_SIZE)
    struct.pack_into("<H", bpb, 24, 18)
    struct.pack_into("<H", bpb, 26, 2)
    struct.pack_into("<I", bpb, 28, 0)
    struct.pack_into("<I", bpb, 32, 0)
    bpb[36] = 0x00
    bpb[38] = 0x29
    struct.pack_into("<I", bpb, 39, 0x12345678)
    bpb[43:54] = b"NO NAME    "
    bpb[54:62] = b"FAT16   "
    bpb[510:512] = b"\x55\xaa"
    img[0:512] = bpb

    fat_off = RESERVED * SECTOR
    fat = bytearray(FAT_SIZE * SECTOR)
    struct.pack_into("<H", fat, 0, 0xFF00 | 0xF0)
    struct.pack_into("<H", fat, 2, 0xFFFF)
    struct.pack_into("<H", fat, 2 * 2, 0xFFFF)  # cluster 2 -> EOF
    struct.pack_into("<H", fat, 3 * 2, 0xFFFF)  # cluster 3 -> EOF
    for n in range(NFATS):
        img[fat_off + n * FAT_SIZE * SECTOR: fat_off + (n + 1) * FAT_SIZE * SECTOR] = fat

    root = ROOT_DIR_SEC * SECTOR
    short = dirent("HELLO   ", "TXT", 0x20, 2, 10)
    lname = "LongFileNameTest.txt"
    u16 = (lname + "\x00").encode("utf-16-le")
    entries = b""
    entries += lfn_entry(1, True, u16, lfn_checksum(short[:11]))
    entries += short
    entries += dirent("SUBDIR  ", "   ", 0x10, 3, 0)
    img[root:root + len(entries)] = entries

    sub = 3
    dot = dirent(".       ", "   ", 0x10, 3, 0)[:32]
    dotdot = dirent("..      ", "   ", 0x10, 0, 0)[:32]
    img[DATA_SEC * SECTOR + SECTOR: DATA_SEC * SECTOR + SECTOR + 64] = dot + dotdot

    hello = b"Hello FAT!"
    img[DATA_SEC * SECTOR: DATA_SEC * SECTOR + len(hello)] = hello
    return bytes(img)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "seed_fat16.img"
    d = build()
    open(out, "wb").write(d)
    print("wrote %s (%d bytes)" % (out, len(d)))
