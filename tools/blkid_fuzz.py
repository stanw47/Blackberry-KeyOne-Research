#!/usr/bin/env python3
"""blkid_fuzz.py - fuzz the KEYone's libblkid (vold's untrusted-media probe).

vold runs: /system/bin/blkid -c /dev/null -s TYPE -s UUID -s LABEL <path>
and also calls blkid_get_tag_value() in-process; both parse attacker media as
root. Seeds are per-filesystem superblocks with valid magics; mutations keep
the magic so probes go deep.

Usage:
  py tools/blkid_fuzz.py --count 512 --batch 256 [--mode vold|probe]
"""
import argparse
import os
import random
import struct
import subprocess
import sys
import time

ADB_DEFAULT = r"C:\platform-tools\adb.exe"
SERIAL = os.environ.get("BB_SERIAL", "1164118297")
REMOTE = "/data/local/tmp/bz"


def _tool(env_name, default):
    p = os.environ.get(env_name, default)
    if os.path.isdir(p):
        p = os.path.join(p, os.path.basename(default))
    return p


ADB = _tool("ADB", ADB_DEFAULT)


def adb(*args, timeout=600):
    return subprocess.run([ADB, "-s", SERIAL, *args],
                          capture_output=True, text=True, timeout=timeout)


def seed(kind, size=0x4000):
    d = bytearray(os.urandom(size))
    if kind == "ext4":
        # ext superblock at 1024
        d[1024 + 0x38:1024 + 0x3A] = b"\x53\xef"
        struct.pack_into("<I", d, 1024 + 0x04, 1024)      # blocks count
        struct.pack_into("<I", d, 1024 + 0x18, 0)         # log block size
        struct.pack_into("<I", d, 1024 + 0x54, 0x10000)   # inodes
        struct.pack_into("<H", d, 1024 + 0x58, 0x100)     # inode size
        d[1024 + 0x78:1024 + 0x88] = b"01234567-89ab-cdef-0123-456789abcdef"[:16]
    elif kind == "ntfs":
        d[3:11] = b"NTFS    "
        struct.pack_into("<H", d, 11, 512)
        d[13] = 8
        struct.pack_into("<Q", d, 40, 0x100000)
    elif kind == "exfat":
        d[3:11] = b"EXFAT   "
        struct.pack_into("<Q", d, 64, 0)
        struct.pack_into("<Q", d, 72, size // 512)
        struct.pack_into("<I", d, 80, 24)
        struct.pack_into("<I", d, 84, 1)
        struct.pack_into("<I", d, 88, 128)
        struct.pack_into("<I", d, 92, 32)
        struct.pack_into("<I", d, 96, 4)
        d[104] = 0x01
        d[106:108] = b"\x00\x00"
        d[108] = 9
        d[109] = 3
        d[110] = 1
        d[111] = 0x80
        d[510:512] = b"\x55\xaa"
    elif kind == "btrfs":
        d = bytearray(os.urandom(0x20000))
        d[0x10040:0x10048] = b"_BHRfS_M"
        struct.pack_into("<Q", d, 0x10070, 0x10000)
        struct.pack_into("<Q", d, 0x10078, 0x1000000)
    elif kind == "xfs":
        d[0:4] = b"XFSB"
        struct.pack_into("<I", d, 4, 512)
        struct.pack_into("<I", d, 8, 0x1000000)
        struct.pack_into("<I", d, 100, 0x10000)
    elif kind == "iso":
        d = bytearray(os.urandom(0x9000))
        d[0x8001:0x8006] = b"CD001"
        d[0x8000] = 1
        d[32768 + 80:32768 + 88] = b"        "
    elif kind == "hfsplus":
        d[1024:1026] = b"H+"
        struct.pack_into("<H", d, 1024 + 2, 4)
        struct.pack_into("<I", d, 1024 + 40, 0x10000)
    elif kind == "luks":
        d[0:6] = b"LUKS\xba\xbe"
        struct.pack_into("<H", d, 6, 1)
        d[8:40] = b"aes" + b"\x00" * 29
    elif kind == "swap":
        struct.pack_into("<I", d, 1024 - 10, 1)  # bad magic -> probe cheap
        struct.pack_into("<I", d, 0xFF6, 0x4541)
    else:  # vfat
        d[0:3] = b"\xeb\x3c\x90"
        d[3:11] = b"MSDOS5.0"
        struct.pack_into("<H", d, 11, 512)
        d[13] = 1
        struct.pack_into("<H", d, 14, 1)
        d[16] = 2
        struct.pack_into("<H", d, 17, 224)
        struct.pack_into("<H", d, 22, 16)
        d[21] = 0xF0
        d[510:512] = b"\x55\xaa"
    return d


KINDS = ["ext4", "ntfs", "exfat", "btrfs", "xfs", "iso", "hfsplus", "luks",
         "vfat", "random"]


def mutate(base, rng):
    d = bytearray(base)
    n = len(d)
    choice = rng.random()
    if choice < 0.5:
        for _ in range(rng.randrange(1, 24)):
            off = rng.randrange(min(n, 0x2000))
            d[off] = rng.randrange(256)
    elif choice < 0.8:
        for _ in range(rng.randrange(1, 8)):
            off = rng.randrange(n - 8)
            d[off:off + rng.choice([1, 2, 4])] = os.urandom(rng.choice([1, 2, 4]))
    else:  # 16/32-bit field storms
        for _ in range(rng.randrange(1, 10)):
            off = rng.randrange(min(n, 0x3000) - 4)
            struct.pack_into("<I", d, off, rng.randrange(1 << 32))
    return d


def run(remote, args_tmpl):
    script = (
        "cd %s && rm -rf crashes && mkdir crashes && "
        "for f in m*.bin; do "
        "/data/local/tmp/blkid %s \"$f\" >/dev/null 2>&1; rc=$?; "
        "if [ $rc -ge 128 ]; then echo \"CRASH $rc $f\"; cp \"$f\" crashes/; fi; "
        "done; echo LOOP_DONE" % (remote, args_tmpl)
    )
    return adb("shell", script, timeout=900)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=512)
    ap.add_argument("--batch", type=int, default=256)
    ap.add_argument("--outdir", default="artifacts/blkid-fuzz")
    ap.add_argument("--mode", choices=["vold", "probe", "both"], default="both")
    args = ap.parse_args()

    if args.mode == "vold":
        modes = ["-c /dev/null -s TYPE -s UUID -s LABEL"]
    elif args.mode == "probe":
        modes = ["-p"]
    else:
        modes = ["-c /dev/null -s TYPE -s UUID -s LABEL", "-p"]

    rng = random.Random(0xB1B1D)
    os.makedirs(args.outdir, exist_ok=True)
    total = 0
    crashes = 0
    t0 = time.time()
    while total < args.count:
        n = min(args.batch, args.count - total)
        local = os.path.join(args.outdir, "batch")
        subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", local],
                       capture_output=True)
        os.makedirs(local, exist_ok=True)
        for i in range(n):
            kind = rng.choice(KINDS)
            base = seed(kind)
            img = mutate(base, rng) if kind != "random" else bytearray(os.urandom(rng.choice([512, 4096, 16384])))
            open(os.path.join(local, "m%05d.bin" % i), "wb").write(img)
        adb("shell", "rm -rf %s" % REMOTE)
        r = adb("push", local, REMOTE, timeout=900)
        if r.returncode != 0:
            print("push failed:", r.stderr[:200])
            return 2
        for m in modes:
            out = run(REMOTE, m)
            hits = [l for l in out.stdout.splitlines() if l.startswith("CRASH")]
            crashes += len(hits)
            for h in hits:
                print("  ", m, h)
            if hits:
                adb("pull", REMOTE + "/crashes",
                    os.path.join(args.outdir, "crashes"), timeout=300)
        total += n
        print("batch %d/%d: total crashes %d  %.1f img/s"
              % (total, args.count, crashes, total / (time.time() - t0)))
    print("done: %d mutants, %d crashes, %.1fs" % (total, crashes, time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
