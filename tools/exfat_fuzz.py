#!/usr/bin/env python3
"""exfat_fuzz.py - fuzz the KEYone's fsck.exfat (relan/exfat 1.2.3, root on insert).

vold runs: /system/bin/fsck.exfat <dev>   (fsck_untrusted context)
Seed: tools/exfat_seed.py output (1 MiB, 512/4096, boot checksum valid).
Mutations recompute the VBR checksum so boot-sector changes still mount deep.

Usage: py tools/exfat_fuzz.py --seed seed_exfat.img --count 512 --batch 64
"""
import argparse
import os
import random
import struct
import subprocess
import sys
import time

SECTOR = 512


def _tool(env, default):
    p = os.environ.get(env, default)
    return os.path.join(p, os.path.basename(default)) if os.path.isdir(p) else p


ADB = _tool("ADB", r"C:\platform-tools\adb.exe")
SERIAL = os.environ.get("BB_SERIAL", "1164118297")
REMOTE = "/data/local/tmp/ez"


def adb(*args, timeout=900):
    return subprocess.run([ADB, "-s", SERIAL, *args],
                          capture_output=True, text=True, timeout=timeout)


def vbr_fix(d):
    s = 0
    for i in range(11):
        base = i * SECTOR
        for j in range(SECTOR):
            if i == 0 and j in (0x6A, 0x6B, 0x70):
                continue
            s = (((s << 31) | (s >> 1)) + d[base + j]) & 0xFFFFFFFF
    d[11 * SECTOR:12 * SECTOR] = struct.pack("<I", s) * (SECTOR // 4)


def root_pos(d):
    return struct.unpack_from("<I", d, 88)[0] * SECTOR + \
        (struct.unpack_from("<I", d, 96)[0] - 2) * (SECTOR << d[109])


def mutate(seed, rng):
    d = bytearray(seed)
    n = len(d)
    kind = rng.randrange(5)
    if kind == 0:  # boot sector fields with checksum recompute
        fields = [(72, 8), (80, 4), (84, 4), (88, 4), (92, 4), (96, 4),
                  (100, 4), (104, 1), (105, 1), (106, 2), (108, 1), (109, 1),
                  (110, 1), (111, 1), (112, 1)]
        for off, sz in fields:
            if rng.random() < 0.35:
                v = rng.choice([0, 1, 2, 3, 0xFF, 0xFFFFFFFF,
                                rng.randrange(1 << (8 * sz))])
                d[off:off + sz] = (v & ((1 << (8 * sz)) - 1)).to_bytes(sz, "little")
        vbr_fix(d)
    elif kind == 1:  # FAT entries
        fat = struct.unpack_from("<I", d, 80)[0] * SECTOR
        fatlen = struct.unpack_from("<I", d, 84)[0] * SECTOR
        for _ in range(rng.randrange(1, 6)):
            off = fat + rng.randrange(0, min(fatlen, n - fat) - 4)
            struct.pack_into("<I", d, off, rng.choice(
                [0, 1, 2, 3, 0xFFFFFFF7, 0xFFFFFFF8, 0xFFFFFFFF,
                 rng.randrange(1 << 32)]))
    elif kind == 2:  # root directory entries
        rp = root_pos(d)
        if rp + 32 * 8 < n:
            for _ in range(rng.randrange(1, 5)):
                e = rp + 32 * rng.randrange(0, 8)
                r = rng.random()
                if r < 0.4:
                    d[e] = rng.choice([0x81, 0x82, 0x83, 0x85, 0xC0, 0xC1,
                                       0xA0, 0x00, 0xFF, 0x0F])
                elif r < 0.7:
                    struct.pack_into("<I", d, e + 20, rng.randrange(1 << 32))
                else:
                    struct.pack_into("<Q", d, e + 24, rng.randrange(1 << 48))
    elif kind == 3:  # bitmap + upcase table bytes
        hp = struct.unpack_from("<I", d, 88)[0] * SECTOR
        for _ in range(rng.randrange(1, 12)):
            d[hp + rng.randrange(0, 0x4000)] = rng.randrange(256)
    else:  # random flips in the data area (sectors 12+), VBR untouched
        for _ in range(rng.randrange(1, 32)):
            d[rng.randrange(12 * SECTOR, n)] = rng.randrange(256)
    return d


def run(remote):
    script = (
        "cd %s && rm -rf crashes && mkdir crashes && "
        "for f in m*.img; do "
        "/data/local/tmp/fsck.exfat \"$f\" >/dev/null 2>&1; rc=$?; "
        "if [ $rc -ge 128 ]; then echo \"CRASH $rc $f\"; cp \"$f\" crashes/; fi; "
        "done; echo LOOP_DONE" % remote
    )
    return adb("shell", script)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", required=True)
    ap.add_argument("--count", type=int, default=512)
    ap.add_argument("--batch", type=int, default=64)
    ap.add_argument("--outdir", default="artifacts/exfat-fuzz")
    args = ap.parse_args()
    seed = open(args.seed, "rb").read()
    rng = random.Random(0xE0FA7)
    os.makedirs(args.outdir, exist_ok=True)
    total = crashes = 0
    t0 = time.time()
    while total < args.count:
        k = min(args.batch, args.count - total)
        local = os.path.join(args.outdir, "batch")
        subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", local],
                       capture_output=True)
        os.makedirs(local, exist_ok=True)
        for i in range(k):
            open(os.path.join(local, "m%04d.img" % i), "wb").write(mutate(seed, rng))
        adb("shell", "rm -rf %s" % REMOTE)
        r = adb("push", local, REMOTE, timeout=900)
        if r.returncode != 0:
            print("push failed:", r.stderr[:200])
            return 2
        out = run(REMOTE)
        hits = [l for l in out.stdout.splitlines() if l.startswith("CRASH")]
        crashes += len(hits)
        for h in hits:
            print("  ", h)
        if hits:
            adb("pull", REMOTE + "/crashes",
                os.path.join(args.outdir, "crashes"), timeout=300)
        total += k
        print("batch %d/%d: crashes %d  %.1f img/s"
              % (total, args.count, crashes, total / (time.time() - t0)))
    print("done: %d mutants, %d crashes, %.1fs" % (total, crashes, time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
