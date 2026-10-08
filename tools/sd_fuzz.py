#!/usr/bin/env python3
"""sd_fuzz.py - offline fuzzer for the KEYone's vold-executed filesystem parsers.

Runs the *device's own* /system/bin/fsck_msdos (pushed to /data/local/tmp)
against host-generated mutants, via adb. Mutants are structured (BPB / FAT /
directory fields) plus random flips. Crash = rc >= 128 (SIGSEGV/ABRT).

Usage:
  py tools/sd_fuzz.py --seed seed.img --count 256 --batch 64 [--mode f16]
"""
import argparse
import os
import random
import struct
import subprocess
import sys
import time

def _tool(env_name, default):
    p = os.environ.get(env_name, default)
    if os.path.isdir(p):
        p = os.path.join(p, os.path.basename(default))
    return p


ADB = _tool("ADB", r"C:\platform-tools\adb.exe")
SERIAL = os.environ.get("BB_SERIAL", "1164118297")
REMOTE = "/data/local/tmp/fz"


def adb(*args, timeout=120):
    return subprocess.run([ADB, "-s", SERIAL, *args],
                          capture_output=True, text=True, timeout=timeout)


def geom(d):
    bps = struct.unpack_from("<H", d, 11)[0] or 512
    reserved = struct.unpack_from("<H", d, 14)[0]
    nfats = d[16] or 2
    fat_size = struct.unpack_from("<H", d, 22)[0]
    root_ents = struct.unpack_from("<H", d, 17)[0] or 224
    fat_off = reserved * bps
    root = (reserved + nfats * fat_size) * bps
    data = root + (root_ents * 32 + bps - 1) // bps * bps
    return bps, fat_off, root, data, root_ents


def mutate(seed, rng):
    d = bytearray(seed)
    n = len(d)
    strat = rng.randrange(9)
    if strat == 0:  # random byte flips, first 64K weighted
        for _ in range(rng.randrange(1, 12)):
            if rng.random() < 0.8:
                off = rng.randrange(min(0x10000, n))
            else:
                off = rng.randrange(n)
            d[off] = rng.randrange(256)
    elif strat == 1:  # BPB fields
        fields = [(11, 2), (13, 1), (14, 2), (16, 1), (17, 2), (19, 2),
                  (21, 1), (22, 2), (24, 2), (26, 2), (32, 4), (36, 1),
                  (39, 4), (43, 11), (54, 8)]
        for off, sz in fields:
            if rng.random() < 0.4:
                v = rng.randrange(1 << (8 * sz))
                d[off:off + sz] = v.to_bytes(sz, "little")
    elif strat == 2:  # FAT entries
        spc = max(1, d[13])
        reserved = struct.unpack_from("<H", d, 14)[0]
        fat_size = struct.unpack_from("<H", d, 22)[0]
        bps = struct.unpack_from("<H", d, 11)[0] or 512
        fat_off = reserved * bps
        fatbytes = max(4, fat_size * bps)
        for _ in range(rng.randrange(1, 6)):
            off = fat_off + rng.randrange(0, fatbytes - 2)
            struct.pack_into("<H", d, off, rng.randrange(0x10000))
        _ = spc
    elif strat == 3:  # directory entries (root dir region)
        bps = struct.unpack_from("<H", d, 11)[0] or 512
        reserved = struct.unpack_from("<H", d, 14)[0]
        nfats = d[16] or 2
        fat_size = struct.unpack_from("<H", d, 22)[0]
        root_ents = struct.unpack_from("<H", d, 17)[0] or 224
        root = (reserved + nfats * fat_size) * bps
        for _ in range(rng.randrange(1, 5)):
            e = root + 32 * rng.randrange(0, root_ents)
            if e + 32 > n:
                break
            f = rng.choice([0, 11, 12, 26, 27, 28, 30])
            if f == 11:
                d[e + 11] = rng.choice([0x0F, 0x10, 0x20, 0x08, 0x01, 0xFF])
            elif f in (26, 28):
                struct.pack_into("<H", d, e + f, rng.randrange(0x10000))
            elif f == 30:
                struct.pack_into("<H", d, e + 30, rng.randrange(0x10000))
            else:
                d[e + f] = rng.randrange(256)
    elif strat == 4:  # LFN entry corruption in root dir
        bps = struct.unpack_from("<H", d, 11)[0] or 512
        reserved = struct.unpack_from("<H", d, 14)[0]
        nfats = d[16] or 2
        fat_size = struct.unpack_from("<H", d, 22)[0]
        root = (reserved + nfats * fat_size) * bps
        for i in range(0, 16):
            e = root + 32 * i
            if e + 32 > n:
                break
            if d[e + 11] == 0x0F and rng.random() < 0.5:
                for _ in range(rng.randrange(1, 10)):
                    d[e + rng.randrange(32)] = rng.randrange(256)
    elif strat == 6:  # semantic FAT corruption on a valid geometry
        bps, fat_off, root, data, root_ents = geom(d)
        for _ in range(rng.randrange(1, 4)):
            cl = rng.choice([2, 3, rng.randrange(2, 64)])
            struct.pack_into("<H", d, fat_off + 2 * cl, rng.choice(
                [0, 1, 2, 3, 0xFFF6, 0xFFF7, 0xFFF8, 0xFFFE, 0xFFFF,
                 0x7FFF, 4000, 9000, 0x0555, 0xAAAA]))
    elif strat == 7:  # used directory entries: size/cluster fields
        bps, fat_off, root, data, root_ents = geom(d)
        for i in range(root_ents):
            e = root + 32 * i
            if e + 32 > n or d[e] == 0:
                break
            if rng.random() < 0.4:
                f = rng.choice([26, 28, 30, 20, 21, 22])
                if f in (26, 28, 30, 20, 22):
                    struct.pack_into("<H", d, e + f, rng.choice(
                        [0, 1, 2, 3, 0xFFFE, 0xFFFF, 0x7FFF]))
                else:
                    struct.pack_into("<I", d, e + 28, rng.choice(
                        [0, 1, 0xFFFF, 0xFFFFF, 0xFFFFFFFF, 0x7FFFFFFF]))
    elif strat == 8:  # LFN sequence games
        bps, fat_off, root, data, root_ents = geom(d)
        for i in range(8):
            e = root + 32 * i
            if e + 32 > n:
                break
            if d[e + 11] == 0x0F:
                r = rng.random()
                if r < 0.33:
                    d[e] = rng.choice([0x00, 0x01, 0x41, 0x42, 0x7F, 0x80, 0xFF])
                elif r < 0.66:
                    d[e + 13] = rng.randrange(256)  # checksum
                else:
                    for _ in range(rng.randrange(1, 8)):
                        d[e + rng.randrange(1, 32)] = rng.randrange(256)
    else:  # truncate/append-style: cluster chain numbers near boundaries
        for _ in range(rng.randrange(1, 4)):
            off = rng.choice([0x00, 0x0b, 0x0d, 0x0e, 0x10, 0x11, 0x13,
                              0x15, 0x16, 0x18, 0x1a, 0x20, 0x24, 0x28])
            if off + 4 <= n:
                struct.pack_into("<I", d, off, rng.choice(
                    [0, 1, 2, 0xFFFF, 0xFFFFF, 0xFFFFFFFF]))
    return d


def run_remote(remote_dir, fsck_args):
    script = (
        "cd %s && rm -rf crashes && mkdir crashes && "
        "for f in m*.img; do "
        "/data/local/tmp/fsck_msdos %s \"$f\" >/dev/null 2>&1; rc=$?; "
        "if [ $rc -ge 128 ]; then echo \"CRASH $rc $f\"; cp \"$f\" crashes/; fi; "
        "done; echo LOOP_DONE; ls crashes | wc -l" % (remote_dir, fsck_args)
    )
    return adb("shell", script, timeout=600)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", required=True)
    ap.add_argument("--count", type=int, default=256)
    ap.add_argument("--batch", type=int, default=64)
    ap.add_argument("--outdir", default="artifacts/sd-fuzz")
    ap.add_argument("--fsck-args", default="-p -f",
                    help="exact vold invocation by default (preen + force)")
    args = ap.parse_args()

    seed = open(args.seed, "rb").read()
    os.makedirs(args.outdir, exist_ok=True)
    rng = random.Random(0xB100D)
    total = 0
    found = 0
    t0 = time.time()
    while total < args.count:
        n = min(args.batch, args.count - total)
        local = os.path.join(args.outdir, "batch")
        subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", local],
                       capture_output=True)
        os.makedirs(local, exist_ok=True)
        for i in range(n):
            img = mutate(seed, rng)
            open(os.path.join(local, "m%04d.img" % i), "wb").write(img)
        adb("shell", "rm -rf %s" % REMOTE)
        r = adb("push", local, REMOTE, timeout=900)
        if r.returncode != 0:
            print("push failed:", r.stderr[:200])
            return 2
        out = run_remote(REMOTE, args.fsck_args)
        txt = out.stdout
        crashes = [l for l in txt.splitlines() if l.startswith("CRASH")]
        found += len(crashes)
        total += n
        rate = total / max(1e-9, time.time() - t0)
        print("batch %d/%d: %d crashes (total %d) %.1f img/s"
              % (total, args.count, len(crashes), found, rate))
        for c in crashes:
            print("  ", c)
        if crashes:
            adb("pull", REMOTE + "/crashes", os.path.join(args.outdir, "crashes"),
                timeout=300)
    print("done: %d mutants, %d crashes, %.1fs" % (total, found, time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
