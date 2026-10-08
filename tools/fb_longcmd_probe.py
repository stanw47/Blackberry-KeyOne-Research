#!/usr/bin/env python3
"""
Fastboot long-command boundary probe (BlackBerry KEYone, libusb direct).

Protocol note: LK treats ONE USB bulk OUT transfer as ONE complete command
line. Chunked writes are NOT valid fastboot (each chunk would be a separate
command, and the device blocks sending its reply while we keep writing).
The correct test is a single `ep_out.write()` of the full command, then read
the reply.

Steps:
  1. sanity `getvar:version` (expect OKAY)
  2. single-transfer `getvar:` + N chars  (--chars)
  3. liveness
  4. optional second size (--chars2) + liveness

Stops at the first stall (endpoint needs USB replug to recover).

Usage:
    py -3.11 fb_longcmd_probe.py --chars 1018 [--chars2 1500]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import usb.backend.libusb1 as lb
import usb.core
import usb.util

from fastboot_libusb import Fastboot


def get_backend():
    for p in (r"C:\bb10mt\libusb-1.0.dll",
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "libusb-1.0.dll")):
        if os.path.exists(p):
            return lb.get_backend(find_library=lambda n, p=p: p)
    return None


def open_fb():
    be = get_backend()
    devs = list(usb.core.find(find_all=True, idVendor=0x0FCA, idProduct=0x8040, backend=be))
    if not devs:
        print("[!] no fastboot device")
        return None
    return Fastboot(devs[0], interface=0, timeout=5000)


def liveness(fb, label):
    try:
        out = fb.command("getvar:version", seconds=4)
    except usb.core.USBError as e:
        print(f"  [{label}] liveness: STALL ({e})")
        return False
    ok = b"OKAY" in out
    print(f"  [{label}] liveness: {'OK' if ok else 'NO-RESPONSE'} ({out[:40]!r})")
    return ok


def single(fb, text, seconds=8):
    try:
        fb.ep_out.write(text.encode(), timeout=6000)
        out = fb.collect(seconds=seconds)
        print(f"  single write {len(text)}B -> {out[:70]!r}")
        return True
    except usb.core.USBError as e:
        print(f"  single write {len(text)}B -> STALL ({e})")
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chars", type=int, default=1018)
    ap.add_argument("--chars2", type=int, default=0)
    args = ap.parse_args()

    fb = open_fb()
    if not fb:
        return 1
    print(f"[*] {fb.endpoints}")

    if not liveness(fb, "pre"):
        print("[!] endpoint stalled - replug USB and retry")
        return 2

    size = args.chars + 7
    print(f"[1] single transfer, total {size}B")
    if not single(fb, "getvar:" + "A" * args.chars):
        print("[!] stalled - replug USB to continue")
        return 3
    if not liveness(fb, "post1"):
        print("[!] stalled - replug USB to continue")
        return 3

    if args.chars2:
        size2 = args.chars2 + 7
        print(f"[2] single transfer, total {size2}B")
        if not single(fb, "getvar:" + "B" * args.chars2):
            print("[!] stalled - replug USB to continue")
            return 4
        if not liveness(fb, "post2"):
            print("[!] stalled - replug USB to continue")
            return 4

    print("[*] survived")
    fb.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
