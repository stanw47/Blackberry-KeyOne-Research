#!/usr/bin/env python3
"""
Long fastboot command transport probe (BlackBerry KEYone, libusb direct).

Determines whether long commands fail because of host transfer size or
device-side handling:
  - sanity single small command
  - long command sent in paced 64-byte chunks
  - long command sent as one bulk write
  - liveness check after each step (short command)

Stops immediately when the endpoint stalls (needs USB replug to recover).

Usage:
    py -3.11 fb_longcmd_probe.py [--chars 1500] [--chunk 64] [--delay 0.02]
"""
import argparse
import os
import sys
import time

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
        out = fb.command("getvar version", seconds=4)
    except usb.core.USBError as e:
        print(f"  [{label}] liveness: STALL ({e})")
        return False
    ok = b"OKAY" in out or b"version" in out
    print(f"  [{label}] liveness: {'OK' if ok else 'NO-RESPONSE'} ({out[:40]!r})")
    return ok


def single(fb, text, seconds=8):
    try:
        out = fb.command(text, seconds=seconds)
        print(f"  single write ({len(text)}B): {out[:60]!r}")
        return True
    except usb.core.USBError as e:
        print(f"  single write ({len(text)}B): STALL ({e})")
        return False


def chunked(fb, text, chunk=64, delay=0.02, seconds=10):
    b = text.encode()
    try:
        for i in range(0, len(b), chunk):
            fb.ep_out.write(b[i:i + chunk], timeout=5000)
            time.sleep(delay)
        out = fb.collect(seconds=seconds)
        print(f"  chunked write ({len(b)}B in {chunk}B chunks): {out[:60]!r}")
        return True
    except usb.core.USBError as e:
        print(f"  chunked write ({len(b)}B): STALL ({e})")
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chars", type=int, default=1500)
    ap.add_argument("--chunk", type=int, default=64)
    ap.add_argument("--delay", type=float, default=0.02)
    args = ap.parse_args()

    fb = open_fb()
    if not fb:
        return 1
    print(f"[*] {fb.endpoints}")

    print("[1] sanity")
    if not liveness(fb, "pre"):
        print("[!] endpoint already stalled - replug USB and retry")
        return 2

    name = "A" * args.chars
    print(f"[2] chunked getvar ({args.chars} chars)")
    ok = chunked(fb, "getvar " + name, args.chunk, args.delay)
    if not liveness(fb, "post-chunk"):
        print("[!] stalled after chunked write - replug to continue")
        return 3

    print(f"[3] single-write getvar ({args.chars} chars)")
    ok = single(fb, "getvar " + name)
    if not liveness(fb, "post-single"):
        print("[!] stalled after single write - replug to continue")
        return 4

    print("[*] both transports survived")
    fb.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
