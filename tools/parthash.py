#!/usr/bin/env python3
"""
parthash.py - pre-auth partition hash oracle client for the BlackBerry KEYone.

The ABL766 bootloader exposes `oem parthash:<partition> <bytes>` WITHOUT
authentication. It returns INFO<SHA-224 hex>OKAY over the first <bytes> of the
named partition (excluding a data blacklist: cache, userdata).

Usage:
    py -3.11 parthash.py query <partition> <bytes>
    py -3.11 parthash.py compare <partition> <local-file>
    py -3.11 parthash.py list            # probe a built-in candidate list

Notes:
    - Uses the raw libusb fastboot transport (fastboot_libusb.py).
    - Digest is SHA-224 of raw partition bytes from offset 0.
"""
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import usb.backend.libusb1 as lb
import usb.core

from fastboot_libusb import Fastboot

PARTITIONS = [
    "prdid", "boardid", "sbl1", "rpm", "tz", "devcfg", "aboot", "tunning",
    "traceability", "fsg", "boot", "bootsig", "keymaster", "lksecapp",
    "cmnlib", "cmnlib64", "modem", "ddrbak", "dip", "mdtp", "devinfo",
    "apdp", "msadp", "dpo", "splash", "ddr", "sec", "limits", "fsc", "ssd",
    "modemst1", "modemst2", "oempersist", "persist", "misc", "keystore",
    "config", "frp", "recovery", "recoverysig", "perm", "nvuser", "metadata",
    "rcause", "bcota", "blog", "dsp", "syscfg", "mota", "mcfg", "hdcp",
    "bbpersist", "oem", "system",
]


def backend():
    for p in (r"C:\bb10mt\libusb-1.0.dll",
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "libusb-1.0.dll")):
        if os.path.exists(p):
            return lb.get_backend(find_library=lambda n, p=p: p)
    return None


def open_fb():
    devs = list(usb.core.find(find_all=True, idVendor=0x0FCA, idProduct=0x8040,
                              backend=backend()))
    if not devs:
        print("[!] no fastboot device")
        return None
    return Fastboot(devs[0], interface=0, timeout=5000)


def cmd(fb, text, seconds=8):
    fb.ep_out.write(text.encode(), timeout=8000)
    return fb.collect(seconds)


def parse_info(raw):
    s = raw.decode("latin1")
    i, k = s.find("INFO"), s.find("OKAY")
    if i >= 0 and k > i:
        return s[i + 4:k]
    return None


def do_query(fb, part, size):
    return parse_info(cmd(fb, "oem parthash:%s %d" % (part, size)))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("query"); q.add_argument("partition"); q.add_argument("bytes", type=int)
    c = sub.add_parser("compare"); c.add_argument("partition"); c.add_argument("file")
    sub.add_parser("list")
    args = ap.parse_args()

    fb = open_fb()
    if not fb:
        return 1

    if args.cmd == "query":
        h = do_query(fb, args.partition, args.bytes)
        print(h or "ERROR")
    elif args.cmd == "compare":
        n = os.path.getsize(args.file)
        local = hashlib.sha224(open(args.file, "rb").read()).hexdigest()
        h = do_query(fb, args.partition, n)
        print("device %s[0:%d] = %s" % (args.partition, n, h or "ERROR"))
        print("local  %s      = %s" % (args.file, local))
        print("MATCH" if h == local else "DIFF")
    elif args.cmd == "list":
        for p in PARTITIONS:
            h = do_query(fb, p, 64)
            print("%-14s %s" % (p, h[:56] if h else "n/a"))
    fb.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
