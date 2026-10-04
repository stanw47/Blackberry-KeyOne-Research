#!/usr/bin/env python3
"""
keyone_unlock.py - KEYone (BBB100-x) bootloader research harness.

A userland analogue of BlackBerryBootUnlock.exe: talks raw fastboot to the
BlackBerry bootloader over libusb (no Google fastboot / authboot needed), so we
can experiment with the same primitives the KEY2 unlock tool used:

    getvar:bb_bc_version  getvar:all  getvar:bootmode  reboot-bootloader

On the KEY2 that tool exploited CVE-2021-1931 (UEFI ABL RAM overflow). The KEYone
runs LittleKernel (emmc_appsboot.mbn), so the payload/patch table is different -
this harness is the *framework* for testing an analogous LK bug.

SAFE BY DEFAULT: all read-only unless you pass an explicit --send / --overflow.
Test only on a device you own.

Usage:
    py -3.11 keyone_unlock.py scan
    py -3.11 keyone_unlock.py info
    py -3.11 keyone_unlock.py cmd "getvar:bb_bc_version"
    # DANGEROUS (only after you have a validated payload + offsets):
    py -3.11 keyone_unlock.py overflow --file payload.bin --size 0x68C34
    py -3.11 keyone_unlock.py patch --file abl.bin --out patched.bin --offsets offsets.json
"""
import argparse
import json
import os
import struct
import sys
import time

for _d in (r"C:\bb10mt", os.path.dirname(os.path.abspath(__file__))):
    try:
        os.add_dll_directory(_d)
    except (AttributeError, FileNotFoundError, OSError):
        pass

try:
    import usb.core
    import usb.util
except Exception as exc:
    print(f"[fatal] pyusb not available: {exc}")
    sys.exit(2)

# BlackBerry USB IDs seen across modes
BB_PIDS = {
    0x0FCA: {
        0x8040: "fastboot (KEY2/KEYone)",
        0x8041: "MTP/BB composite",
        0x8042: "Android ADB composite",
        0x8014: "BB mass storage",
        0x8017: "BB device/tether",
        0x8001: "bootloader/loader",
    }
}


def find_all(vid, pid):
    return list(usb.core.find(find_all=True, idVendor=vid, idProduct=pid))


class Fastboot:
    """Minimal fastboot transport over libusb (BlackBerry 0FCA:8040)."""

    def __init__(self, dev, interface=0, timeout=3000):
        self.dev = dev
        self.timeout = timeout
        self.interface = interface
        cfg = dev.get_active_configuration()
        intf = cfg[(interface, 0)]
        self.ep_in = usb.util.find_descriptor(
            intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)
        self.ep_out = usb.util.find_descriptor(
            intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
        if not self.ep_in or not self.ep_out:
            raise RuntimeError("bulk endpoints not found")
        try:
            if dev.is_kernel_driver_active(interface):
                dev.detach_kernel_driver(interface)
        except (NotImplementedError, usb.core.USBError):
            pass
        usb.util.claim_interface(dev, interface)

    def write(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.ep_out.write(data, timeout=self.timeout)

    def read(self, size=4096):
        return bytes(self.ep_in.read(size, timeout=self.timeout))

    def collect(self, seconds=5.0):
        out = b""
        end = time.time() + seconds
        while time.time() < end:
            try:
                out += self.read()
            except usb.core.USBError as exc:
                if "timeout" in str(exc).lower():
                    break
                raise
            if b"OKAY" in out or b"FAIL" in out:
                break
        return out

    def command(self, text, seconds=5.0):
        self.write(text)
        return self.collect(seconds)

    def close(self):
        try:
            usb.util.release_interface(self.dev, self.interface)
        except Exception:
            pass


def cmd_scan(_):
    print("[*] scanning BlackBerry USB devices...")
    found = False
    for vid, pids in BB_PIDS.items():
        for pid, name in pids.items():
            for d in find_all(vid, pid):
                found = True
                try:
                    sn = d.serial_number
                except Exception:
                    sn = "<n/a>"
                print(f"    {vid:04x}:{pid:04x}  {name}  bus={d.bus} addr={d.address} sn={sn}")
    if not found:
        print("    (none - device off or unplugged)")
    return 0


def open_fastboot():
    devs = find_all(0x0FCA, 0x8040)
    if not devs:
        print("[!] no fastboot device (0FCA:8040). Bootloader mode?")
        return None
    return Fastboot(devs[0])


def cmd_info(_):
    fb = open_fastboot()
    if not fb:
        return 1
    print("[*] claimed fastboot interface")
    for c in ("getvar:bb_bc_version", "getvar:bootmode", "getvar:product",
              "getvar:variant", "getvar:subvariant", "getvar:all"):
        print(f"\n>>> {c}")
        try:
            print("   ", fb.command(c).decode("utf-8", "replace").replace("\r", "\n    "))
        except usb.core.USBError as e:
            print("    [err]", e)
    fb.close()
    return 0


def cmd_cmd(args):
    fb = open_fastboot()
    if not fb:
        return 1
    print(f">>> {args.command}")
    print("   ", fb.command(args.command).decode("utf-8", "replace").replace("\r", "\n    "))
    fb.close()
    return 0


def load_payload(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, "rb") as f:
        return bytearray(f.read())


def apply_patches(buf, offsets_json):
    """
    Apply a patch table: { "<hex offset>": <byte value or [bytes...]> }.
    Same idea as the KEY2 tool's hardcoded stind.i1 writes, driven by JSON so
    offsets can be derived per bootloader image instead of hardcoded.
    """
    with open(offsets_json) as f:
        table = json.load(f)
    n = 0
    for off_str, val in table.items():
        off = int(off_str, 0)
        if isinstance(val, list):
            for i, b in enumerate(val):
                buf[off + i] = b & 0xFF
            n += len(val)
        else:
            buf[off] = int(val) & 0xFF
            n += 1
    return n


def cmd_patch(args):
    buf = load_payload(args.file)
    n = apply_patches(buf, args.offsets)
    with open(args.out, "wb") as f:
        f.write(buf)
    print(f"[*] applied {n} byte(s) from {args.offsets}; wrote {args.out} ({len(buf)} bytes)")
    return 0


def cmd_overflow(args):
    """
    Send a payload of a given size to the fastboot OUT endpoint with the
    'flash:'-style / raw sequence. DANGEROUS - only with a validated payload.
    Mirrors the KEY2 tool: malloc(0x68C34) then bulk-send.
    """
    payload = load_payload(args.file)
    if args.size and len(payload) > args.size:
        payload = payload[:args.size]
    print(f"[!] about to send {len(payload)} bytes to fastboot OUT")
    if not args.yes:
        print("    refusing without --yes (this can brick the device)")
        return 2
    fb = open_fastboot()
    if not fb:
        return 1
    try:
        fb.write(payload)
        print("[*] payload sent; watching for response/reboot")
        print("   ", fb.collect(seconds=6).decode("utf-8", "replace"))
        time.sleep(7)
    except usb.core.USBError as e:
        print("[!] USB error during send:", e)
    fb.close()
    print("[*] done. Power-cycle if the device is unresponsive.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="KEYone bootloader research harness")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan").set_defaults(fn=cmd_scan)
    sub.add_parser("info").set_defaults(fn=cmd_info)

    p = sub.add_parser("cmd"); p.add_argument("command"); p.set_defaults(fn=cmd_cmd)

    p = sub.add_parser("patch")
    p.add_argument("--file", required=True); p.add_argument("--out", required=True)
    p.add_argument("--offsets", required=True); p.set_defaults(fn=cmd_patch)

    p = sub.add_parser("overflow")
    p.add_argument("--file", required=True)
    p.add_argument("--size", type=lambda x: int(x, 0), default=0x68C34)
    p.add_argument("--yes", action="store_true"); p.set_defaults(fn=cmd_overflow)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
