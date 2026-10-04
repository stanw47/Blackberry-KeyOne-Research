#!/usr/bin/env python3
"""
authboot_client.py - RTAS2 / authboot protocol research harness (BlackBerry KEYone).

The KEYone bootloader runs the "authboot" (RTAS2) protocol used to authorize
privileged operations (unlock, flash, erase, factory-mode) and to provision
debug tokens (e.g. /nvuser/hlos_unsigned.tkn -> skips image verification).

This is the FRAMEWORK to capture, replay, and (carefully) fuzz that protocol.
Modeled on pcauthtool.exe + bbauthtool (LK side).

SAFE BY DEFAULT. Nothing is sent unless you pass a subcommand that writes.

Protocol structs (from pcauthtool.exe):
    msg_header_t            { cookie, msg_size, version, code }
    msg_pc_handshake_dev_t  / msg_dev_handshake_pc_t
    msg_dev_password_pc_t   / msg_pc_password_dev_t
    msg_dev_rtas_chal_pc_t  / msg_pc_rtas_chal_dev_t
LK events: HANDSHAKE, PASSWORD, RTAS_INIT, RTAS_HAS_PERM, RTAS_SIGN, DISCONNECTED

Usage:
    py -3.11 authboot_client.py scan
    py -3.11 authboot_client.py sniff [--vid 0x0FCA --pid 0x8040] [--interface 1]
    py -3.11 authboot_client.py send --hex 01020304...
    py -3.11 authboot_client.py frame --cookie 0x... --code 0 --size 12 --version 1
"""
import argparse
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

# Known BlackBerry (0FCA) interfaces
BB_IFACES = {
    0x8030: "fastboot (composite MI_00)",
    0x8040: "fastboot (KEY2/KEYone)",
    0x8041: "MTP/composite",
    0x8042: "ADB composite",
    0x8001: "bootloader/loader",
    0x8014: "mass storage",
    0x8017: "device/tether",
    0x8031: "composite (STV)",
    0x8032: "ADB composite (Priv)",
}

# LK authboot event codes (working hypothesis; confirm by capture)
EVENTS = {
    0: "HANDSHAKE",
    1: "PASSWORD",
    2: "RTAS_INIT",
    3: "RTAS_HAS_PERM",
    4: "RTAS_SIGN",
    5: "DISCONNECTED",
}


def find(vid, pid):
    return list(usb.core.find(find_all=True, idVendor=vid, idProduct=pid))


def dump_endpoints(dev):
    cfg = None
    try:
        cfg = dev.get_active_configuration()
    except usb.core.USBError as e:
        print(f"    [desc err] {e}")
        return []
    eps = []
    for intf in cfg:
        for ep in intf:
            eps.append((intf.bInterfaceNumber, ep.bEndpointAddress,
                        usb.util.endpoint_type(ep.bmAttributes),
                        usb.util.endpoint_direction(ep.bEndpointAddress)))
    return eps


def cmd_scan(args):
    print("[*] scanning BlackBerry USB devices ...")
    found = False
    for pid, name in BB_IFACES.items():
        for d in find(args.vidint, pid):
            found = True
            try:
                sn = d.serial_number
            except Exception:
                sn = "<n/a>"
            print(f"    {args.vidint:04x}:{pid:04x}  {name}  bus={d.bus} addr={d.address} sn={sn}")
            for bn, ep, typ, dirn in dump_endpoints(d):
                dstr = "IN" if dirn == usb.util.ENDPOINT_IN else "OUT"
                print(f"        if{bn} ep0x{ep:02x} {dstr} type={typ}")
    if not found:
        print("    (none)")
    return 0


class BbTransport:
    def __init__(self, dev, interface=0, timeout=3000):
        self.dev = dev
        self.timeout = timeout
        cfg = dev.get_active_configuration()
        intf = cfg[(interface, 0)]
        self.ep_in = usb.util.find_descriptor(
            intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)
        self.ep_out = usb.util.find_descriptor(
            intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
        if not self.ep_in or not self.ep_out:
            raise RuntimeError("no bulk endpoints on interface")
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

    def close(self):
        try:
            usb.util.release_interface(self.dev, self.interface)
        except Exception:
            pass


def build_frame(cookie, code, version, payload=b""):
    """Working-hypothesis msg_header_t + payload."""
    body = payload
    total = 16 + len(body)
    return struct.pack("<IIII", cookie, total, version, code) + body


def cmd_sniff(args):
    devs = find(args.vidint, args.pid)
    if not devs:
        print(f"[!] no {args.vidint:04x}:{args.pid:04x} device")
        return 1
    t = BbTransport(devs[0], interface=args.interface)
    print(f"[*] claimed {args.vidint:04x}:{args.pid:04x} if{args.interface}; sniffing {args.seconds}s")
    end = time.time() + args.seconds
    while time.time() < end:
        try:
            data = t.read()
            if data:
                print(f"[<] {len(data)} bytes: {data.hex()}")
        except usb.core.USBError as e:
            if "timeout" not in str(e).lower():
                print(f"[!] {e}")
                break
    t.close()
    return 0


def cmd_frame(args):
    data = build_frame(args.cookie, args.code, args.version, bytes.fromhex(args.payload or ""))
    print("[*] frame:", data.hex())
    print("    cookie=%#x code=%d(%s) version=%d size=%d" %
          (args.cookie, args.code, EVENTS.get(args.code, "?"), args.version, len(data)))
    if args.send:
        devs = find(args.vidint, args.pid)
        if not devs:
            print("[!] device not found")
            return 1
        t = BbTransport(devs[0], interface=args.interface)
        t.write(data)
        print("[*] sent")
        try:
            print("[<]", t.read().hex())
        except usb.core.USBError as e:
            print("[!]", e)
        t.close()
    return 0


def cmd_send(args):
    data = bytes.fromhex(args.hex)
    devs = find(args.vidint, args.pid)
    if not devs:
        print("[!] device not found")
        return 1
    t = BbTransport(devs[0], interface=args.interface)
    t.write(data)
    print(f"[*] sent {len(data)} bytes")
    try:
        print("[<]", t.read().hex())
    except usb.core.USBError as e:
        print("[!]", e)
    t.close()
    return 0


def main():
    ap = argparse.ArgumentParser(description="RTAS2/authboot research harness")
    ap.add_argument("--vid", default="0x0FCA")
    ap.add_argument("--pid", default="0x8040")
    ap.add_argument("--interface", type=int, default=0)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan"); s.set_defaults(fn=cmd_scan)
    s = sub.add_parser("sniff"); s.add_argument("--seconds", type=float, default=10); s.set_defaults(fn=cmd_sniff)

    s = sub.add_parser("frame")
    s.add_argument("--cookie", type=lambda x: int(x, 0), default=0x0)
    s.add_argument("--code", type=int, default=0)
    s.add_argument("--version", type=int, default=1)
    s.add_argument("--payload", default="")
    s.add_argument("--send", action="store_true")
    s.set_defaults(fn=cmd_frame)

    s = sub.add_parser("send"); s.add_argument("--hex", required=True); s.set_defaults(fn=cmd_send)

    args = ap.parse_args()
    args.vidint = int(args.vid, 0)
    args.pid = int(args.pid, 0)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
