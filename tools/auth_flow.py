#!/usr/bin/env python3
"""
auth_flow.py - drive the KEYone authboot/RTAS exchange from the host.

Wire format (from pcauthtool.exe RE, 2026-10-11):
  frame = {cookie:u32 LE = 0xbba78701, code:u32 LE, payload...}, sent as ONE
  bulk transfer (size includes the 8-byte header).
  PC->DEV codes: 0x2000 handshake(28B), 0x2003 password(72B), 0x2005 chal resp(528B)
  DEV->PC codes: 0x2001 handshake, 0x2002 password, 0x2004 RTAS challenge

Usage:
  py -3.11 auth_flow.py handshake        # send 0x2000, dump replies
  py -3.11 auth_flow.py raw <hexbytes>   # send raw frame bytes, dump replies
"""
import os, sys, time, struct, argparse
for _d in (r"C:\bb10mt", os.path.dirname(os.path.abspath(__file__))):
    try: os.add_dll_directory(_d)
    except Exception: pass
import usb.core, usb.util, usb.backend.libusb1 as lb

COOKIE = 0xbba78701

def frame(code, payload=b""):
    return struct.pack("<II", COOKIE, code) + payload

def handshake_frame():
    # 28 bytes total: cookie, code=0x2000, 0x10003, "Linux", 0x78, 0, 0
    return frame(0x2000, struct.pack("<I", 0x00010003) + b"Linux" + struct.pack("<I", 0x78) + b"\x00" * 8)

def chal_frame(len_a=0, len_b=0, payload=b"", total_pad=0):
    # 0x2005: {cookie, code, field8=0, len_a:u16, len_b:u16, payload...}
    body = struct.pack("<IHH", 0, len_a, len_b) + payload
    if total_pad > len(body):
        body += b"\x00" * (total_pad - len(body))
    return frame(0x2005, body)

def dump_replies(d, seconds=6):
    t0 = time.time()
    seen = []
    while time.time() - t0 < seconds:
        for ep, tag in ((0x82, "AUTH"), (0x81, "FB")):
            try:
                data = d.read(ep, 4096, timeout=250)
                b = data.tobytes()
                print(f"[{tag}] {len(b)} {b.hex()}")
                if tag == "AUTH" and len(b) >= 8:
                    cookie, code = struct.unpack("<II", b[:8])
                    print(f"      cookie={cookie:#010x} code={code:#06x} payload={b[8:].hex()}")
                seen.append((tag, b))
            except usb.core.USBTimeoutError:
                pass
            except Exception as e:
                print(f"[{tag}] err {type(e).__name__} {e}")
                return seen
        time.sleep(0.02)
    return seen

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["handshake", "raw", "flow", "chal", "big", "probe"])
    ap.add_argument("hexbytes", nargs="?")
    ap.add_argument("--seconds", type=int, default=6)
    ap.add_argument("--size", type=int, default=0, help="total message size for big/chal")
    args = ap.parse_args()

    backend = lb.get_backend(find_library=lambda x: r"C:\bb10mt\libusb-1.0.dll")
    d = usb.core.find(idVendor=0x0FCA, idProduct=0x8040, backend=backend)
    if d is None:
        print("device not found (bootloader mode required)"); return 2
    for i in (0, 1):
        try:
            if d.is_kernel_driver_active(i): d.detach_kernel_driver(i)
        except Exception: pass
    usb.util.claim_interface(d, 0)
    usb.util.claim_interface(d, 1)

    if args.action in ("handshake", "flow"):
        msg = handshake_frame()
    elif args.action == "chal":
        # notes/18 truncation candidate: len_a+len_b+4 wraps to 3
        msg = chal_frame(len_a=0xFFFE, len_b=0x0001, payload=b"\x00" * 32)
    elif args.action == "big":
        # length-trust test: oversized 0x2005 (dispatcher stack buffer is 0x760)
        msg = chal_frame(len_a=0x10, len_b=0x10, payload=b"\x41" * max(0, args.size - 24))
    elif args.action == "probe":
        msg = handshake_frame()
    else:
        msg = bytes.fromhex(args.hexbytes or "")
    print(f"[*] sending {len(msg)} bytes: {msg.hex()}")
    try:
        d.write(0x02, msg)
        print("[*] sent; capturing replies")
    except Exception as e:
        print("write failed:", e)
    dump_replies(d, args.seconds)
    if args.action == "probe":
        # walk the state machine: 0x1010 (state), 0x1012 (rtas init -> challenge), 0x1016
        for label, m in (("0x1010", frame(0x1010, b"\x00" * 16)),
                         ("0x1012", frame(0x1012, b"\x00" * 16)),
                         ("0x1016", frame(0x1016, b"\x00" * 0x120))):
            print(f"[*] {label}: {m.hex()}")
            try:
                d.write(0x02, m)
            except Exception as e:
                print("write failed:", e); break
            dump_replies(d, args.seconds)
    if args.action == "flow":
        # password step (device has none set; send a zeroed 72B reply anyway)
        pw = frame(0x2003, b"\x00" * 64)
        print(f"[*] password reply: {len(pw)} bytes: {pw.hex()}")
        try:
            d.write(0x02, pw); print("[*] sent password reply; capturing replies")
        except Exception as e:
            print("write failed:", e)
        dump_replies(d, args.seconds)
    usb.util.release_interface(d, 1)
    usb.util.release_interface(d, 0)
    print("[*] done")
    return 0

if __name__ == "__main__":
    sys.exit(main())
