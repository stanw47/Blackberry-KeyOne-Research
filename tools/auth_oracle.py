#!/usr/bin/env python3
"""
auth_oracle.py - KEYone auth-channel permission oracle.
Holds the auth interface (0FCA:8040 intf 1), answers the device's
has-permission requests with YES, while authboot.exe drives the
fastboot command (oem set-factory-mode) on the fastboot interface.

Protocol (device-initiated):
  DEV -> PC: {cookie 0xbba78701, code=0x1012, tool_name...}   rtas init
  PC  -> DEV: {cookie, 0x1013, result=1, ...}
  DEV -> PC: {cookie, code=0x1014, code_being_checked...}     has-permission
  PC  -> DEV: {cookie, 0x1015, answer=1, ...}
"""
import os, sys, time, struct
for _d in (r"C:\bb10mt", os.path.dirname(os.path.abspath(__file__))):
    try: os.add_dll_directory(_d)
    except Exception: pass
import usb.core, usb.util, usb.backend.libusb1 as lb

COOKIE = 0xbba78701

def frame(code, payload=b""):
    return struct.pack("<II", COOKIE, code) + payload

def handshake_frame():
    return frame(0x2000, struct.pack("<I", 0x00010003) + b"Linux" + struct.pack("<I", 0x78) + b"\x00" * 8)

def main():
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    backend = lb.get_backend(find_library=lambda x: r"C:\bb10mt\libusb-1.0.dll")
    d = usb.core.find(idVendor=0x0FCA, idProduct=0x8040, backend=backend)
    if d is None:
        print("[!] device not found (bootloader mode required)"); return 2
    for i in (0, 1):
        try:
            if d.is_kernel_driver_active(i): d.detach_kernel_driver(i)
        except Exception: pass
    try:
        usb.util.claim_interface(d, 1)
        print("[*] auth interface claimed")
    except Exception as e:
        print("[!] claim failed:", e); return 3

    print("[*] handshake 0x2000")
    d.write(0x02, handshake_frame(), timeout=2000)
    t0 = time.time()
    answers = 0
    while time.time() - t0 < seconds:
        try:
            b = d.read(0x82, 4096, timeout=400).tobytes()
        except usb.core.USBTimeoutError:
            continue
        except Exception as e:
            print(f"[!] read err {e}")
            break
        if len(b) < 8:
            print(f"[?] short {len(b)} {b.hex()}")
            continue
        cookie, code = struct.unpack("<II", b[:8])
        payload = b[8:]
        print(f"[<] code={code:#06x} len={len(b)} payload={payload[:48].hex()}")
        if code == 0x1012:
            # rtas init request (tool name in payload) -> reply 0x1013 result=1
            rep = frame(0x1013, struct.pack("<I", 1) + payload[:0x1f] + b"\x00" * 8)
            d.write(0x02, rep, timeout=2000)
            print(f"[>] replied 0x1013 result=1 ({len(rep)}B)")
            answers += 1
        elif code == 0x1014:
            # has-permission request -> reply 0x1015 answer=1
            rep = frame(0x1015, struct.pack("<I", 1) + payload[:0x20])
            d.write(0x02, rep, timeout=2000)
            print(f"[>] replied 0x1015 answer=1 ({len(rep)}B)")
            answers += 1
        elif code == 0x2004:
            # RTAS/nv challenge - log (not expected during oem)
            print(f"[<] challenge received: {payload[:64].hex()}")
        else:
            print(f"[<] unhandled code={code:#06x}")
    print(f"[*] done, answered {answers} requests")
    return 0

if __name__ == "__main__":
    sys.exit(main())
