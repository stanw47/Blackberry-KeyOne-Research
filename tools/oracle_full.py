#!/usr/bin/env python3
"""oracle_full.py - answer the KEYone no-password authboot flow with the exact
statuses the LK expects (decoded from ABL766):

  0x1010 (auth_password session query)  -> 0x1011 status=1
  0x1012 (auth_rtas_init)               -> 0x1013 status=0
  0x1014 (auth_rtas_has_permission)     -> 0x1015 status=0 result=1

Usage: oracle_full.py [seconds]
"""
import sys, time, struct
import usb.core, usb.util

COOKIE = 0xbba78701

def fr(code, *fields):
    return struct.pack("<II", COOKIE, code) + b"".join(struct.pack("<I", f) for f in fields)

def main():
    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    d = usb.core.find(idVendor=0x0FCA, idProduct=0x8040)
    if d is None:
        print("[!] device not found"); return 2
    for i in (0, 1):
        try:
            if d.is_kernel_driver_active(i):
                d.detach_kernel_driver(i)
        except Exception:
            pass
    usb.util.claim_interface(d, 1)
    print("[*] auth interface claimed", flush=True)

    hs = struct.pack("<II", COOKIE, 0x2000) + struct.pack("<I", 0x00010003) + b"Linux" + struct.pack("<I", 0x78) + b"\x00" * 8
    try:
        d.write(0x02, hs, timeout=2000)
        print("[>] handshake 0x2000 sent", flush=True)
    except Exception as e:
        print(f"[!] handshake failed: {e}", flush=True)

    t0 = time.time()
    while time.time() - t0 < secs:
        try:
            b = d.read(0x82, 4096, timeout=300).tobytes()
        except usb.core.USBTimeoutError:
            continue
        except usb.core.USBError as e:
            print(f"[!] USB error: {e}", flush=True)
            break
        if len(b) < 8:
            print(f"[?] short {len(b)}: {b.hex()}", flush=True)
            continue
        cookie, code = struct.unpack("<II", b[:8])
        print(f"[<] code={code:#06x} len={len(b)} {b[:64].hex()}", flush=True)
        try:
            if code == 0x1010:
                d.write(0x02, fr(0x1011, 1), timeout=2000)
                print("[>] 0x1011 status=1", flush=True)
            elif code == 0x1012:
                d.write(0x02, fr(0x1013, 0), timeout=2000)
                print("[>] 0x1013 status=0", flush=True)
            elif code == 0x1014:
                d.write(0x02, fr(0x1015, 0, 1), timeout=2000)
                print("[>] 0x1015 status=0 result=1", flush=True)
            elif code == 0x2004:
                print("[!] 0x2004 challenge (unexpected in this flow)", flush=True)
            else:
                print(f"[?] unhandled {code:#06x}", flush=True)
        except Exception as e:
            print(f"[!] reply error: {e}", flush=True)
            break
    print("[*] oracle done", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
