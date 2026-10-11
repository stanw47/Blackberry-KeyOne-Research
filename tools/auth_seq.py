#!/usr/bin/env python3
"""auth_seq.py - handshake then a sequence of raw frames, one connection."""
import os, sys, time, struct
for _d in (r"C:\bb10mt", os.path.dirname(os.path.abspath(__file__))):
    try: os.add_dll_directory(_d)
    except Exception: pass
import usb.core, usb.util, usb.backend.libusb1 as lb

COOKIE = 0xbba78701
def fr(code, payload=b""): return struct.pack("<II", COOKIE, code) + payload

def main():
    frames = []
    # default sequence: handshake, 0x1012 (rtas init), 0x1016
    hs = fr(0x2000, struct.pack("<I", 0x00010003) + b"Linux" + struct.pack("<I", 0x78) + b"\x00" * 8)
    # 0x1016: payload offsets: +0 = msg+8 (name str), +0x20 = msg+0x28, +0x120 = msg+0x128 (must be nonzero)
    p1016 = bytearray(b"\x00" * 0x124)
    p1016[0:8] = b"nvitem\x00\x00"
    p1016[0x20:0x28] = b"signit\x00\x00"
    p1016[0x120:0x124] = struct.pack("<I", 1)
    chal_trunc = fr(0x2005, struct.pack("<IHH", 0, 0xFFFE, 0x0001) + b"\x00" * 32)
    chal_norm = fr(0x2005, struct.pack("<IHH", 0, 0x10, 0x10) + b"\x41" * 32)
    seq = [("handshake", hs),
           ("0x1016 nvsign", fr(0x1016, bytes(p1016))),
           ("0x2005 trunc", chal_trunc),
           ("0x2005 normal", chal_norm)]
    if len(sys.argv) > 1:
        seq = []
        for hx in sys.argv[1:]:
            seq.append((hx[:12], bytes.fromhex(hx)))

    backend = lb.get_backend(find_library=lambda x: r"C:\bb10mt\libusb-1.0.dll")
    d = usb.core.find(idVendor=0x0FCA, idProduct=0x8040, backend=backend)
    if d is None:
        print("device not found"); return 2
    for i in (0, 1):
        try:
            if d.is_kernel_driver_active(i): d.detach_kernel_driver(i)
        except Exception: pass
    usb.util.claim_interface(d, 0); usb.util.claim_interface(d, 1)
    for label, m in seq:
        print(f"[*] send {label}: {m.hex()[:80]}")
        try: d.write(0x02, m)
        except Exception as e:
            print("write failed:", e); break
        t0 = time.time()
        while time.time() - t0 < 2.5:
            for ep, tag in ((0x82, "AUTH"), (0x81, "FB")):
                try:
                    b = d.read(ep, 4096, timeout=200).tobytes()
                    if len(b) >= 8:
                        c, code = struct.unpack("<II", b[:8])
                        print(f"  [{tag}] {len(b)} cookie={c:#010x} code={code:#06x}")
                        print(f"        {b.hex()[:200]}")
                    else:
                        print(f"  [{tag}] {len(b)} {b.hex()}")
                except usb.core.USBTimeoutError:
                    pass
            time.sleep(0.02)
    usb.util.release_interface(d, 1); usb.util.release_interface(d, 0)
    print("[*] done")
    return 0

if __name__ == "__main__":
    sys.exit(main())
