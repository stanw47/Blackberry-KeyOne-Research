#!/usr/bin/env python3
"""
auth_capture.py - trigger the KEYone authboot/RTAS exchange and capture the
device-side frames on the auth interface (0FCA:8040 intf 1, ep 0x82/0x02),
without USBPcap.

Sequence:
  1. claim intf 0 (fastboot) + intf 1 (auth)
  2. send a gated fastboot command on ep 0x01 (default: "oem getvarp:bsn")
  3. read device->PC frames on ep 0x82 for N seconds, hex-dump each
  4. also drain fastboot responses on ep 0x81

Safe: no response is sent back to the auth interface; the gated command will
fail/timeout on the device side (session stays in bootloader).
"""
import os, sys, time, argparse
for _d in (r"C:\bb10mt", os.path.dirname(os.path.abspath(__file__))):
    try: os.add_dll_directory(_d)
    except Exception: pass
import usb.core, usb.util, usb.backend.libusb1 as lb

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", default="oem getvarp:bsn")
    ap.add_argument("--seconds", type=int, default=8)
    args = ap.parse_args()

    backend = lb.get_backend(find_library=lambda x: r"C:\bb10mt\libusb-1.0.dll")
    d = usb.core.find(idVendor=0x0FCA, idProduct=0x8040, backend=backend)
    if d is None:
        print("device not found (is it in fastboot?)"); return 2
    for i in (0, 1):
        try:
            if d.is_kernel_driver_active(i): d.detach_kernel_driver(i)
        except Exception: pass
    try:
        usb.util.claim_interface(d, 0)
        usb.util.claim_interface(d, 1)
    except Exception as e:
        print("claim failed:", e); return 2
    print(f"[*] sending gated cmd: {args.cmd!r} on ep 0x01")
    try:
        d.write(0x01, args.cmd.encode())
    except Exception as e:
        print("write failed:", e)

    print(f"[*] capturing auth frames on ep 0x82 for {args.seconds}s")
    t0 = time.time()
    while time.time() - t0 < args.seconds:
        got = False
        for ep, tag in ((0x82, "AUTH"), (0x81, "FB")):
            try:
                data = d.read(ep, 4096, timeout=250)
                print(f"[{tag}] {len(data)} {data.tobytes().hex()}")
                got = True
            except usb.core.USBTimeoutError:
                pass
            except Exception as e:
                print(f"[{tag}] err {type(e).__name__} {e}")
        if not got:
            time.sleep(0.05)
    usb.util.release_interface(d, 1)
    usb.util.release_interface(d, 0)
    print("[*] done")
    return 0

if __name__ == "__main__":
    sys.exit(main())
