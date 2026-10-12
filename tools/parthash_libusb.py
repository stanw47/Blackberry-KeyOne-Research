#!/usr/bin/env python3
"""Resumable parthash extraction using the resident libusb client (fb2.py style).
Usage: fb_extract.py <part> <target_n> <logfile>"""
import sys, time, hashlib, re, os
import usb.core, usb.util

VID, PID = 0x0fca, 0x8040

class FB:
    def __init__(self):
        self.dev = usb.core.find(idVendor=VID, idProduct=PID)
        if self.dev is None:
            raise SystemExit("no fastboot device")
        cfg = self.dev.get_active_configuration()
        intf = cfg[(0, 0)]
        usb.util.claim_interface(self.dev, 0)
        self.ep_in = usb.util.find_descriptor(intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)
        self.ep_out = usb.util.find_descriptor(intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
    def cmd(self, s, wtimeout=8000, rtimeout=6.0):
        self.ep_out.write(s.encode('ascii'), timeout=wtimeout)
        buf = b''
        t0 = time.time()
        while time.time() - t0 < rtimeout:
            try:
                chunk = self.ep_in.read(64, timeout=1500)
                buf += bytes(chunk)
            except usb.core.USBTimeoutError:
                if buf:
                    break
                continue
            if b'OKAY' in buf or b'FAIL' in buf:
                break
        return buf
    def parthash(self, part, size):
        r = self.cmd(f"oem parthash:{part}:{size}")
        m = re.search(rb'([0-9a-f]{56})', r)
        return m.group(1).decode() if m else None

part, target_n, logfile = sys.argv[1], int(sys.argv[2]), sys.argv[3]

known = b""
if os.path.exists(logfile):
    hexes = re.findall(r'\[([0-9a-f]+)\]', open(logfile).read())
    if hexes:
        known = bytes.fromhex(hexes[-1])

fb = FB()
print(f"resuming {part} at {len(known)} bytes, target {target_n}", flush=True)
with open(logfile, "a") as log:
    for i in range(len(known) + 1, target_n + 1):
        try:
            target = fb.parthash(part, i)
        except Exception as e:
            print(f"[!] usb error at size {i}: {e}", flush=True)
            break
        if target is None:
            print(f"[!] no hash for size {i}", flush=True)
            break
        found = None
        for b in range(256):
            if hashlib.sha224(known + bytes([b])).hexdigest() == target:
                found = b
                break
        if found is None:
            print(f"[!] no byte match at offset {i-1}", flush=True)
            break
        known += bytes([found])
        ch = chr(found) if 32 <= found < 127 else '.'
        log.write(f"{i-1:4}: {found:#04x} {ch}   [{known.hex()}]\n")
        if i % 256 == 0:
            log.flush()
            print(f"progress: {i}/{target_n}", flush=True)
        time.sleep(0.004)
print("done:", len(known), flush=True)
