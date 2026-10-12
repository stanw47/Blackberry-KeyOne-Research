#!/usr/bin/env python3
"""
fb_fuzz.py - 0x2005 challenge-response fuzzer for the KEYone (ABL766).

Flow per case:
  1. start `fastboot oem getvarp:bsn` (triggers the RTAS challenge)
  2. capture the 0x2004 message (524B) on the auth interface
  3. parse its items (varint TLV: [len][type][value])
  4. build a 0x2005 response:
       region A = echo items (PIN type1 / echo type2 / BSN type3 / session type4)
       region B = DER signature blob (case-specific)
  5. send it, observe: fastboot result + whether 0x1010 (tool lane) arrives
  6. cleanup: garbage 0x2005 if the flow is still waiting; drain EP 0x81

Usage: fb_fuzz.py <mode> [count]
  modes: boundary | rs | items
"""
import sys, time, struct, subprocess, os
import usb.core, usb.util

COOKIE = 0xbba78701
FB_BIN = "/home/stanw47/Documents/Blackberry-KeyOne-Research/recon/2026-10-02/autoloader/ABL766 - Hn03/host/linux-x86/bin/fastboot"
SERIAL = "1164118297"

def varint(v):
    out = b""
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            return out

def parse_items(buf):
    items = []
    i = 0
    while i < len(buf):
        ln, i2 = 0, i
        shift = 0
        ok = False
        while i2 < len(buf) and shift < 35:
            c = buf[i2]; i2 += 1
            ln |= (c & 0x7f) << shift
            if not (c & 0x80):
                ok = True; break
            shift += 7
        if not ok or i2 >= len(buf):
            break
        ty, i3 = 0, i2
        shift = 0
        ok = False
        while i3 < len(buf) and shift < 35:
            c = buf[i3]; i3 += 1
            ty |= (c & 0x7f) << shift
            if not (c & 0x80):
                ok = True; break
            shift += 7
        if not ok or i3 + ln > len(buf):
            break
        items.append((ty, buf[i3:i3+ln]))
        i = i3 + ln
    return items

def enc_item(ty, val):
    return varint(len(val)) + varint(ty) + val

class FB:
    def __init__(self):
        self.d = usb.core.find(idVendor=0x0FCA, idProduct=0x8040)
        if self.d is None:
            raise SystemExit("no device")
        for i in (0, 1):
            try:
                if self.d.is_kernel_driver_active(i):
                    self.d.detach_kernel_driver(i)
            except Exception:
                pass
        usb.util.claim_interface(self.d, 1)
    def read_auth(self, timeout=250):
        try:
            b = self.d.read(0x82, 4096, timeout=timeout).tobytes()
            return b
        except usb.core.USBTimeoutError:
            return None
    def send(self, data, timeout=2000):
        self.d.write(0x02, data, timeout=timeout)
    def handshake(self):
        hs = struct.pack("<II", COOKIE, 0x2000) + struct.pack("<I", 0x00010003) + b"Linux" + struct.pack("<I", 0x78) + b"\x00" * 8
        self.send(hs)
    def drain_fb(self):
        for _ in range(8):
            try:
                self.d.read(0x81, 4096, timeout=250)
            except Exception:
                pass
    def garbage_2005(self):
        body = struct.pack("<IHH", 0, 256, 256) + b"\x00" * 512
        try:
            self.send(struct.pack("<II", COOKIE, 0x2005) + body)
        except Exception:
            pass

def build_response(items, sigblob):
    region_a = b"".join(enc_item(ty, val) for ty, val in items)
    body = struct.pack("<HH", len(region_a), len(sigblob)) + region_a + sigblob
    return struct.pack("<II", COOKIE, 0x2005) + struct.pack("<I", 0) + body

def wait_ready(tries=20):
    for _ in range(tries):
        try:
            p = subprocess.run([FB_BIN, "-s", SERIAL, "getvar", "version"],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=6)
            if "version:" in p.stdout:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False

def run_case(fb, case_name, region_items, sigblob):
    if not wait_ready():
        return case_name, "device-not-ready", "-"
    proc = subprocess.Popen([FB_BIN, "-s", SERIAL, "oem", "getvarp:bsn"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    chal = None
    t0 = time.time()
    passed = False
    while time.time() - t0 < 6:
        b = fb.read_auth()
        if b is None:
            if proc.poll() is not None:
                break
            continue
        if len(b) < 8:
            continue
        code = struct.unpack("<I", b[4:8])[0]
        if code == 0x2004:
            chal = b
            break
    if chal is None:
        proc.kill()
        out = proc.communicate()[0]
        return case_name, "no-challenge", out.strip()[:60]
    # extract challenge items (payload after 12B hdr; trailing u32 len)
    payload = chal[12:520]
    items = parse_items(payload)
    # build echo items: keep types 1..4 from the challenge (PIN/echo/BSN/session)
    echo = [(ty, val) for ty, val in items if ty in (1, 2, 3, 4)]
    if not region_items:
        region_items = echo
    resp = build_response(region_items, sigblob)
    try:
        fb.send(resp)
    except Exception as e:
        fb.garbage_2005()
        proc.kill()
        return case_name, "send-err", str(e)
    # observe
    t0 = time.time()
    while time.time() - t0 < 5:
        b = fb.read_auth()
        if b is not None and len(b) >= 8:
            code = struct.unpack("<I", b[4:8])[0]
            if code == 0x1010:
                passed = True
                fb.send(struct.pack("<III", COOKIE, 0x1011, 1))
            elif code == 0x1012:
                fb.send(struct.pack("<III", COOKIE, 0x1013, 0))
            elif code == 0x1014:
                fb.send(struct.pack("<IIII", COOKIE, 0x1015, 0, 1))
        if proc.poll() is not None:
            break
    if proc.poll() is None:
        fb.garbage_2005()
        try:
            out = proc.communicate(timeout=5)[0]
        except subprocess.TimeoutExpired:
            proc.kill()
            out = proc.communicate()[0] + " (killed)"
    else:
        out = proc.communicate()[0]
    fb.drain_fb()
    for _ in range(4):
        fb.read_auth(timeout=250)
    time.sleep(0.8)
    res = out.strip().splitlines()[-1][:70] if out.strip() else "?"
    return case_name, ("PASSED-TOOL-LANE" if passed else "denied"), res

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "boundary"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    fb = FB()
    fb.handshake()
    time.sleep(0.3)
    # consume handshake reply
    fb.read_auth(timeout=800)

    cases = []
    if mode == "boundary":
        # length-field boundaries and small item mutations (region A echo + tiny sig)
        for la, lb in [(0,0),(1,0),(0,1),(3,0),(4,0),(4,1),(5,1),(511,1),(512,0),(0xFFFF,1),(0xFFFE,1),(0xFF00,0xFF),(258,258)]:
            cases.append((f"lenA={la} lenB={lb}", None, b"\x00"*min(lb,8)))
    elif mode == "rs":
        # DER signature sweeps with echo items: SEQUENCE{INTEGER r, INTEGER s}
        def der(rbytes, sbytes):
            r = b"\x02" + bytes([len(rbytes)]) + rbytes
            s = b"\x02" + bytes([len(sbytes)]) + sbytes
            body = r + s
            return b"\x30\x81" + bytes([len(body)]) + body
        for sl, sll in [(1,1),(2,2),(32,32),(65,65),(66,66),(67,67),(68,68),(66,68),(68,66),(136,68),(0,0)]:
            rb = b"\x00"*sl if sl else b""
            sb = b"\x00"*sll if sll else b""
            cases.append((f"rs={sl},{sll} zeros", None, der(rb, sb)))
        # all-FF and small-value signatures
        cases.append(("rs=66,66 FF", None, der(b"\xff"*66, b"\xff"*66)))
        cases.append(("rs=1,1 val1", None, der(b"\x01", b"\x01")))
    elif mode == "items":
        # mutate the item stream: bad type/length varints
        for ty, ln in [(1,4),(2,16),(3,4),(4,18),(0,4),(255,4),(0x1000a,4)]:
            cases.append((f"item ty={ty} len={ln}", [(ty, b"\x00"*min(ln,32))], b"\x00"*8))
    else:
        raise SystemExit("unknown mode")

    for name, items, sig in cases[:count]:
        n, verdict, res = run_case(fb, name, items, sig)
        print(f"[{verdict:16s}] {n:24s} fastboot={res}", flush=True)

if __name__ == "__main__":
    main()
