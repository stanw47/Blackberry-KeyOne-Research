#!/usr/bin/env python3
"""fb_case.py - run ONE crafted 0x2005 case (fresh process => clean USB state).
Usage: fb_case.py <case_index>
"""
import sys, time, struct, subprocess
import usb.core, usb.util

COOKIE = 0xbba78701
FB_BIN = "/home/stanw47/Documents/Blackberry-KeyOne-Research/recon/2026-10-02/autoloader/ABL766 - Hn03/host/linux-x86/bin/fastboot"
SERIAL = "1164118297"

def varint(v):
    out = b""
    while True:
        b = v & 0x7f; v >>= 7
        if v: out += bytes([b | 0x80])
        else: return out + bytes([b])

def parse_items(buf):
    items = []; i = 0
    while i < len(buf):
        ln = 0; shift = 0; ok = False; i2 = i
        while i2 < len(buf) and shift < 35:
            c = buf[i2]; i2 += 1; ln |= (c & 0x7f) << shift
            if not (c & 0x80): ok = True; break
            shift += 7
        if not ok or i2 >= len(buf): break
        ty = 0; shift = 0; ok = False; i3 = i2
        while i3 < len(buf) and shift < 35:
            c = buf[i3]; i3 += 1; ty |= (c & 0x7f) << shift
            if not (c & 0x80): ok = True; break
            shift += 7
        if not ok or i3 + ln > len(buf): break
        items.append((ty, buf[i3:i3+ln]))
        i = i3 + ln
    return items

def enc_item(ty, val):
    return varint(len(val)) + varint(ty) + val

def der(rb, sb):
    r = b"\x02" + bytes([len(rb)]) + rb
    s = b"\x02" + bytes([len(sb)]) + sb
    body = r + s
    return b"\x30\x81" + bytes([len(body)]) + body

def get_case(idx):
    # returns (name, items_override or None, sigblob, len_override or None)
    cases = [
        ("baseline-echo-emptysig", None, b"", None),
        ("echo-sig-zero8", None, b"\x00" * 8, None),
        ("echo-sig-der-1-1", None, der(b"\x01", b"\x01"), None),
        ("echo-sig-der-66-66-zero", None, der(b"\x00" * 66, b"\x00" * 66), None),
        ("echo-sig-der-66-66-ff", None, der(b"\xff" * 66, b"\xff" * 66), None),
        ("echo-sig-der-67-67", None, der(b"\x00" * 67, b"\x00" * 67), None),
        ("echo-sig-der-136-68", None, der(b"\x00" * 136, b"\x00" * 68), None),
        ("echo-sig-der-137-68", None, der(b"\x00" * 137, b"\x00" * 68), None),
        ("echo-sig-siglen300", None, der(b"\x00" * 66, b"\x00" * 66) + b"\x00" * 100, None),
        ("items-empty", [], b"", None),
        ("items-badtype", [(0x1000a, b"\x00" * 4)], b"", None),
        ("items-overflow-len", [(1, b"\x00" * 4)], b"", (0xFFFF, 1)),
    ]
    return cases[idx % len(cases)]

def main():
    idx = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    name, items_override, sigblob, len_override = get_case(idx)
    d = usb.core.find(idVendor=0x0FCA, idProduct=0x8040)
    if d is None:
        print(f"[{name}] no device"); return 2
    for i in (0, 1):
        try:
            if d.is_kernel_driver_active(i): d.detach_kernel_driver(i)
        except Exception: pass
    usb.util.claim_interface(d, 1)
    hs = struct.pack("<II", COOKIE, 0x2000) + struct.pack("<I", 0x00010003) + b"Linux" + struct.pack("<I", 0x78) + b"\x00" * 8
    d.write(0x02, hs, timeout=2000)
    time.sleep(0.3)
    try: d.read(0x82, 4096, timeout=800)
    except Exception: pass
    proc = subprocess.Popen([FB_BIN, "-s", SERIAL, "oem", "getvarp:bsn"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    chal = None; t0 = time.time()
    while time.time() - t0 < 6:
        try:
            b = d.read(0x82, 4096, timeout=250).tobytes()
        except usb.core.USBTimeoutError:
            if proc.poll() is not None: break
            continue
        except Exception as e:
            print(f"[{name}] read err {e}"); break
        if len(b) >= 8 and struct.unpack("<I", b[4:8])[0] == 0x2004:
            chal = b; break
    if chal is None:
        proc.kill(); out = proc.communicate()[0]
        print(f"[{name}] no-challenge: {out.strip()[-60:]}")
        return 0
    items = parse_items(chal[12:520])
    echo = [(ty, val) for ty, val in items if ty in (1, 2, 3, 4)]
    region_items = echo if items_override is None else items_override
    region_a = b"".join(enc_item(ty, val) for ty, val in region_items)
    la, lb = len(region_a), len(sigblob)
    if len_override:
        la, lb = len_override
    body = struct.pack("<HH", la & 0xFFFF, lb & 0xFFFF) + region_a + sigblob
    resp = struct.pack("<II", COOKIE, 0x2005) + struct.pack("<I", 0) + body
    try:
        d.write(0x02, resp, timeout=2000)
    except Exception as e:
        print(f"[{name}] send err {e}")
    passed = False
    t0 = time.time()
    while time.time() - t0 < 4:
        try:
            b = d.read(0x82, 4096, timeout=250).tobytes()
            if len(b) >= 8:
                code = struct.unpack("<I", b[4:8])[0]
                if code == 0x1010:
                    passed = True
                    d.write(0x02, struct.pack("<III", COOKIE, 0x1011, 1), timeout=2000)
                elif code == 0x1012:
                    d.write(0x02, struct.pack("<III", COOKIE, 0x1013, 0), timeout=2000)
                elif code == 0x1014:
                    d.write(0x02, struct.pack("<IIII", COOKIE, 0x1015, 0, 1), timeout=2000)
        except usb.core.USBTimeoutError:
            if proc.poll() is not None: break
            continue
        except Exception: break
    if proc.poll() is None:
        body = struct.pack("<IHH", 0, 256, 256) + b"\x00" * 512
        try: d.write(0x02, struct.pack("<II", COOKIE, 0x2005) + body, timeout=2000)
        except Exception: pass
        try: out = proc.communicate(timeout=5)[0]
        except subprocess.TimeoutExpired:
            proc.kill(); out = proc.communicate()[0] + " (killed)"
    else:
        out = proc.communicate()[0]
    verdict = "PASSED-TOOL-LANE" if passed else "denied"
    last = out.strip().splitlines()[-1][:60] if out.strip() else "?"
    print(f"[{verdict:16s}] {name:28s} {last}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
