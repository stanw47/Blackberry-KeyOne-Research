import sys, time, struct
import usb.core, usb.util
import usb.backend.libusb1

backend = usb.backend.libusb1.get_backend(find_library=lambda x: r"C:\bb10mt\libusb-1.0.dll")
dev = usb.core.find(idVendor=0x0fca, idProduct=0x8030, backend=backend)
if dev is None:
    print("no device"); sys.exit(1)
print("found", hex(dev.idVendor), hex(dev.idProduct))

dev.set_configuration()
try:
    dev.detach_kernel_driver(1)
except Exception:
    pass

def txrx(pkt, label, tout=2500):
    data = bytes(pkt)
    try:
        dev.write(0x02, data, timeout=1000)
    except Exception as e:
        print(f"{label}: write err {e}")
        return
    time.sleep(0.15)
    try:
        r = dev.read(0x82, 1024, timeout=tout)
        print(f"{label}: RESP {len(r)} bytes: {r[:64].hex()}")
        return r
    except usb.core.USBError as e:
        print(f"{label}: read {e}")
        return None

# candidate 1: OPEN_REQUEST with name, layout guess {op u8, chan u8, ?, param u8, len u16, cmd u16, payload}
# version 4, cmd 1 (OPEN), channel name "NVSIG-venicena"
name = b"NVSIG-venicena"
for op in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]:
    hdr = bytes([op, 0, 0, 0]) + struct.pack("<H", 6 + 2 + len(name)) + struct.pack("<H", 1) + struct.pack("<H", 4) + name
    txrx(hdr, f"OPEN op={op}")

# candidate 2: with version field before name, len = 6 + payload
for op in [0, 3, 9, 1, 2]:
    hdr = bytes([op, 0, 0, 0]) + struct.pack("<H", 6 + len(name) + 2) + struct.pack("<H", 1) + struct.pack("<H", 4) + name
    txrx(hdr, f"OPEN2 op={op}")

# candidate 3: bare version handshake (op with just version)
for op in [0, 1, 3]:
    hdr = bytes([op, 0, 0, 0]) + struct.pack("<H", 6 + 2) + struct.pack("<H", 1) + struct.pack("<H", 4)
    txrx(hdr, f"OPEN3 op={op}")
