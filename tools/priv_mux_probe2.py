import sys, time, struct
import usb.core, usb.util
import usb.backend.libusb1

backend = usb.backend.libusb1.get_backend(find_library=lambda x: r"C:\bb10mt\libusb-1.0.dll")
dev = usb.core.find(idVendor=0x0fca, idProduct=0x8030, backend=backend)
print("dev:", dev)
if dev is None:
    sys.exit(1)

# dump all interfaces/endpoints with a raw config read
print("bNumConfigurations:", dev.bNumConfigurations)
cfg = dev.get_active_configuration()
print("cfg:", cfg)
for itf in cfg:
    print(" intf", itf.bInterfaceNumber, hex(itf.bInterfaceClass), hex(itf.bInterfaceSubClass), hex(itf.bInterfaceProtocol))
    for ep in itf:
        print("   ep", hex(ep.bEndpointAddress), ep.bmAttributes, ep.wMaxPacketSize)

# claim interface 1
try:
    usb.util.claim_interface(dev, 1)
    print("claimed intf 1 OK")
except Exception as e:
    print("claim intf1 err:", e)
try:
    usb.util.claim_interface(dev, 0)
    print("claimed intf 0 OK")
except Exception as e:
    print("claim intf0 err:", e)

def txrx(pkt, label, tout=2500):
    try:
        n = dev.write(0x02, bytes(pkt), timeout=1000)
        print(f"{label}: wrote {n}")
    except Exception as e:
        print(f"{label}: write err {e}")
        return
    time.sleep(0.15)
    try:
        r = dev.read(0x82, 1024, timeout=tout)
        print(f"{label}: RESP {len(r)}: {r[:64].hex()}")
        return r
    except usb.core.USBError as e:
        print(f"{label}: read {e}")

name = b"NVSIG-venicena"
for op in [0, 1, 3]:
    hdr = bytes([op, 0, 0, 0]) + struct.pack("<H", 6 + 2 + len(name)) + struct.pack("<H", 1) + struct.pack("<H", 4) + name
    txrx(hdr, f"OPEN op={op}")
