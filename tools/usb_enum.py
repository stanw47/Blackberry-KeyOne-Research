import usb.core
import usb.util
import usb.backend.libusb1

backend = usb.backend.libusb1.get_backend(find_library=lambda x: r"C:\bb10mt\libusb-1.0.dll")
devs = list(usb.core.find(find_all=True, backend=backend))
for d in devs:
    try:
        print(f"{d.idVendor:04x}:{d.idProduct:04x} bus={d.bus} addr={d.address} man={d.manufacturer} prod={d.product}")
        for cfg in d:
            for itf in cfg:
                print(f"   intf {itf.bInterfaceNumber} class={itf.bInterfaceClass:02x} sub={itf.bInterfaceSubClass:02x} proto={itf.bInterfaceProtocol:02x}")
                for ep in itf:
                    print(f"      ep {ep.bEndpointAddress:#04x} attr={ep.bmAttributes:#04x} maxpkt={ep.wMaxPacketSize}")
    except Exception as e:
        print(f"{d.idVendor:04x}:{d.idProduct:04x} err {e}")
