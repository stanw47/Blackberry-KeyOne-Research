"""auth_winusb.py - raw WinUSB access to the KEYone auth interface (8040&MI_01)."""
import ctypes, ctypes.wintypes as w, sys, time, struct

ADB_GUID = "{F72FE0D4-CBCB-407D-8814-9ED673D0DD6B}"

setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
winusb = ctypes.WinDLL("winusb", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# SetupDi
setupapi.SetupDiGetClassDevsW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.HANDLE, w.DWORD]
setupapi.SetupDiGetClassDevsW.restype = w.HANDLE
setupapi.SetupDiEnumDeviceInterfaces.argtypes = [w.HANDLE, w.LPVOID, w.LPCWSTR, w.DWORD, w.LPVOID]
setupapi.SetupDiEnumDeviceInterfaces.restype = w.BOOL
setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [w.HANDLE, w.LPVOID, w.LPVOID, w.DWORD, w.LPDWORD, w.LPVOID]
setupapi.SetupDiGetDeviceInterfaceDetailW.restype = w.BOOL
setupapi.SetupDiDestroyDeviceInfoList.argtypes = [w.HANDLE]

# WinUsb
winusb.WinUsb_Initialize.argtypes = [w.HANDLE, ctypes.POINTER(w.HANDLE)]
winusb.WinUsb_Initialize.restype = w.BOOL
winusb.WinUsb_ReadPipe.argtypes = [w.HANDLE, w.BYTE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]
winusb.WinUsb_ReadPipe.restype = w.BOOL
winusb.WinUsb_WritePipe.argtypes = [w.HANDLE, w.BYTE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]
winusb.WinUsb_WritePipe.restype = w.BOOL
winusb.WinUsb_Free.argtypes = [w.HANDLE]

kernel32.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
kernel32.CreateFileW.restype = w.HANDLE
kernel32.CloseHandle.argtypes = [w.HANDLE]

GENERIC_RW = 0xC0000000
FILE_SHARE_RW = 3
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000

class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [("cbSize", w.DWORD), ("InterfaceClassGuid", ctypes.c_byte*16),
                ("Flags", w.DWORD), ("Reserved", w.LPVOID)]

class SP_DEVICE_INTERFACE_DETAIL_DATA(ctypes.Structure):
    _fields_ = [("cbSize", w.DWORD), ("DevicePath", ctypes.c_wchar*1)]

cfgmgr32 = ctypes.WinDLL("cfgmgr32", use_last_error=True)
cfgmgr32.CM_Get_Device_Interface_List_SizeW.argtypes = [ctypes.POINTER(w.ULONG), w.LPCWSTR, w.LPCWSTR, w.DWORD]
cfgmgr32.CM_Get_Device_Interface_ListW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPWSTR, w.ULONG, w.DWORD]

def find_paths(devinst):
    size = w.ULONG()
    r = cfgmgr32.CM_Get_Device_Interface_List_SizeW(ctypes.byref(size), devinst, None, 0)
    if r != 0 or size.value == 0:
        return []
    buf = ctypes.create_unicode_buffer(size.value)
    r = cfgmgr32.CM_Get_Device_Interface_ListW(devinst, None, buf, size.value, 0)
    if r != 0:
        return []
    return [p for p in buf.value.split(chr(0)) if p]

def main():
    paths = [
        "\\\\?\\USB#VID_0FCA&PID_8040&MI_01#7&17999439&0&0001#{5B675820-E67C-4D5A-9FF6-8E2E397BEAE7}",
        "\\\\?\\USB#VID_0FCA&PID_8040&MI_01#7&342FC168&0&0001#{5B675820-E67C-4D5A-9FF6-8E2E397BEAE7}",
    ]
    for p in paths:
        print("[*] path:", p)
    h = w.HANDLE(-1).value
    for p in paths:
        print("[*] trying:", p)
        h = kernel32.CreateFileW(p, GENERIC_RW, FILE_SHARE_RW, None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None)
        if h != w.HANDLE(-1).value:
            print("[*] opened:", p)
            break
        print("[!] CreateFile failed err", ctypes.get_last_error())
    if h == w.HANDLE(-1).value:
        return 3
    win = w.HANDLE()
    if not winusb.WinUsb_Initialize(h, ctypes.byref(win)):
        print("[!] WinUsb_Initialize failed err", ctypes.get_last_error()); return 4
    print("[*] WinUsb open OK")

    COOKIE = 0xbba78701
    hs = struct.pack("<II", COOKIE, 0x2000) + struct.pack("<I", 0x00010003) + b"Linux" + struct.pack("<I", 0x78) + b"\x00"*8
    n = w.DWORD()
    winusb.WinUsb_WritePipe(win, 0x02, hs, len(hs), ctypes.byref(n), None)
    print(f"[*] handshake sent {n.value} bytes")
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 90
    t0 = time.time()
    answered = 0
    while time.time() - t0 < seconds:
        buf = (ctypes.c_ubyte * 4096)()
        n = w.DWORD()
        if not winusb.WinUsb_ReadPipe(win, 0x82, buf, 4096, ctypes.byref(n), None):
            err = ctypes.get_last_error()
            if err in (121,):  # semaphore timeout
                continue
            print("[!] ReadPipe err", err)
            break
        b = bytes(buf[:n.value])
        if len(b) < 8:
            print(f"[?] short {len(b)} {b.hex()}")
            continue
        cookie, code = struct.unpack("<II", b[:8])
        print(f"[<] code={code:#06x} len={len(b)} payload={b[8:48].hex()}")
        if code == 0x1012:
            rep = struct.pack("<II", COOKIE, 0x1013) + struct.pack("<I", 1) + b[8:8+0x1f] + b"\x00"*8
            winusb.WinUsb_WritePipe(win, 0x02, rep, len(rep), ctypes.byref(n), None)
            print(f"[>] 0x1013 result=1")
            answered += 1
        elif code == 0x1014:
            rep = struct.pack("<II", COOKIE, 0x1015) + struct.pack("<I", 1) + b[8:8+0x20]
            winusb.WinUsb_WritePipe(win, 0x02, rep, len(rep), ctypes.byref(n), None)
            print(f"[>] 0x1015 answer=1")
            answered += 1
    print(f"[*] done, answered {answered}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
