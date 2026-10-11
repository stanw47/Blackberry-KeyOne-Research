import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"C:\Users\Stanley Williamson\AppData\Local\Temp\opencode\priv-aaw068\emmc_appsboot.mbn"
data = open(BIN, "rb").read()
LOAD_OFF = 0x8000
LOAD_VADDR = 0xF900000
FILE_BASE = LOAD_VADDR - LOAD_OFF
CODE_END_VA = LOAD_VADDR + 0x1634BC

def va2off(va):
    return va - FILE_BASE

# find string addresses by content
def find_str(s):
    off = data.find(s)
    return off + FILE_BASE if off >= 0 else None

strs = {
    "challenge-fit": b"Cannot fit challlenge in supplied buffer.",
    "pin-len": b"Could not read pin, length = %d\n",
    "bsn-len": b"Could not read BSN, length = %d\n",
    "rtas-init": b"rtas_init_tool_authorization",
    "sendNextPacket": b"sendNextPacket",
    "authboot-ch": b"authboot channel not opened",
    "rtas-auth-fail": b"rtas_cmd_authorization_check failed",
    "authboot-part": b"AUTHBOOT",
    "nv-sig": b"NVSIG-venice",
    "session-fail": b"Failed to start session",
    "enc-blob": b"Failed to encrypt the blob",
    "enc-blob2": b"Failed to encrypt blob",
}
targets = {}
for k, s in strs.items():
    offs = []
    i = 0
    while True:
        i = data.find(s, i)
        if i < 0:
            break
        offs.append(i + FILE_BASE)
        i += 1
    targets[k] = offs
    print(k, [hex(o) for o in offs])

TARGET_SET = set()
for offs in targets.values():
    TARGET_SET.update(offs)

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
print()
print("=== movw/movt refs (chunked) ===")
found = []
va = LOAD_VADDR
while va < CODE_END_VA:
    chunk = data[va2off(va):va2off(va) + 0x1000]
    pend = {}
    for ins in md.disasm(chunk, va):
        if ins.mnemonic == "movw":
            p = ins.op_str.split(", #")
            if len(p) == 2:
                try: pend[p[0].strip()] = (ins.address, int(p[1], 16))
                except Exception: pass
        elif ins.mnemonic == "movt":
            p = ins.op_str.split(", #")
            if len(p) == 2 and p[0].strip() in pend:
                a, lo = pend.pop(p[0].strip())
                try: full = (int(p[1], 16) << 16) | lo
                except Exception: continue
                if full in TARGET_SET:
                    found.append((a, full))
    va += 0x1000

name_of = {}
for k, offs in targets.items():
    for o in offs:
        name_of[o] = k

for a, full in found:
    print(f"  {a:#010x} -> {name_of[full]} ({full:#x})")
