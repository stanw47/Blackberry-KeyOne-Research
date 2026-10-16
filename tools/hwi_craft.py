#!/usr/bin/env python3
"""Craft the KeyOne HWI/BSI boot0 store (offset 0x4400, 4096 B) with
bbss_insecure=true. Format+checksum per notes/67:
  FNV-1a: h=0x811C9DC5; per line: hash name bytes then value bytes:
  h = ((h*0x01000193)&0xffffffff) ^ byte. Final line: chksum = <h>.
Keys/values = the live ro.boot.binfo.* props (note 67: values identical to
the real store), bbss_insecure flipped to true."""
import struct

props = [
    ("bbss_insecure", "true"),
    ("bbss_wp_type", "permanent"),
    ("bsis_type", "bsis_lite"),
    ("builtby", "JDM"),
    ("dtsid", "0xf24098b1"),
    ("hwid", "0xf24098b1"),
    ("model", "BBB100-3"),
    ("model_num", "BBB100-3"),
    ("name", "bbb100usasprint"),
    ("oem_tag", "sprint"),
    ("pcb_name", "PCB-61876-001-1"),
    ("pcb_rev", "9"),
    ("pop_name", "POP-63135-001-1"),
    ("pop_rev", "1"),
    ("primary_bc_ver", "ABL766"),
    ("backup_bc_ver", "AAK171"),
    ("processor_id", "000100004C000000A6F528E800000000000000000000000000000000000000000000000000000000"),
    ("product", "bbb100"),
    ("rev", "0x00090100"),
    ("simcount", "1"),
]

def fnv1a(lines):
    h = 0x811C9DC5
    for name, val in lines:
        for b in name.encode():
            h = ((h * 0x01000193) & 0xffffffff) ^ b
        for b in val.encode():
            h = ((h * 0x01000193) & 0xffffffff) ^ b
    return h

chk = fnv1a(props)
lines = [f"{k} = {v}" for k, v in props] + [f"chksum = 0x{chk:08x}"]
text = "\n".join(lines) + "\n"
store = text.encode() + b"\x00" * (4096 - len(text))

# verify: re-parse our own store like the aboot would
body = store[:4096]
txt = body.split(b"\x00", 1)[0].decode()
parsed = []
for ln in txt.splitlines():
    if not ln.strip():
        continue
    k, _, v = ln.partition("=")
    parsed.append((k.strip(), v.strip()))
data = [(k, v) for k, v in parsed if k != "chksum"]
want = fnv1a(data)
got = int([v for k, v in parsed if k == "chksum"][0], 0)
print(f"lines={len(data)} chksum=0x{want:08x} stored=0x{got:08x} match={want==got}")
print(f"store bytes={len(store)} text={len(text)} insecure={dict(data).get('bbss_insecure')}")
open("/tmp/opencode/hwi_store.bin", "wb").write(store)
open("/tmp/opencode/hwi_store.txt", "w").write(text)
print("wrote /tmp/opencode/hwi_store.bin (4096 B) + .txt")
print("--- store text ---")
print(text)
