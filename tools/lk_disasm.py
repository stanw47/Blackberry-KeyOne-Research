#!/usr/bin/env python3
"""
Disassemble ABL766 emmc_appsboot.mbn (LK, ARM32) regions with annotations.

The MBN wraps an ELF whose first LOAD segment maps file offset 0x8000 to
VA 0x8F600000. String literal pools are annotated, plus known symbols/globals
from notes/aboot-re-authboot.md and notes/aboot-re-devinfo.md.

Usage:
    py -3.11 lk_disasm.py <emmc_appsboot.mbn> <start_va> <end_va>
    py -3.11 lk_disasm.py <emmc_appsboot.mbn> <start_va> +<length>
"""
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

LOAD_OFF = 0x8000
LOAD_VADDR = 0x8F600000

SYMBOLS = {
    0x8F62C06C: "write_device_info",
    0x8F62C484: "set_device_unlock",
    0x8F62C55C: "cmd_oem_unlock",
    0x8F62C65C: "cmd_oem_unlock_go",
    0x8F637C4C: "get_perm_item",
    0x8F637D04: "rtas2_cmd_authorization_check",
    0x8F637E0C: "authboot_check_permission",
    0x8F638168: "authboot_check_command_permission",
    0x8F6386E8: "auth_rtas_has_permission",
    0x8F639BA0: "bbauthtool_sock_client_send",
    0x8F6547FC: "bbss_wp_type_parse",
    0x8F655390: "wp_manager",
    0x8F60EB74: "wp_applier",
}

GLOBALS = {
    0x8F7944D0: "devinfo_present",
    0x8F7944D4: "devinfo_base",
    0x8F7944E4: "devinfo.is_unlocked",
    0x8F7944E8: "devinfo.is_unlock_critical",
    0x8F7944EC: "devinfo.is_tampered",
    0x8F7944F0: "devinfo.charger_screen_enabled",
}


def va2off(va):
    return LOAD_OFF + (va - LOAD_VADDR)


def off2va(off):
    return LOAD_VADDR + (off - LOAD_OFF)


def build_strings(data):
    tbl = {}
    for m in re.finditer(rb"[ -~]{4,}", data):
        off = m.start()
        if off < LOAD_OFF:
            continue
        tbl[off2va(off)] = m.group().decode()
    return tbl


def pool_annotation(data, strings, addr):
    off = va2off(addr)
    if off < 0 or off + 4 > len(data):
        return None
    word = struct.unpack_from("<I", data, off)[0]
    if word in strings:
        return f'"{strings[word]}"'
    if word in GLOBALS:
        return GLOBALS[word]
    if word in SYMBOLS:
        return SYMBOLS[word]
    return None


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 1
    path = sys.argv[1]
    start = int(sys.argv[2], 0)
    end = int(sys.argv[3], 0)
    if sys.argv[3].startswith("+"):
        end = start + int(sys.argv[3][1:], 0)

    with open(path, "rb") as f:
        data = f.read()
    strings = build_strings(data)

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = False
    code = data[va2off(start): va2off(end)]
    for insn in md.disasm(code, start):
        ann = ""
        m = re.search(r"\[pc, #(-?0x[0-9a-f]+)\]", insn.op_str)
        if m:
            imm = int(m.group(1), 0)
            ann = pool_annotation(data, strings, insn.address + 8 + imm) or ""
        if ann == "" and insn.mnemonic in ("bl", "b", "bx", "blx"):
            try:
                tgt = int(insn.op_str, 0)
            except ValueError:
                tgt = None
            if tgt in SYMBOLS:
                ann = SYMBOLS[tgt]
        line = f"0x{insn.address:08x}  {insn.mnemonic:<7} {insn.op_str}"
        if ann:
            line = f"{line:<52}  ; {ann}"
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
