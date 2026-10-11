#!/usr/bin/env python3
"""callers.py - list call sites (bl/b) of given functions in ABL766."""
import sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

BIN = r"firmware\keyone-abl766\ABL766 - Hn03\target\product\bbry_qc8953\emmc_appsboot.mbn"
LOAD_OFF = 0x8000
LOAD_VADDR = 0x8F600000

TARGETS = {
    0x8F6742FC: "set_pending_wipe",
    0x8F673D58: "wipe_device",
    0x8F67416C: "process_pending_wipe",
    0x8F673F2C: "execute_wipe",
    0x8F62C484: "set_device_unlock",
    0x8F62C06C: "write_device_info",
    0x8F64B104: "set_bootmode",
    0x8F633120: "cmd_oem_set_factory_mode",
}

def va2off(va):
    return va - LOAD_VADDR + LOAD_OFF

def main():
    data = open(BIN, "rb").read()
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    code = data[va2off(0x8F600000):va2off(0x8F700000)]
    for ins in md.disasm(code, 0x8F600000):
        if ins.mnemonic in ("bl", "b") and ins.op_str.startswith("#0x"):
            t = int(ins.op_str[1:], 16)
            if t in TARGETS:
                print(f"{ins.address:#010x} -> {TARGETS[t]} ({t:#010x})")

if __name__ == "__main__":
    main()
