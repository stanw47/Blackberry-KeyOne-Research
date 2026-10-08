#!/usr/bin/env python3
"""
Function-level binary diff for BlackBerry Qualcomm LK aboot images
(emmc_appsboot.mbn, ARM32, loaded at 0x8f600000 from file offset 0x8000).

Heuristic:
  1. Linear-sweep the code region with capstone.
  2. Function starts = all branch targets (b/bl) + image base, sorted.
  3. Fingerprint each function from its disassembly with operands normalized
     (immediates -> I, branch targets -> T, all else kept): catches functions
     that are byte-identical modulo relocation/addresses.
  4. Match fingerprints across two builds; report:
       - identical functions
       - functions only in A / only in B
       - for unmatched, the strings referenced (movw/movt -> VA in string table)

Usage:
    py -3.11 lk_bindiff.py <a.mbn> <b.mbn> [--top 40] [--json out.json]
"""
import argparse
import hashlib
import json
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

LOAD_OFF = 0x8000
LOAD_VADDR = 0x8F600000


def load(path):
    with open(path, "rb") as f:
        d = f.read()
    return d


def va2off(va):
    return LOAD_OFF + (va - LOAD_VADDR)


def strings_table(data):
    tbl = {}
    for m in re.finditer(rb"[ -~]{4,}", data):
        off = m.start()
        if off < LOAD_OFF:
            continue
        tbl[LOAD_VADDR + (off - LOAD_OFF)] = m.group().decode()
    return tbl


def code_region(data):
    return data[LOAD_OFF:]


def discover_functions(data):
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = False
    starts = {LOAD_VADDR}
    for insn in md.disasm(code_region(data), LOAD_VADDR):
        if insn.mnemonic in ("b", "bl", "bx", "blx"):
            m = re.match(r"^#?\s*(0x[0-9a-fA-F]+)\s*$", insn.op_str.strip())
            if m:
                t = int(m.group(1), 0)
                if LOAD_VADDR <= t < LOAD_VADDR + len(code_region(data)):
                    starts.add(t)
    ordered = sorted(starts)
    ranges = []
    for i, s in enumerate(ordered):
        e = ordered[i + 1] if i + 1 < len(ordered) else LOAD_VADDR + len(code_region(data))
        if e - s >= 8 and e - s <= 0x8000:  # skip absurd ranges
            ranges.append((s, e))
    return ranges


def fingerprint(data, start, end, strings):
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = False
    chunk = data[va2off(start):va2off(end)]
    toks = []
    refs = []
    movw = {}
    for insn in md.disasm(chunk, start):
        op = insn.op_str
        # track movw/movt pairs for string references
        if insn.mnemonic == "movw":
            m = re.match(r"(\w+), #(0x[0-9a-fA-F]+)", op)
            if m:
                movw[m.group(1)] = int(m.group(2), 0)
        elif insn.mnemonic == "movt":
            m = re.match(r"(\w+), #(0x[0-9a-fA-F]+)", op)
            if m and m.group(1) in movw:
                v = movw.pop(m.group(1)) | (int(m.group(2), 0) << 16)
                if v in strings:
                    refs.append(strings[v])
        # normalize immediate/branch operands
        norm = re.sub(r"#-?0x[0-9a-fA-F]+", "#I", op)
        toks.append(f"{insn.mnemonic} {norm}")
    fp = hashlib.md5("\n".join(toks).encode()).hexdigest()
    return fp, toks, refs


def build(path):
    data = load(path)
    strings = strings_table(data)
    ranges = discover_functions(data)
    funcs = {}
    for s, e in ranges:
        fp, toks, refs = fingerprint(data, s, e, strings)
        funcs[fp] = {
            "start": s,
            "end": e,
            "size": e - s,
            "insns": len(toks),
            "refs": refs[:4],
            "head": toks[:6],
        }
    return data, strings, funcs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--json")
    args = ap.parse_args()

    da, sa, fa = build(args.a)
    db, sb, fb = build(args.b)
    print(f"[*] A: {len(fa)} functions   B: {len(fb)} functions")

    common = set(fa) & set(fb)
    only_a = set(fa) - set(fb)
    only_b = set(fb) - set(fa)
    print(f"[*] identical (fingerprint match): {len(common)}")
    print(f"[*] only in A: {len(only_a)}   only in B: {len(only_b)}")

    def rows(keys, funcs):
        out = []
        for k in keys:
            f = funcs[k]
            out.append((f["size"], f["start"], f["refs"], f["head"]))
        return sorted(out, reverse=True)

    print(f"\n=== top {args.top} functions only in A (={args.a}) ===")
    for size, start, refs, head in rows(only_a, fa)[: args.top]:
        print(f"  0x{start:08x} size={size:5d} refs={refs}")
    print(f"\n=== top {args.top} functions only in B (={args.b}) ===")
    for size, start, refs, head in rows(only_b, fb)[: args.top]:
        print(f"  0x{start:08x} size={size:5d} refs={refs}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {
                    "a": {"path": args.a, "funcs": fa},
                    "b": {"path": args.b, "funcs": fb},
                    "summary": {
                        "identical": len(common),
                        "only_a": len(only_a),
                        "only_b": len(only_b),
                    },
                },
                f,
                indent=1,
            )
        print(f"\n[*] wrote {args.json}")


if __name__ == "__main__":
    sys.exit(main())
