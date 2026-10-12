#!/usr/bin/env python3
import sys, re
sys.path.insert(0, '/tmp/opencode')
from fb2 import FB

fb = FB()
vars_ = ["hlos_unsigned.tkn", "hlos_signature.tkn", "hlos_signature.tkn.subvariant",
         "is-password-set", "bootmode", "gpt_version", "version-bootloader", "product"]
for v in vars_:
    try:
        r = fb.cmd(f"getvar:{v}")
        val = r.replace(b"OKAY", b"").replace(b"INFO", b"").replace(b"FAIL", b"FAIL:")
        print(f"{v:32s} = {val[:80]!r}")
    except Exception as e:
        print(f"{v:32s} ERR {e}")
        break
