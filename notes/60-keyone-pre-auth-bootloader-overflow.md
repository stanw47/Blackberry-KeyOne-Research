# notes/60 — PRE-AUTH BOOTLOADER STACK OVERFLOW in ABL766 (nv_sig path)

Date: 2026-10-11. Device: KEYone BBB100-3 ABL766, bootloader mode.
Status: **vulnerability PROVEN LIVE (canary control confirmed). Exploit next.**

## Summary

A controllable, pre-auth stack buffer overflow exists in the KEYone's
bootloader (LK/ABL766), reachable from a plain PC over the **auth USB
interface** (no password, no credentials), via the RTAS NV-signature
verification path. The stack canary is a **fixed, known constant** (0x54), so
the overflow can preserve it and control the saved return address.

## Reachability chain (all reversed and driven live)

1. `0x2000` handshake on the auth interface (0FCA:8040 intf 1, ep 0x02/0x82)
   -> device replies `0x2001` (548 B info dump).
2. `0x1016` message -> `0x8f63a684` sets `[ctx+0x75c]=1`, builds and sends the
   **NV-sign challenge** (`0x2004`, 524 B, payload starts `NVSIG-bbb100usa`).
3. `0x2005` message -> `process_rtas_chal_response` (0x8f63a450; no session
   needed on this arm) -> `rtas_verify_nv_sig_response` (0x8f659e24)
   -> `0x8f658f30` (the vulnerable parser).

## The bug (0x8f658f30, rtas nv_sig signature parse)

Record layout (all host-controlled, only bounded by the <=0x200 message cap):
- message: `[len_a u16][len_b u16][data_a len_a][data_b len_b]` at msg+0xc.
- `data_a` must contain TLV records `[len varint][type varint][data]` with
  types 5 and 6 (`00 05 00 06`).
- `data_b` is parsed as an ASN.1-ish signature blob:
  `30 81 <len_b-3> 02 <sl> <sl bytes> 02 <r4len> <r4len bytes>`.

Bug: `memcpy(dst=sp+0x4c, src=blob+5, len=sl)` with `sl = blob[4]` **never
checked against the destination size** (real capacity ~0x44 bytes; the region
up to the canary at sp+0xd4 is 0x88). The buffer is then byte-reversed in
place, so after reversal the canary slot (buffer+0x88 = sp+0xd4) holds
`data[0]`.

Stack layout: buffer1 sp+0x4c..0x8f, buffer2 sp+0x90..0xd3, canary sp+0xd4,
saved r4..fp sp+0xdc..0xf4, saved PC (LR) sp+0xf8.

## The canary is FIXED

`__stack_chk_guard` global = `0x8f7c2ed0`. The image value is `0x00000054`
and **no code writes it** (1006 refs, all loads; the single apparent store is
a false positive). So the runtime canary is `0x00000054`.

## Live proof

- Negative control: `sl=0x89`, `data[0]=0x00` -> overflow writes the canary
  -> canary check fails -> **bootloader crash/reset** (device reappeared in
  fastboot with `????????????` serial). Overflow execution CONFIRMED.
- Positive control: `sl=0x89`, `data[0]=0x54` -> canary preserved -> no crash.
- Device survived multiple probes; a full physical reset recovers the wedged
  USB state after the crash (same as prior bootloader crash states).

## Tools

- `tools/auth_flow.py`, `tools/auth_seq.py` — auth protocol drivers.
- `tools/auth_canary.py` — the canary probes (`probe89` / `probe89b`).

## Next (exploit)

1. Determine the LK stack address (entry `sp` setup / linker layout) to point
   the saved PC at stack-resident shellcode (ARM32, no ASLR).
2. Overflow layout: preserve canary (data[0]=0x54 via reversal), control saved
   PC at buffer+0xAC (=sp+0xf8), place shellcode in the overflow bytes.
3. Payload goal (in order of preference):
   a. call `switch_bootmode(1,0)` / write the RPMB bootmode record -> FACTORY
      mode (the KEY2 win condition) - **careful: factory transition triggers
      the wipe path (BbryWipeLib); the KEY2 unlock had to defuse it. Must
      handle the wipe first or pick a non-wipe route.**
   b. patch the authboot command check / unlock gate in RAM.
4. NO SECURITY WIPE: any factory-mode route must first defuse the wipe path
   (the KEY2's `defuse_wipelib` equivalent) or avoid it entirely.
