# notes/82 — KeyOne ECDSA verifier: full trace + the "very end" compare slot

Date: 2026-10-16. ABL766. Follows notes/60, 62, 63, 64.

## Why this lane

User's framing: the BB signature is unobtainable, so the only hope is a bug at the
VERY END of verification. Traced the whole chain; everything upstream is airtight;
the entire verdict hinges on ONE compare call.

## Chain

`sb_ecc521_verify_sign` (0x8f66d648)
 → `hu_ECDSANoHashVerify` (0x8f6c0914)
 → `husw_ECDSANoHashVerify` (0x8f694a30)  [dispatched via fn-ptr, table below]
 → curve methods via `blx [params+off]`.

Caller logic (success iff BOTH):
- hu_ returns 0, AND
- out-flag != 0 (flag zeroed at entry; ONLY the final compare sets it).

## Checks present (all good)

- magic/type (ctx 0x2001, params 0x2003), null args
- hash length == curve byte size (0xe307/0xe30a); r/s size bound (0xe103)
- `husw_memcmp` gate (0xf503) — range/order
- in-range method call (+0x4c must return 0)
- `osLSTruncate` (hash truncation to order bitlen)
- `husw_EcaMultiplyLinearX` (X of u1*G + u2*Q) — **0xff00 = infinity → reject** (present)
- mod-n reduce (+0x20, +0x5c), then final compare (+0x5c) → flag

## THE target

`[params+0x5c]` = the final `X mod n == r` compare. If it has a bug (length,
truncation, byte order, early-nonzero), a crafted (r,s) passes with no key.

## Provider tables located (data)

Crypto registration region **0x8f7a4dc8–0x8f7a5200** (.data), dense `husw_*` fn ptrs:
- 0x8f7a50f4: { husw_ECDSANoHashVerify, 0x8f693194, 0x8f69dfa0 }
- 0x8f7a4f94: { husw_ECDSANoHashSign,  0x8f69e64c, 0x8f6b14c8 }

Method struct = entry with ptrs at +0x18/+0x1c/+0x20/+0x24/+0x28/+0x30/+0x40/
+0x4c/+0x5c/+0x60. Slot +0x5c = compare → audit next.

## Curve setup path (found)

- `husw_ECCsecp521r1_2ParamsCreate` 0x8f693d70 → `sb_ECAsecp521r1_2ParamsCreate`
  0x8f6a69c4 → ff_fp521aParamsCreate 0x8f6a77d0 + ff_fp521r1OrderParamsCreate
  0x8f6a7984 → **`eca_fppm3CombParamsCreate` 0x8f6b0ae8** (builds the params
  object: husw_malloc + husw_EcaPointCreate 0x8f6a6778 + eca_pointSet 0x8f6b1354
  + comb table). The method pointers are installed here → tail of this function
  = where +0x5c gets its compare (eca_*/fp_* family).
- eca_* family seen: eca_pointSet, eca_ParamsDestroy, eca_combTableCreate/Destroy
  (0x8f6b5fd8/0x8f6b66b4), eca_linMultX 0x8f6b1034, husw_EcaPointCreate/Destroy
  0x8f6a6778/0x8f6a67e0.
- secp256r1 sibling: husw_ECCsecp256r1_2ParamsCreate 0x8f693ce8.
- Next: disasm tail of eca_fppm3CombParamsCreate → table install → +0x5c fn name
  → audit (length/byte-order/early-out).

## Update — method-slot hunt (state)

- eca_fppm3CombParamsCreate does NOT install method pointers (no str to +0x18..+0x60).
- The methods come from the GLOBAL CTX: husw_ECDSANoHashVerify does `ldr fp,[r0,#8]`
  (r0 = ctx) and calls fp+0x18..+0x60. So fp = the registered crypto-provider
  method struct; find where [ctx+8] is filled (provider registration at init).
- Two candidate data regions found:
  - 0x8f7ba0d0.. region: 16-byte entries {0, 0x20000, tag, fn} — fn in 4th dword
    (e.g. 0x8f6b0ae8 eca_fppm3CombParamsCreate, 0x8f6b0d84 eca_fppm3DoubleJacobian,
    0x8f6b1034 eca_linMultX). Looks like a registration/class table (tag field).
  - 0x8f7a4dc8..0x8f7a5200: dense husw_* fn pointers (provider API table;
    @0x8f7a5168 window: +0x40 = eca_linMultX, +0x4c = husw_ECCsecp256r1_2ParamsCreate).
- eca/fp method family (from table): eca_fppm3DoubleJacobian 0x8f6b0d84,
  eca_linMultX 0x8f6b1034, eca_pointSet 0x8f6b1354, ff_IsEqual17 0x8f6b1714,
  ff_IsEqual8 0x8f6b1740, ff_IsZero17 0x8f6b18f4, fp_*Red* 0x8f6b1b60-0x8f6b20dc,
  fp_InvGen 0x8f6b2240, eca_fpDouble 0x8f6b675c, eca_fpCombMult 0x8f6b70d8.
- Next: resolve the provider struct base (where [ctx+8] points) → read +0x5c →
  audit (likely an ff_IsEqual*/fp_ reduction-compare). Then the probe.

## RESOLVED + AUDITED — the very end is CLEAN (lane closed)

- `hu_GlobalCtxCreateDefault` 0x8f6ba038 → `hu_GlobalCtxCreate` 0x8f6bf460
  (ctx holds sym/asym/hash/misc/authenc/rng/mac alg tables).
- Field object for the order field: `ff_fp521r1OrderParamsCreate` 0x8f6a7984.
  GOT base (fixed): `add r3,pc,r3` @0x8f6a7998 (PC 0x8f6a79a0) + 0xfd414
  = **0x8f7a4db4**. Slot map (obj+off ← GOT):
  +0x14 ff_ConvertToOS, +0x18 fp_CarryRedGen, +0x1c fp_BorrowRedGen,
  +0x20 fp_WordRedGen, +0x24 fp_SizeRedGen, +0x28 fp_FinalRedGen,
  +0x30 fp_InvGen, +0x34 fp_AddGen, +0x38 fp_SubGen, +0x40 fp_MulGen,
  +0x4c ff_IsZero17, +0x50 ff_IsUnity17, +0x54 ff_SetToZero17,
  +0x58 ff_SetToUnity17, **+0x5c ff_IsEqual17 0x8f6b1714**, +0x60 ff_Copy17.
- Final compare = `ff_IsEqual17` = fp_SubGen (X − r, order field mod n) then
  `ff_IsZero17` 0x8f6b18f4. Audited in full: 17-word zero test, nonzero-word
  paths return 0, all-zero returns 1 (last word: `rsbs r0,word16,#1`).
  **CORRECT — no length/truncation/early-out/byte-order bug.**
- VERDICT: the KeyOne ECDSA verification is airtight end-to-end. No forged
  (r,s) is possible via impl bugs. This lane is CLOSED (negative, with evidence).
- Remaining lanes: nv_sig parser overflow (canary TZ-random), other pre-auth
  parsers (guarded), kernel-root lane, boot0 data route (WP), Priv mux (blocked).

## Probe rig (ready)

- `tools/auth_canary.py` — 0x2000 hs → 0x1016 nvinit (nvitem/signit/[+0x120]=1)
  → 0x2005 crafted ASN.1. NOTE: its "fixed canary 0x54" theory is WRONG
  (canary = TZ-random, notes/60/78). Use canary-safe sl <= 0x88 only.
- Sweep script (canary-safe): r0_s0, r1_s1, r_ff_s_ff, rempty_s0, r65_s0.
- Oracle: `oem set-factory-mode` → pass installs type-4 bitmap → command goes
  through → FACTORY (win). Wrong guesses cost nothing (no canary touch).
- Positive control: feed genuine boot.img.sig r/s (clean rejection expected).

## Front-end blocker + solution

Raw pyusb cannot arm the K1 auth session (read+write on intf1 ep0x82/0x02 both
time out; device-initiated). pcauthtool provably arms it.
=> Patch `pcauthtool_fake` to forward our crafted 0x2005 (incl. live challenge
echo) instead of the server blob (bypass decrypt). Rig: notes/79 + /tmp/opencode.

## Endgame reminder

Any code-exec that reaches the BOOTLOADER gets RPMB (set_bootmode ->
rpmb_write_record("BOOT_MODE_TYPE","FACTORY_MODE") -> qsee_alloc/TZ), unlike
Igor's Android-side context. Or a pass at +0x5c skips all of it via the session
bitmap.
