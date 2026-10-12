# notes/63 — RTAS challenge/response fully mapped + 0x2005 fuzzer harness

Date: 2026-10-12. Device: KEYone BBB100-3 ABL766. Related: notes/16, 59, 60, 62.

## 1. Verdict reconfirmed: no client key is ever used

Both verifiers end in the same function:
- AUTH path: `process_rtas_chal_response` (0x8f63a450) → `rtas_verify_response` (0x8f659bc8)
- NV_SIG path: → `rtas_verify_nv_sig_response` (0x8f659e24) — requires items type 5+6, then
- → `is_sig_valid` (0x8f658f30): `SHA-512(region A)` + ECDSA-P521 verify with
  **`[ctx+0x40] = get_key(tool_name)`** (device's built-in per-channel key).
No response-supplied key. Self-signed credentials impossible (notes/62).

## 2. 0x2005 wire format (fully decoded)

```
{ cookie=0xbba78701, code=0x2005, 0 (u32), len_a (u16), len_b (u16),
  region A [len_a bytes], region B [len_b bytes] }
total = len_a+len_b+4 (checked; uxth truncation upstream caught in parse_response)
```
- `parse_response` (0x8f6598a4): copies the 4 length bytes, validates the exact
  total, sets ptr_a/ptr_b.
- Items (region A) = varint TLV: `[len varint][type varint][value]`
  (`find_challenge_item` 0x8f659110; type varint bounded to 5 bytes, length
  varint to ~4; remaining-count accounting is hand-rolled — fuzz target).
- Response item checks (rtas_verify_response):
  - **type 1 = PIN** (4B) == `get_pin()` ← **prdid partition, item "pin"** (read_pin 0x8f65a464)
  - **type 3 = BSN** (4B) == `get_bsn()` ← **boardid partition, item "bsn"** (first 4 bytes = "AAKH", known from jdm_bsn)
  - **type 2 = echo** (16B) == ctx+24 (the device's random nonce, len u16[ctx+6]=16)
  - type 4 (≤18B) copied to ctx+0x2e on success (session material)
- Region B (DER sig): `30 81 <len> 02 <sl> <r> 02 <r4> <s>`, siglen = len_b.
  Both copies (`sl`→136B buf @sp+0x4c, `r4`→68B buf @sp+0x90) end **exactly at
  the canary @sp+0xd4** — sl>136 or r4>68 hits the per-boot random canary
  (notes/60). No useful non-canary overflow.

## 3. Challenge side (device → PC)

- `send_rtas_challenge` (0x8f639e30) → `rtas_create_challenge` (0x8f659a84) →
  `create_challenge` (0x8f6594e8): builds a **524-byte** 0x2004 message:
  `[8B header][payload ≤512B][u32 payload_len]`.
- Payload: descriptor item + random nonce (`get_random` into ctx+24, 16B) +
  `get_bsn()` item; the channel string `AUTHBOOT-bbb100usa` is embedded.
- Live capture: payload_len = 171; first item = type 1, len 43 =
  `[22B config][18B "AUTHBOOT-bbb100usa"][3B]`; then ~117B of nonce data.
- Trigger: every RTAS-gated command (oem set-factory-mode, oem getvarp:bsn)
  on a fresh session sends 0x2004 — **regardless of the 0x2000 handshake tool
  name** (sweep: Linux/AUTHBOOT/ec_agent/authboot all → challenge).
- Corrected tool-lane statuses (behind the challenge): 0x1011 status=1,
  0x1013 status=0, 0x1015 status=0 result=1.

## 4. The ec_agent mystery resolved (negative)

The Windows toolchain (authboot.exe/fastboot.exe/pcauthtool.exe/libusbauth.dll)
contains **no P-521 constants and no crypto imports** → it cannot compute the
0x2005 signature. Therefore notes/58's "authorized getvarp" must have used
authboot.exe's **own protocol** (its own PIN/BSN reader —
`AUTHBOOT_DEVICE_PIN_FAILED`/`BSN_FAILED` strings), not the fastboot RTAS lane.
The RTAS challenge remains unpassable without BlackBerry's channel private key.

## 5. Fuzzer harness (built + validated)

- `tools/fb_fuzz.py` — case generator + response builder (item echo, DER sweeps,
  length boundaries); `tools/fb_case.py` — one-case-per-process runner
  (fresh USB state; persistent-process runs block the fastboot client after
  the first case).
- Validated: 12/12 boundary/sig cases denied cleanly (~0.112 s each), device
  healthy after every case; garbage-0x2005 + EP 0x81/0x82 drain keeps it clean.
- To reach `is_sig_valid` the response needs the **correct PIN** (prdid "pin")
  and the **nonce offset** in the challenge payload — both pending:
  - prdid is parthash-readable (like nvuser/perm; ~10 min for the table region).
  - nonce offset: finish `create_challenge` decode (item emitter layout).

## 6. Next

1. Read prdid "pin" via the parthash oracle (and boardid "bsn" to confirm).
2. Finish `create_challenge` item-layout decode → exact nonce bytes.
3. Then: ECDSA verifier r/s sweep (impl-bug hunt) + item-parser boundary fuzz
   (find_challenge_item accounting) — with the stable one-case-per-process
   harness.

---

## 7. FINAL CLOSURE (same day): the challenge is cryptographic in every element

Deeper `create_challenge` decode + fresh live capture (payload_len=171):

- Payload layout: `[3B][20B descriptor][18B "AUTHBOOT-bbb100usa"][2B][128B ECIES blob]`.
  - The 20-byte descriptor: `{u16 18 (name len), u16 16 (nonce len), u16 2,
    u16 129, u16 5, u16 1, u16 132, u16 5, u16 1, u16 0}` — a record layout
    descriptor (types/lengths), NOT the values.
  - The values (BSN/nonce/PIN items) are built by `create_challenge` via
    `get_bsn()`, `get_random(ctx+24,16)`, `get_pin()` and then
    **`sb_ecc521_ies_kdf_xor_encrypt([key+0xc],[key+0x10], data128, 128, ...)`**
    — ECIES-encrypted to the **channel public key** (`get_key(tool_name)`).
- To echo the items (esp. the 16-byte nonce, item type 2 == ctx+24) the tool
  must **decrypt the ECIES blob with the channel PRIVATE KEY**.
- Therefore: **no valid 0x2005 is constructible without BlackBerry's key** —
  not just the signature, but the item values too. The RTAS path is
  conclusively closed for pre-auth attackers.
- Consequence for the fuzzer: the AUTH path's item checks gate `is_sig_valid`,
  so the canary overflow in `is_sig_valid` is **not reachable** via 0x2005
  pre-auth on the AUTH path. The only lighter verifier is the **NV_SIG path**
  (`rtas_verify_nv_sig_response`): it requires only items **type 5 + type 6 to
  exist** (no value checks!) before calling `is_sig_valid` — but it is gated by
  ctx flags (`[ctx+0x54]==0` and `[ctx+0x75c]!=0`, the latter set by the
  RTAS_SIGN event path, `init_nv_sign_rtas_ctx`). If a reachable command
  triggers a sign event, a 0x2005 with items 5+6 would reach `is_sig_valid`
  (DER parser + the canary-walled overflow). Open lead, not yet found.
- Fuzzer harness remains in `tools/fb_fuzz.py`/`fb_case.py` (stable, one case
  per process, garbage-0x2005 + drain cleanup) for that NV_SIG path or future
  work.
