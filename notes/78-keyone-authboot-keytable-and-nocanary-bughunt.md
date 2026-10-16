# notes/78 — RTAS/AUTHBOOT token key-table audited (P-521, unforgeable) + non-canary bug hunt (negative) + live secure-boot confirm

Date: 2026-10-16
Device: BBB100-3 `1164118297`, ABL766, fastboot mode.
Extends: notes/49 (token crypto), notes/60 (pre-auth overflow, TZ-random canary),
notes/66 (pre-auth parser audit + command whitelist). Confirms and sharpens them.

## 1. Live: secure boot IS enabled (flash lane closed)

`fastboot -s 1164118297 oem info` (type-0, no token, so it always prints) returns:

```
Bootchain Software: Primary Version: ABL766 / Backup Version: AAK171
Security:
  Insecure:  false
  WP Type:   permanent
debug tokens: (none)
Hardware Information: Product bbb100 / Variant usa / Subvariant sprint
Product Identifiers: PIN 0x2c48d4c8 / IMEI 990004630122962 / MEID 99000463012296 / BSN 1164118297
HLOS boot+recovery Signature: Name ec_agent / Time 20181127.133122 / ID APBI / Tag sprint
```

`Insecure: false` => `bbry_is_secure`=true; `WP Type: permanent` => fuses permanently
write-protected. Falsifies the "if secure boot were off, flash the unlock flag" hypothesis.
Device-info and bootmode live in RPMB (`write_device_info_rpmb`; `update_bootmode_count`→RPMB
record 0xc88), NOT in a flashable `misc`/BSI. `print_info @ 0x8f63217c` prints
`Security:` + `bsi_get_data("bbss_insecure")` and `bbss_wp_type`; `cmd_oem_info`
(perm type0) calls it unconditionally (its `authboot_check_pinfo_rtas_permission`
uses aid 0x1006 but does not gate the output).

## 2. Key-table audit: 55 ECDSA P-521 PUBLIC keys, no secret, unforgeable

`get_key(name)` (0x8f65a270) builds `"<name>-<device_id>"` and `find_key` (0x8f65a1e8)
linear-searches a **55-entry table at `0x8f794988`** (stride 20 = `{name_ptr, u32 type,
u32 one, key_ptr, u32 0x88}`). Full enumeration confirms 5 tools × variant set:
`AUTHBOOT` / `DBGSIG` / `DDT` / `NVSIG` / `STP`, over bbb100{cn,dscn,emea,global,japan,usa}
and bbd100{americas,cdma,cn,dscn,global}. Our unit resolves to **`AUTHBOOT-bbb100usa`**
(entry 5; key blob @ `0x8f6e2b34`).

The verifier `sb_ecc521_verify_sign @ 0x8f66d648` (called from `is_sig_valid @ 0x8f658f30`
via `[ctx+0x40]`) is decisive:

- It rejects any key whose length != **136 (0x88)** (`subs r7,#0x88`), and any sig/aux != 136.
- `memcpy(sp+0x2c, key+0x44, 68)` and `memcpy(sp+0x70, key+0, 68)`, then byte-reverse each:
  the 136-byte blob is exactly **two 68-byte big-endian P-521 coordinates**.
- Feeds them to real Huksy `hu_ECDSANoHashVerify` (curve 0x11 = P-521, 64-byte SHA-512 digest).

=> The blobs are **ECC-521 public keys**; no symmetric key and no private scalar is present.
Combined with `get_key`/`find_key` having no writable key store, forging a valid `0x2005`
requires BlackBerry's HSM-held private key. (Refines notes/49 §3: the RTAS/AUTHBOOT token
path is P-521, distinct from the HLOS bootsig path's 256-family keys.)

## 3. What a valid token actually grants (has_permission logic)

`has_permission(ctx, aid) @ 0x8f65a140` (reached via `rtas_has_permission` ← daemon reply):

- `type = u16[ctx+0x2c]` (tool class, set from the init name by `tool_name_to_num`:
  `AUTHBOOT`=1, `STP`=2, `NVSIG`=3, `DBGSIG`=4, `DDT`=5; strings @ 0x8f6ddf5c etc.).
- type 1 => aid must be in `0x1000..0x1080` (`aid-0x1000 <= 0x80`), magic `u16[ctx+0x2e]`
  must equal **0x2346**; type 2 => aid in `0x2000..0x2080`, magic **0x2347**.
- permission = bit `(aid-base)` set in a 16-byte bitmap at `ctx+0x30` (`>>32` uses `ctx+0x38`).

That 18-byte `{magic, bitmap[16]}` blob is copied into `ctx+0x2e` by `rtas_verify_response`
**only after** `is_sig_valid` returns 0. So the entire grant is inside the signed token.

## 4. Command-permission jump table — aid mapping (corrected/verified)

`authboot_check_permission @ 0x8f637e0c`: `ldrls pc,[pc,type<<2]`; the switch index is the
**type** field of the matched `get_perm_item` entry:

| type | aid | type | aid |
|---|---|---|---|
| 0 | allow | 6 | **0x1004** |
| 1 | allow (`chk(1,0,0)`) | 7 | 0x1005 |
| 2 | 0x1000 | 8 | 0x1006 |
| 3 | 0x1001 | 9 | 0x1007 |
| 4 | 0x1002 | 10 | 0x1008 |
| 5 | 0x1003 | | |

Table dump @ `0x8f6de194` (38×16B) confirms `oem set-factory-mode` = **type 6 → aid 0x1004**.
(Correction: an earlier working note said 0x1005 — wrong; type7 is 0x1005. notes/66 is correct.)

## 5. Non-canary memory-corruption bug hunt — negative

Scripted the whole disassembly (2624 functions) with function-boundary + call-target parsing:

- **Dangerous-copy vs canary:** exactly **11** functions use `strcpy/sprintf/strcat/memcpy`
  with NO `__stack_chk_fail`, and all are low-level primitives
  (`SHA256_Update`, `SHA512_Update`, `sbdef_memcpy`, `husw_AESKeyUnwrap/RSA*/ECSPEKE`,
  `eca_fp*`). **Every attacker-facing copy path is canary-guarded** — `cmd_oem_*`,
  `fastboot_*`, `auth_rtas_init/has_permission`, `bbauthtool_*`,
  `process_rtas_chal_response`, `parse_response`.
- **Format strings:** scanned every `sprintf/snprintf/vsnprintf/_dprintf/printf/fastboot_ex`
  call site; every format arg is a `movw/movt` literal. The only "stack-loaded" formats are
  varargs forwarders (`fastboot_ex @ 0x8f62f858`, `add_to_cmdline @ 0x8f63af98`), whose
  callers all pass literals. No attacker-controlled format string. (Matches notes/66 item 11.)

## 6. is_sig_valid overflow — re-confirmed canary-walled

`is_sig_valid @ 0x8f658f30`: `memset(sp+0x4c, 0, 0x88)` zeroes up to **exactly** the canary
at `sp+0xd4`. Buffer1 @ `sp+0x4c`, buffer2 @ `sp+0x90`; both are below the canary, and the
saved regs/return live at `sp+0xdc`+. Any overflow that reaches them must cross (and corrupt)
`[sp+0xd4]`, checked against the TZ-random guard at `0x8f7c2ed0` just before the restored
`pop {...,pc}` — after all of the attacker-influenced code. No control transfer occurs before
the check. Matches notes/60.

## 7. Canary leak hunt (pre-auth output paths) — negative

Goal: disclose `__stack_chk_guard @ 0x8f7c2ed0` to weaponize the note/60 overflow. Only type-0
and type-1 commands are reachable pre-auth; their entire output surface is `getvar` and
`oem info` (plus the auth daemon messages). All checked:

- `cmd_getvar @ 0x8f62f6bc`: walks the published-variable list; for each, `strlcpy(buf,value,64)`
  + `strlcat` into a **64-byte stack buffer at sp+4**, `fastboot_info`, then `memset(buf,0,64)`.
  Bounded, and cleared after every use. Values are the pointers published at init.
- `fastboot_publish @ 0x8f62efac`: stores `{next,name,value}`; every pre-auth caller passes a
  **global** buffer (BSS ~`0x8f7c39d0..0x8f7c3be8`, e.g. serial/variant/flash-size snprintf'd
  once) or a static literal — never a stack or transient heap pointer.
- `print_info @ 0x8f63217c` (`oem info`): prints BSI fields (`bsi_get_data`), 4-byte NV reads,
  `get_identifier_string` (returns **global** buffers 0x8f7945d0 / 0x8f7bd8xx),
  `hlos_info_fastboot_print` (reads a partition into a `memalign` heap buffer, prints fields),
  `dbg_token_fastboot_print` (reads token partitions). `[sp]` is pre-set to `0xffffffff` at
  entry, so the `bbry_get_nv_fd==0` fall-through path at 0x8f6323c4 does not leak uninitialized
  stack. Nothing reads uninitialized stack to the host.
- Auth daemon messages: `send_rtas_challenge @ 0x8f639e30` does `memset(sp,0,524)` **before**
  `rtas_create_challenge` and `usb_send_msg(0x2004, sp, 524)`. `event_thread` zeroes the
  0x2001/0x2002 buffers (`memset(sp+20,0,548)` etc.) before building/sending. No uninitialized
  stack is transmitted.

=> No info-disclosure primitive found in the pre-auth surface. The canary leak avenue is closed
by inspection (matches notes/60's conclusion that no leak was yet found).

## Conclusion

The RTAS/AUTHBOOT token gate is ECDSA-521 with keys that are provably public-only, the
command-permission model is exact-match with the grant carried inside the signed token, the
only memory-corruption bug (`is_sig_valid`) is walled by a per-boot TZ-random canary, and an
exhaustive scan finds no canary-free or format-string bug reachable pre-auth. **No
software-only path to `oem set-factory-mode` exists on ABL766 with secure boot on.**

Residual options: (a) find a canary leak (would unlock the note/60 ROP), (b) a logic flaw in
the oracle/0x2004/0x2005 exchange (replaying/session caching/variant spoofing), or (c) the
kernel lane (notes/58/2215) for root → TZ → RPMB bootmode.
