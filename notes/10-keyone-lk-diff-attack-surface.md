# KEYone LK Diff vs Reference + Attack Surface Map

Date: 2026-10-02
Target: `emmc_appsboot.mbn` (BlackBerry KEYone ABL766) vs `Aarqw12/lk_msm8953` (stock Qualcomm LK).

## Method
- BlackBerry LK ships a **full symbol table** (7,968 syms) — function-level disassembly.
- Cloned the reference MSM8953 LK (`ref/lk_msm8953`, gitignored) for diffing.

## The core "download overflow" hypothesis — CLOSED

BlackBerry `cmd_download` @ `0x8f62f3d4`:
```
parse hex length into r4
ldr r3,[download_max]; str 0,[download_size]
cmp r3, r4 ; bhs proceed   <-- BOUNDS CHECK PRESENT (len > download_max => fail)
... usb_read(download_base, len)
subs r3, r0, r4 ; check read==len and >=0
```
Same guard as stock LK (`if (len > download_max) fastboot_fail`). The `max-download-size`
(`0x20000000`) is the announced cap, and the check matches. **No obvious CVE-2021-1931-style
download-parser overflow in BlackBerry's cmd_download.**

## The real BlackBerry deltas (what stock LK does NOT have)

From string diff, BlackBerry added a whole security layer to LK:

### 1. Authboot / RTAS2 (`bbauthtool`) — the big one
A full **USB protocol state machine** runs inside the bootloader for authenticated
operations (unlock, flash, erase, factory-mode). Events/handshake:
```
EVENT.HANDSHAKE / EVENT.PASSWORD / EVENT.DISCONNECTED
PCAuthTool Version / OS Type / handshake response
Creating password challenge ... Challenge creation failed
rtas_init / rtas_has_permission / rtas_sign
USB may have not enabled RTAS2
```
Validation strings show it is **actively bounds-checked**:
```
"Size of received data too large: %u"
"Too many bytes received: %d>%u"   /  "Too few bytes received: %d<%u"
"Invalid sock message size" / "Invalid sock message cookie"
"resp_len too small: %u<%u" / "Message too larget to sent"
```
⚠️ Note the tests exist but are the *only* barrier — this is a large, complex,
BlackBerry-specific parser that never went through Qualcomm's hardening. **Highest-value
fuzzing target.**

### 2. BBSS / secure-boot state
```
bbss_btime, bbss_log, bbss_insecure, bbss_wp_type, bbss_antirollback
BSIS Type / BBSS Revision
"Anti-rollback protection disabled due to token presence"
"BBSS anti-rollback greater than image"
"Unable to find BBSS partition"
```
Confirms the `bbss.insecure` switch + anti-rollback floor (`FUSED_FLOOR` in SBL1).

### 3. Debug tokens
```
debug_token:ddt.tkn / force_fastboot.tkn / all_debug_tokens
"Failed to write debug token" / "Failed to remove debug token"
```
`force_fastboot.tkn` is intriguing — a debug token that forces fastboot.

### 4. Verified-boot / HLOS
```
"Failed to load App for verified"
"Verified the BOOT_MAGIC in image header"
"HLOS/bootchain blocked"
"Could not disable TZ access before HLOS execution"
RPMB record ... hlos blocklist check
```

### 5. vtnvfs (BB /nvram)
```
"vtnvfs partitions must use oem format <partition>"
"Successfully formatted %s to vtnvfs"
```

## Attack-surface priority (software-only)

| Surface | Notes |
|---|---|
| **1. `bbauthtool` / RTAS2 USB protocol** | Complex, BB-specific, stateful; run inside bootloader during boot. Fuzz handshake/password/challenge sizes. |
| 2. `force_fastboot.tkn` debug token | Could bypass to a fastboot mode; investigate format/location |
| 3. RTAS sign/NV signature parsers | `rtas_verify_response`, `nvverify_*` |
| 4. `cmd_oem_read_protected` / `cmd_oem_get_part_hash` | read primitives that may leak data |
| 5. `cmd_oem_set_factory_mode` / `set_product_mode` | authboot-gated, but the *state machine* is what fails |

## What is confirmed NOT the path
- `cmd_download` parser overflow (guard present)
- Classic LK `image_verify` size bypass (hardened; see notes/08)
- Cross-variant firmware flash (signature + PRD gated)

## Boot chain verify (SBL1, for reference)
```
boot_authenticator.c + auth_hash_seg_entry/exit + elf_segs_hash_verify_entry
"SHA256 auth failure!"   FUSED_FLOOR   bbss_insecure / "bbry_is_insecure: TRUE"
```
SBL1 verifies aboot's ELF segments (SHA256) against the fused key unless `bbss_insecure`.
`bbss_insecure` lives in the permanently-WP'd boot0 — the chokepoint.

## Recommended next actions
1. **Fuzz `bbauthtool` over USB** — the bootloader's RTAS2 protocol. This is the largest
   un-hardened, BlackBerry-specific parser and runs at high privilege. Tools: capture the
   `pcauthtool.exe`/`bbauthtool` exchange (autoloader has both) and mutate message sizes.
2. **Reverse `force_fastboot.tkn` handling** — a debug token that forces fastboot could be a
   shortcut to a more permissive state.
3. **Map `cmd_oem_get_part_hash` / `read_protected`** — potential info-leak / read primitives.
4. Keep the full LK symbol table + reference diff as the base for all future work.
