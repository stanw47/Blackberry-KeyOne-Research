# notes/43 — Backup bootchain AAK171 interrogated + debug-token system mapped

Date: 2026-10-08

## Backup bootchain AAK171 (factory, April 2017) — full read-out

Entered via POWER+VOL_UP. Fastboot surface identical to primary (26 getvars,
same values except battery voltage); `oem info` allowed.

- `Backup Version: AAK171` (presents as backup; primary = ABL766).
- `Insecure: false`, `WP Type: permanent`, `is-password-set: no`,
  `security: enabled`, `authboot_api_ver: 2.0`.
- HLOS token metadata: `Name ec_agent`, `Time 20181127.133122`, `ID APBI`,
  `Tag sprint` (boot + recovery).
- **Debug Tokens (perm): None Found / (nvuser): None Found.**
- Unlock attempts: `oem unlock`, `oem unlock-go`, `flashing unlock` →
  **all `authboot command permission denied`.** The authboot gate exists in the
  factory backup chain too; no weaker unlock path there.

Implication: every reachable image (AAK171 backup, AAK399, AAL093, AAN355,
ABL766) denies unlock. There is no software unlock shortcut anywhere on the
device.

## The debug-token system — the intended engineering mechanism

`getvar` / aboot strings reveal a **file-based token system**:

| Token file | Effect (string evidence) |
|---|---|
| `/nvuser/hlos_unsigned.tkn` | `"Debug token hlos_unsigned is active. Skipping image verification failure."` (0x8f653d4c) — **boots unsigned HLOS images** |
| `/perm/hlos_signature.tkn` | signature-tag override; `"hlos_signature debug token not valid or doesn't exist"` (0x8f653e90) |
| `/nvuser/mfg_mode.tkn` | manufacturing mode |
| `/nvuser/adb_mode.tkn`, `selinux_mode.tkn`, `pathtrust_mode.tkn`, `sw_rollback.tkn`, `dbg_console.tkn`, `power_mode.tkn`, `perf_config.tkn`, `system_dbg.tkn` | mode/behavior tokens |
| `debug_token:ddt.tkn`, `debug_token:force_fastboot.tkn` | fastboot token handler (0x8f62c830) |

- Storage: files on the **plain `nvuser` and `perm` partitions**
  (GPT: nvuser LBA 839256, perm LBA 838744, 256 KB each).
- The service autoloader's rawprogram flashes `..\nvram\nvuser.bin` and
  `perm.bin` (device-unique; not shipped in packages).
- Loader/validator cluster at `0x8f63c438`–`0x8f63c71c` reads a file into a
  0x400 buffer and parses it into globals (`0x8f7be3cc`, `0x8f7be3d4`).

## Attack-path candidates (new)

1. **Craft a token file** → write to `nvuser` via any authorized write path
   (modified autoloader flashall, root, or EDL) → unsigned boot.
   Gate: the token is likely signature-validated (`dbg_token_is_unsigned_hlos_allowed`
   / `parse_hlos_signature_token`); determine the scheme next.
2. **Fuzz the token parser**: it consumes a 0x400-byte file from a writable
   partition — malformed token files are an attacker-controlled input to aboot
   (candidate memory corruption; pairs with the authorized-flash channel).
3. **`debug_token:` fastboot handler**: syntax study + live probes (expected
   RTAS-gated, type 7).
4. Root routes (KGSL/SD-vold) remain viable for writing `nvuser`/`perm` from
   Android.

## Status

- Device returned/rebootable; all research artifacts committed.
- Next: disassemble the token validator (`0x8f63c29c`, `0x8f63c2d8`,
  `0x8f63c3bc`, `0x8f63bfa0`) to establish signature scheme + failure modes.
