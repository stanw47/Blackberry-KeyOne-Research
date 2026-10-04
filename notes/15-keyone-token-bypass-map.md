# KEYone — Complete Token System & Verification-Bypass Map

Date: 2026-10-02  |  `emmc_appsboot.mbn` (LK, symbol table present)

## The two verification-bypass paths in `verify_hlos_image` (0x8f653c38)

Fully decoded disassembly:
```asm
0x8f653c80: bl   bbry_is_secure              ; secure flag
0x8f653c84: cmp  r0,#0
0x8f653c88: beq  0x8f653d5c                  ; NOT secure -> print, SKIP verification
0x8f653c8c: bl   dbg_token_is_unsigned_hlos_allowed   ; reads /nvuser/hlos_unsigned.tkn
0x8f653c90: subs r6,r0,#0
0x8f653c94: bne  0x8f653d48                  ; token active -> print "Skipping image verification
                                             ;   failure." -> return 1 (BOOT OK)
0x8f653c98: ... normal verify path ...
```
```c
if (!bbry_is_secure())                          // (A) insecure flag
    return skip_ok();
if (dbg_token_is_unsigned_hlos_allowed())        // (B) /nvuser/hlos_unsigned.tkn active
    { print("Debug token hlos_unsigned is active. Skipping image verification failure.");
      return 1; }                                // BOOT unsigned image
// else: strict image_verify_with_key -> SHA256/ECDSA against fused OEM key
```

**Path (B) is the direct boot bypass: an active `hlos_unsigned` debug token makes the
bootloader skip image-verification failure and boot the image.**

## Complete token inventory (from LK strings)

```
/nvuser/hlos_unsigned.tkn     -> skip image-verification failure   (B) [CROWN JEWEL]
/nvuser/mfg_mode.tkn          -> manufacturing mode
/nvuser/selinux_mode.tkn      -> SELinux mode (-> kernel cmdline)
/nvuser/pathtrust_mode.tkn    -> Pathtrust mode (-> kernel cmdline)
/nvuser/adb_mode.tkn          -> adb enable/disable (-> cmdline)
/nvuser/dbg_console.tkn       -> debug console
/nvuser/power_mode.tkn        -> power/WLC priority
/nvuser/perf_config.tkn       -> perf config
/nvuser/sw_rollback.tkn       -> software anti-rollback override
/nvuser/system_dbg.tkn        -> system_dbg
/perm/ddt.tkn                 -> device debug token
/perm/hlos_signature.tkn      -> HLOS signature token (which key the device expects)
debug_token:ddt.tkn           -> (fastboot addressable)
debug_token:force_fastboot.tkn-> force fastboot mode
```

### cmdline influence (confirmed)
`bbry_update_cmdline` reads `/nvuser/system_dbg.tkn` and appends
`androidboot.system_dbg=true|false`, `androidboot.adb.mode=enable|disable`, plus
`dbg_token_loglevel`, `power_mode` -> `androidboot.tkn.power_mode=1`.
Token values DO reach the kernel cmdline.

## How tokens are verified (the gate)

`dbg_token_read_payload` -> `nvverify_verified_read` -> `nvverify_verify` (0x8f657c3c):
```
header magic 0xae104a54
is_dbg_token() ? key=debug(0x8f6e2568) : key=production(0x8f6df098)   -> 0x8f659958
... crypto verify (0x8f6580e8) ...
```
Write path: `dbg_token_insert` (0x8f63c05c) -> `dbg_token_validate` (TLV) ->
**`nvsign_write_rec_and_sign` (0x8f657a04)** -> signs the record.

MFG-signature list exists separately: `nvsign_get_mfg_sig_list` (0x8f657944),
`nvsign_free_mfg_sig_list`. `create_sig_rec_list` (0x8f65748c) builds the verification list.

**Tokens are RSA/HMAC-signed with either a debug key or a production key.** A forged token
must carry a valid signature -> needs the private key. **Direct forgery is blocked.**

## Legitimate token provisioning path — the remaining lever

The autoloader exposes token writing (aveflash.lua):
```
flashall -c debugtokens -l <token1> -l <token2>     (authboot debugtokens)
flashall -c debugtokens -l all
```
LK fastboot handlers: `cmd_oem_set_factory_mode`, debug-token fastboot commands. The tokens are
written by `authboot debugtokens` — **the authorized path**. `pcauthtool` (RTAS2) gates it.

### Therefore:
- To write `/nvuser/hlos_unsigned.tkn` you must go through **`authboot debugtokens`** (RTAS2),
  which requires the device password / RTAS credential, OR a bootloader-side bug.
- **This is why the RTAS2/`bbauthtool` protocol (notes/11) is the primary target** — it is the
  gate in front of the token-write path, and if it can be driven to write a token we control,
  the whole chain opens (token -> skip verification -> boot unsigned image -> custom OS/root).

## RTAS2 / authboot protocol surface (from pcauthtool.exe + bbauthtool)

```
PC:  DEV_HANDSHAKE_PC, DEV_PASSWORD_PC, RTAS challenge, BBAuthVerifyCred, BBAuthDecryptRtasBlob2
LK:  EVENT.HANDSHAKE/PASSWORD/DISCONNECTED; bbauthtool sock client; auth_rtas_has_permission
     rtas2_cmd_authorization_check, auth_rtas_sign_record
RTAS server: rtasinsidebb.rim.net   (dead since BlackBerry services shutdown)
```
LK validation strings: size checks on every message (`Too many/few bytes`, `Invalid sock
message size/cookie`, `resp_len too small`). Large, stateful, BB-specific.

## Aggressive, non-bricking next experiments

1. **Enumerate live token state & writability** (no writes): `oem debugtokens` read; check
   `/nvuser` fuse writability from a rooted context (none yet) and from fastboot
   (`oem debugtokens` list). Confirm exact acceptance of `hlos_unsigned.tkn`.
2. **Drive `authboot debugtokens`** locally: run `flashall.bat -c debugtokens -l all` and
   observe the RTAS2 exchange (device has no password -> pcauthtool bypass). Capture the USB
   traffic. This is the exact path that writes tokens.
3. **Fuzz RTAS2 message sizes** via a libusb client (`tools/keyone_unlock.py` shape) against
   the `bbauthtool` handshake/password state machine — the un-hardened parser.
4. **Test `force_fastboot.tkn`** semantics — a token that forces fastboot; if writable via
   `debugtokens`, gives a controlled boot mode.

## The strategic conclusion

The bootloader has a **designed bypass**: an active `hlos_unsigned` debug token skips image
verification. The token is on a **writable** fuse partition (`/nvuser`). The **only gate** is
that tokens are signature-verified, and the **only way to write a signed token** is the
**`authboot debugtokens` RTAS2 path**. So the entire KeyOne unlock problem reduces to:

**break RTAS2 / `bbauthtool`, or obtain the token-signing (debug) key.**

Everything funnels here. The RTAS2 protocol is now the single highest-value target.

## Files
- `emmc_appsboot.mbn` (symbols), `pcauthtool.exe`, `aveflash.lua`, `avecommon.lua`
- `notes/11` (RTAS2), `notes/13` (imagetype), `notes/14` (flash/MFI/pathtrust)
- `tools/keyone_unlock.py` (fastboot harness)
