# KEYone Privileged-Token & RTAS2 Architecture

Date: 2026-10-02
Sources: `emmc_appsboot.mbn` (LK), `pcauthtool.exe` (PC RTAS2 client), `bbauthtool` (LK side).

## 1. The debug-token system (crown jewels)

LK carries a privileged-token system. Token *files* live on writable BB fuse partitions
(`/nvuser`, `/perm`) — NOT the WP'd boot0:

```
/nvuser/system_dbg.tkn          system debug
/nvuser/hlos_unsigned.tkn        boot UNSIGNED HLOS        <-- key
/nvuser/dbg_console.tkn          debug console
/nvuser/sw_rollback.tkn          software rollback
/nvuser/pathtrust_mode.tkn       PATHTRUST MODE            <-- key
/nvuser/selinux_mode.tkn         SELINUX MODE              <-- key
/perm/hlos_signature.tkn         HLOS signature
debug_token:ddt.tkn              device debug token
debug_token:force_fastboot.tkn   force fastboot mode
```

Token API (all symbols in LK):
```
dbg_token_validate, dbg_token_insert, dbg_token_read_payload, dbg_token_remove
dbg_token_get_selinux_mode, dbg_token_get_pathtrust_mode
dbg_token_is_unsigned_hlos_allowed, dbg_token_is_anti_rollback_disabled
dbg_token_is_console_enabled, dbg_token_get_hlos_tag_override
adb_mode_token_present, ddt_token_present
```

### Token binary format (from `dbg_token_validate` @ 0x8f63b770)
```
[ u32 version/magic ]   (must satisfy checks)
[ 0x28-byte header   ]  (copied; strncmp'd for identity)
[ name : NUL-terminated, len <= 0x14 (20) ]
[ payload : NUL-terminated ]
+ trailing signature record
```
Validation gates: min size `0x39`; header copy checked (`cmp r0,#0`); name length
`<= 0x14`; multiple explicit failure branches. Hardened TLV parser.

### `dbg_token_is_unsigned_hlos_allowed` @ 0x8f63c694
Reads the payload via `dbg_token_read_payload`, then `strncmp(payload, expected, 0xc)` —
i.e. the token payload is a **12-char flag string**. If it matches, unsigned HLOS boot is
permitted.

### `dbg_token_get_selinux_mode` @ 0x8f63cc24
Calls `get_cmdline_from_token(name, arg, 2)` → token value flows into the **kernel cmdline**
(selinux / pathtrust / console mode). So these tokens directly steer the OS security posture.

### The gate: tokens are signature-verified through RPMB-backed NV
`dbg_token_read_payload` → `nvverify_verified_read` (`0x8f657fdc`) →
`nvverify_verify_all_required_recs` (`0x8f657f44`) → per-record `verify_rec`.
Record verification is RPMB + signature backed:
```
nvsign_write_rec_and_sign, verify_rec, create_sig_rec_list
rpmb_read_record, rpmb_write_record, rpmb_find_record, validate_blocklist_against_rpmb
```
**Conclusion: you cannot simply drop a forged `.tkn` on /nvuser — the record's signature is
verified against a key via nvverify/RPMB.** This matches the earlier BB10 finding that RPMB is
the replay-protected root.

## 2. THE LEAD — a "proceed anyway" verification bypass exists

LK contains BOTH of these strings:
```
"Failing boot due to NV Signature verification failure"
"NV Signature verification failed, proceeding with boot anyways"    <-- !!!
```
There is a **branch where NV signature verification fails but boot still proceeds.** This is
a boot-policy decision (NV policy flag / token / fuse state). If that decision can be
influenced from a writable location (e.g. a token we control, or a corrupted record that
trips the lenient path instead of the strict one), it is a **verification-bypass primitive**.

This is the single most promising software lead found to date. It dovetails with the earlier
BB10 finding (`FS_DIRTY_ALL` / `FS_DIRTY` RPMB-gated boot policy).

### Next: locate the caller/branch
`nvverify_verify_all_required_recs` is invoked indirectly (function-pointer boot-policy
chain). Need to:
1. Find the caller that emits the two strings (relative string table — resolve via the
   LK `printf` base at ~0x8f6d6000).
2. Determine what condition selects "proceeding anyways" vs "Failing boot".

## 3. RTAS2 / authboot protocol (`bbauthtool` ↔ `pcauthtool`)

A full USB protocol runs **inside the bootloader** for authenticated operations.

### PC side (`pcauthtool.exe`, native)
```
DEV_HANDSHAKE_PC          handshake (version, bootchain versions, HLOS version)
DEV_PASSWORD_PC           device password
Challenge / RTAS challenge
BBAuthDecryptRtasBlob2 / BBAuthVerifyCred
calculate_password_hash_with_entropy
RTAS server: rtasinsidebb.rim.net    (BlackBerry internal)
options: -s store creds, -u user, -r pass, -p device_pass, -b bypass
uses libusbauth.dll
```

### LK side (`bbauthtool`)
```
EVENT.HANDSHAKE / EVENT.PASSWORD / EVENT.DISCONNECTED
bbauthtool_sock_client_register / _send   (socket to bbauthtoold)
bbauthtool_event_wait / _signal
auth_rtas_has_permission, rtas2_cmd_authorization_check, auth_rtas_sign_record
```
Validation strings (bounds-checked but BB-specific, un-hardened by Qualcomm):
```
"Size of received data too large: %u"
"Too many bytes received: %d>%u"  / "Too few bytes received: %d<%u"
"Invalid sock message size" / "Invalid sock message cookie"
"resp_len too small: %u<%u" / "Message too larget to sent"
"Invalid rtas init response size" / "Unexpected rtas init status"
```

## 4. Attack-surface priority (software only)

| # | Target | Rationale |
|---|---|---|
| **1** | **NV-verify "proceeding with boot anyways" branch** | Direct verification bypass if the lenient path is reachable with attacker-influenced state |
| 2 | **`hlos_unsigned.tkn` 12-byte payload match** | If the token can be produced/placed (e.g. via a signed-but-controllable route or a record confusion), unsigned HLOS boot enabled |
| 3 | **`bbauthtool` RTAS2 protocol fuzz** | Large stateful parser in bootloader; sizes are the primary defense |
| 4 | RPMB record confusion (`rpmb_find_record`, record/sig size mismatch) | `"Size in rpmb bl entry (%d) doesn't match nv size (%d)"` — a mismatch is explicitly handled; look for confusion |
| 5 | `force_fastboot.tkn` | Debug token that forces fastboot mode |

## 5. Confirmed NOT viable
- fastboot `download:` overflow (guard present)
- LK `image_verify` classic CVEs (hardened)
- Cross-variant flash (signature + PRD)
- Direct token forgery (nvverify signature via RPMB)

## 6. Suggested immediate next step
Resolve the **two-string branch** (`"Failing boot due to NV Signature verification failure"`
vs `"NV Signature verification failed, proceeding with boot anyways"`). That is the closest
thing to a smoking gun in this entire investigation. Requires:
1. Resolve the LK printf string base and locate the branch that reads those two string VAs.
2. Trace the boot-policy decision function and its input (NV record / token / fuse).
3. Determine reachability from a writable, un-signed location.

## Files
- `firmware/keyone-abl766/.../emmc_appsboot.mbn` — LK (symbol table present)
- `firmware/keyone-abl766/.../host/windows-x86/bin/pcauthtool.exe` — RTAS2 PC client
- `firmware/keyone-abl766/.../host/windows-x86/bin/bbauthtool*` (LK side; also in /system/bin)
- `tools/lk_analyze.py`, `tools/keyone_unlock.py`
