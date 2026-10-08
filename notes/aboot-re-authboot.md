# ABL766 aboot reverse-engineering — authboot / unlock mechanism

Target: `emmc_appsboot.mbn` (LK `aboot`, ABL766, MSM8953, not stripped).
Disasm: `keyone/dumps/2026-10-02/re/aboot.disasm.txt` (209k lines, objdump).
Tooling: arm-none-eabi-objdump, capstone, pyelftools, radare2, Ghidra.

## 1. The unlock code path

```
fastboot oem unlock        -> cmd_oem_unlock      (@0x8f62c55c)
fastboot oem unlock-go     -> cmd_oem_unlock_go   (@0x8f62c65c)
fastboot oem lock          -> cmd_oem_lock
fastboot flashing unlock_critical -> cmd_flashing_unlock_critical
fastboot flashing get_unlock_ability -> cmd_flashing_get_unlock_ability
        all of these -> set_device_unlock(r0=unlock?, r1=critical?)  (@0x8f62c484)
set_device_unlock -> either set_device_unlock.part.5 (write devinfo) or
                      snprintf + fastboot_info/okay/fail
```

The **worker is `set_device_unlock`**: with `(r0=0, r1=1)` it writes the unlock
state (a global at `0x8f7944d4+0x10`), and `write_device_info`
(@0x8f62c06c) persists it to the **`devinfo`** partition (`devinfo_present`
@0x8f7944d0). `reset_device_info` clears the same globals.

So the *only* thing standing between us and an unlocked bootloader is the
**command-permission check that runs before the command handler**.

## 2. The permission gate

`authboot_check_command_permission(name, len)` (@0x8f638168):
- looks up `name` in `authboot_cmd_whitelist` (@0x8f6de194) via
  `get_perm_item` (@0x8f637c4c, a strncmp/strlen table walk),
- then calls `authboot_check_permission(item)` (@0x8f637e0c) which switches on
  the table `type`:

| type | meaning | example commands |
|---|---|---|
| 0 | ALWAYS allowed (no gate) | `getvar`, `reboot`, `oem securewipe`(flag) |
| 1 | **requires RTAS authorization** | `flash:`, `erase:`, **`oem set-product-mode`** |
| 2 | RTAS code 0x1000 | `oem getvarp:` |
| 3 | RTAS 0x1001 | `oem gptinfo`, `oem format`, `oem test-ddr` |
| 4 | RTAS 0x1002 | `oem grswipe`, `oem clear-anti-theft` |
| 5 | RTAS | `oem format`(2nd), `frp` |
| 6 | **RTAS — sets FACTORY MODE** | **`oem set-factory-mode`** |
| 7 | RTAS — debug tokens | `debug_token`, `all_debug_tokens` |
| 8 | RTAS | `oem read`, `oem dmesg`, `oem mmcinfo` |
| 9 | RTAS | `oem setprd:`, `oem console`, `oem bootmetrics` |
| 10 | RTAS | (default) |

> **CORRECTION (2026-10-09, live):** `flash:` is **per-partition gated**, not a
> single global type-1 rule. Verified live pre-auth: `flash tz/boot/recovery/aboot/sbl1/bootsig/recoverysig`
> → **OKAY**; only `flash persist` (data class) → `authboot flash permission denied`.
> `erase cache` also OKAY. `oem securewipe` runs un-gated. See notes/49.

**Key:** `oem set-factory-mode` = type **6**; `flash:` / `erase:` =
type **1**. All of these call:

```
rtas2_cmd_authorization_check(cmd_ctx, r1, rtas_code)   @0x8f637d04
  if (device has password)  -> auth_password()   (RTAS challenge/response)
  else                      -> auth_rtas_init()  ->
                               auth_rtas_has_permission(rtas_code)  @0x8f6386e8
```

`auth_rtas_has_permission` builds a `bbauthtool` message (magic `0x8701bba7`)
and **sends it over a socket to the local `bbauthtool` service**
(`bbauthtool_sock_client_send` @0x8f639ba0), then waits for the reply
(`bbauthtool_event_wait`). That service is the **"BB Tool Auth" / BBToolAuth
daemon** the autoloader Lua warned about — a BlackBerry authorization broker.

## 3. Verdict — no software-only unlock

- Every privileged command (`flash`, `erase`, `set-factory-mode`,
  `unlock`-adjacent writes) requires an **RTAS authorization bitmap** returned
  by an external, BlackBerry-controlled service (online / license-gated).
- The **`pcauthtool`** host tool needs **RIMNET credentials + an RTAS server**
  (challenge/nonce/hash, ECDSA-no-hash sign, RSA). Not forgeable offline.
- `oem unlock` itself is not in the whitelist at all → goes through the same
  authboot gate. `authboot_check_command_permission` returns `-1` without a
  valid authorization.
- The **`devinfo` unlock byte** is only writable via `write_device_info`
  (root on-device path) or EDL. No fastboot command reaches it unauthenticated.
- **`oem set-factory-mode` is RTAS-gated too** — matching the live
  `authboot command permission denied`. So the KEY2-style "factory-mode + modded
  boot image" route is closed on this bootloader as shipped.

**Conclusion: on a retail-locked BBB100-3 at ABL766, there is NO
software-only bootloader unlock or root path.** The bootloader is gated by an
external RTAS authorization service that BlackBerry shut down / gated. The only
routes are:
1. **EDL** (uses the signed firehose we extracted; needs physical entry), or
2. **authboot with valid BlackBerry authorization** (not obtainable).

This is consistent with the community record: **KEYone remains uncracked** (the
KEY2 fell only because of an unpatched Qualcomm bug + SDM660-specific kibo, and
even that needed factory-mode).

## 4. Notable extra findings (for the record)
- `authboot_ptn_whitelist` (@0x8f6ddb10) lists every partition + access type and
  a 256-flag (likely "auth required to write"). `devinfo` is *not* in the cmd
  whitelist; it's reachable only via the internal worker.
- `authboot_ptn_whitelist` includes `debug_token` + `all_debug_tokens` (type 7)
  — the debug-token slot is real but its write path is RTAS-gated.
- The aboot supports a **backup bootchain** (POWER+VOL_UP per the Lua) which
  boots to fastboot if the primary bootchain fails — a recovery feature, not an
  unlock.
- `bbry_is_secure` / `bbry_is_insecure` / `devinfo_present` confirm the generic
  Qualcomm devinfo model; `attempt_cdr_unlock` exists but is a per-command CDR
  (China domestic requirement) thing, unrelated to bootloader unlock.

Disassembly + tables are preserved in `keyone/dumps/2026-10-02/re/`.
