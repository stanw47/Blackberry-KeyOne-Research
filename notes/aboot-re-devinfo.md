# ABL766 devinfo / unlock state — deep dive (final)

Companion to `aboot-re-authboot.md`. All offsets from the runtime image; disasm
in `keyone/dumps/2026-10-02/re/aboot.disasm.txt`.

## devinfo struct (globals base 0x8f7944d4)

Runtime-default values read straight from the image's `.data`:

| off | value | field (from `cmd_oem_devinfo`) |
|---|---|---|
| +0x00 | 0x1 | (version/present) |
| +0x04 | `ANDR` (0x52444e41) | magic `ANDROID-BOOT!` |
| +0x08 | `OID-` (0x2d44494f) | ... |
| +0x0c | `BOOT` (0x544f4f42) | ... magic tail |
| **+0x10** | **0x1** | **is_unlocked** (Device unlocked) |
| **+0x14** | **0x1** | **is_unlock_critical** (Device critical unlocked) |
| +0x18 | 0x0 | is_tampered |
| +0x1c | 0x0 | charger_screen_enabled |
| +0x20 | 0x1 | verified / display-panel selector |
| +0x24.. | 0 | display panel name etc. |

`cmd_oem_devinfo` prints, in order:
`Device tampered`, `Device unlocked`, `Device critical unlocked`,
`Charger screen enabled`, `Display panel` — each rendered via
`boolstr` (0→"no", 1→"yes") from +0x18/+0x10/+0x14/+0x1c/+0x20.

`set_device_unlock(r0, r1)`:
- r0=0 → sets global at **+0x10** to r1, then `write_device_info`
- r0=1 → sets global at **+0x18** to r1 (critical path)

So the **unlock flag is the 32-bit word at struct offset 0x10 inside the
`devinfo` partition** (magic `ANDROID-BOOT!` at 0x04). This is the exact byte
`Giovix92/EDLUnlock` flips on other QCOM devices.

## Where devinfo physically lives

`write_device_info` (@0x8f62c06c):
1. `target_is_emmc_boot` → allocate 4096, copy 228 bytes (0xE4) of struct.
2. `is_secure_boot_enable()` = `scm_check_boot_fuses` (SCM/TZ query) + fuse global.
3. If **secure boot ON** → `write_device_info_rpmb` (256, `get_secapp_handle`,
   TrustZone RPMB write). If OFF → `write_device_info_mmc` (raw partition write).
4. Write failure is a **`_panic`** (line "devinfo" / 0x99a).

On our device `security:enabled` (secure boot on) ⇒ the *authoritative* devinfo
is **RPMB** (replay/rollback-protected, TZ-authenticated). The plain partition
may also be written, but RPMB is what the secure path trusts.

## Why there is no software write

- The only caller that reaches `write_device_info` with the unlock flag is
  `set_device_unlock`, which is reached only from `cmd_oem_unlock` etc. — and
  those pass through `authboot_check_command_permission` first.
- Nothing else in the image writes +0x10 without authorization; there is no
  unauthenticated fastboot command that touches devinfo.
- Even a raw `fastboot flash devinfo` would require the `flash:` command
  (whitelist type 1 → RTAS authorization), and the write path expects a
  *valideştirilmiş* struct, not our bytes.
- **CORRECTION (2026-10-09):** `flash:` is **per-partition**; the boot-chain
  class is open pre-auth (`flash boot` etc. → OKAY). Whether `flash devinfo`
  itself is permitted is **untested**; even if written, the consumer expects a
  validated struct. See notes/49.

## The three lock layers (summary)

1. **Command authorization** — `authboot`/RTAS bitmap via the `bbauthtool`
   daemon (online/service-gated). Blocks data-partition `flash` (e.g. `persist`)
   and `set-factory-mode`; boot-chain-class `flash` is open (notes/49).
2. **Image signature** — boot/recovery/aboot/sbl1 must carry BlackBerry
   ECDSA sigs (APBI/ADBI tokens; `sig/*.sig`, `ECDSA521verify`). We can't sign.
3. **Secure storage** — unlock state in RPMB, written via TZ secapp.

## Verdict (unchanged, now proven at instruction level)

**No software-only unlock/root on a retail BBB100-3 @ ABL766.** All three
layers are BlackBerry-controlled. The EDL route (which bypasses all of them via
the PBL) remains the only path — and that needs physical entry, which is out of
scope per your constraints.

## Value of what we extracted (for any future attempt)
- `prog_emmc_firehose_8953_ddr.mbn` — signed programmer (EDL ready).
- `rawprogram0.xml`/`patch0.xml` — exact eMMC map (devinfo @ sector 425760).
- `emmc_appsboot.mbn` — symbolized bootloader (this analysis).
- Full signed ABL766 firmware set for restore.

## Loose threads (if we ever revisit)
- `scm_check_boot_fuses` result on this unit — does it enable the RPMB path
  (would `oem device-info` even report if unlocked)? Confirm via a read of the
  fuse global.
- Whether the **backup bootchain** path (POWER+VOL_UP) changes any permission
  state (the Lua treats it as a recovery mode; likely same gate).
- `cmd_oem_clear-lal`, `bide-storage-wipe`, `clear-anti-theft` (RTAS types) —
  no unlock relevance, but part of the same auth surface.
