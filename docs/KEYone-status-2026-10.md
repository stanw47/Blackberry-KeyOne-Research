# KEYone (BBB100-3) — project status

Device: BBB100-3, `bbb100usasprint`, Sprint, build **ABL766** (Android 7.1.1,
patch 2018-12-05). Bootloader **locked**, secure boot on, not rooted.
Started 2026-10-02.

## Outcome

**Bootloader unlock / root is NOT achievable on this device** under the current
constraints (no teardown, no EDL test points / deep-flash cable, no BlackBerry
authorization). This is proven, not assumed — see the RE notes.

## Why (three lock layers, all BlackBerry-controlled)

1. **authboot / RTAS command gate** — every privileged fastboot command
   (`flash`, `erase`, `set-factory-mode`, …) is checked against a permission
   bitmap fetched from an external `bbauthtool`/RTAS authorization service that
   is online/license-gated. `oem unlock` isn't even whitelisted.
   (`notes/aboot-re-authboot.md`)
2. **Image signatures** — boot/recovery/aboot/sbl1 need BlackBerry ECDSA sigs
   (APBI/ADBI tokens). Unforgeable.
3. **Secure storage** — the unlock flag lives in the `devinfo` struct
   (magic `ANDROID-BOOT!`, unlock word at offset 0x10) stored in **RPMB**
   (TZ-authenticated). (`notes/aboot-re-devinfo.md`)

The only bypass is the **PBL/EDL** path — physical entry required, out of scope.

Consistent with the public record: the **KEYone was never cracked**; only the
KEY2 (different SoC + unpatched Qualcomm bug + factory-mode) was unlocked.

## What we collected (all reusable, in `keyone/`)

### Notes
- `keyone-research.md` — full external research compendium (variants, history,
  community results, CVE context).
- `firmware-recovery.md` — autoloader/unbrick reference.
- `bootloader-recon-2026-10-02.md` — live fastboot recon (`getvar all` works;
  privileged commands denied).
- `autoloader-teardown.md` — ABL766 autoloader contents + EDL package.
- `aboot-re-authboot.md` — authboot gate RE (tables, types, RTAS path).
- `aboot-re-devinfo.md` — devinfo struct + unlock-flag offsets + RPMB.

### Artifacts
- `dumps/2026-10-02/` — device props, packages, mounts, partitions, system
  layout, fastboot log, screenshots.
- `dumps/2026-10-02/autoloader/ABL766 - Hn03/` — signed firmware, GPT/rawprogram,
  **`prog_emmc_firehose_8953_ddr.mbn`** (signed EDL programmer),
  **`emmc_appsboot.mbn`** (symbolized), `authboot`, `pcauthtool`.
- `dumps/2026-10-02/re/aboot.disasm.txt` — full ARM disassembly (209k lines).
- `tools/edl/` — bkerler/edl (venv installed), ready if EDL ever becomes
  reachable.
- `tools/fastboot_recon.sh`, `tools/env.sh`.

## If constraints change

With **EDL access** (test points / deep-flash cable):
```
edl printgpt
edl r aboot   aboot.bin
edl r boot    boot.bin
edl r devinfo devinfo.bin     # inspect unlock word @0x10
edl w devinfo devinfo_unlocked.bin   # flip +0x10 -> 0x1 (cf. EDLUnlock)
```
All the signed pieces are already extracted. Back up every partition first.

## Non-root options available today
- ADB debloat (`pm uninstall --user 0 …`).
- `adb backup` (needs unlocked screen + tap confirm).
- Autoloader restore / FRP reset (signed factory images archived).
